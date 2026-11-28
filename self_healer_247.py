#!/usr/bin/env python3
"""
AI Agent Factory — 24/7 Autonomous Self-Healing Sentinel (v3.0 — Alice Smart Router Edition)
Monitors all 10 VPS services, ports, Alice Smart AI Router (:20135), Hermes (@alicewordbot),
5 Cloudflare/VPS websites, disk/RAM, and AI model pool health.
Automatically heals crashed/frozen services, resets stuck AI cooldowns, cleans disk pressure,
and writes live state to /opt/ai-factory/data/healer_state.json.
"""

import json
import os
import shutil
import socket
import subprocess
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

STATE_PATH = "/opt/ai-factory/data/healer_state.json"
ENV_PATH = "/opt/ai-factory/hermes/.env"
HERMES_ERRORS_LOG = "/opt/ai-factory/hermes/logs/errors.log"

SERVICES = [
    ("alice-smart-router", "Alice Smart AI Router", 20135),
    ("caddy", "Caddy HTTPS Edge Proxy", 443),
    ("ai-factory-api", "Master Hub & Sports API", 8099),
    ("puchflix-party", "Watch Party WebRTC Signaling", 9999),
    ("coturn", "Singapore TURN/STUN Relay", 3478),
    ("omniroute", "OmniRoute Local Gateway", 20129),
    ("hermes-gateway", "Hermes Agent (@alicewordbot)", None),
    ("hermes-web", "Hermes Web Dashboard", 9119),
    ("rexapf-trade", "RexAPF Crypto Trade Bot", None),
]

WEB_PROBES = [
    ("portal_cf", "Trang Tổng Portal", "https://vnpunchflix.pages.dev/edge-health"),
    ("vnpunchflix_cf", "Web Xem Phim (Cinema)", "https://vnpunchflix-cinema.pages.dev/"),
    ("sports_cf", "Web Bóng Đá AI (Sports)", "https://vnpunchflix-sports.pages.dev/"),
    ("gym_cf", "Web Quyền PV Gym", "https://vnpunchflix-gym.pages.dev/"),
    ("factory_vps", "AI Factory 3D (Origin)", "https://136.85.54.204.sslip.io/"),
]

os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
fail_streaks = {}
last_restart_ts = {}
heal_history = []
last_ai_probe_ts = 0.0
cached_ai_health = []
last_err_size = 0


def load_env_key(name: str) -> str:
    if os.path.exists(ENV_PATH):
        for line in open(ENV_PATH, encoding="utf-8", errors="ignore"):
            line = line.strip()
            if line.startswith(name + "="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return os.environ.get(name, "")


def tcp_open(port: int, host: str = "127.0.0.1", timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def check_url(url: str, timeout: float = 8.0) -> dict:
    t0 = time.time()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VNPunchFlix-SelfHealer/3.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            ms = int((time.time() - t0) * 1000)
            return {
                "ok": 200 <= r.status < 400,
                "status": r.status,
                "ms": ms,
                "edge_cache": r.headers.get("X-CF-Edge-Cache", ""),
                "colo": r.headers.get("X-CF-Colo", "")
            }
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "ms": int((time.time() - t0) * 1000)}
    except Exception as e:
        return {"ok": False, "status": 0, "ms": int((time.time() - t0) * 1000), "error": str(e)[:80]}


def record_heal(target: str, action: str, outcome: str):
    heal_history.insert(0, {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "target": target,
        "action": action,
        "outcome": outcome
    })
    del heal_history[30:]


def check_smart_router_and_alice(now: float) -> dict:
    """Deep health check for Alice Smart Router + auto-recovery if all slots stuck or Alice dead."""
    global last_err_size
    sr_tok = load_env_key("ALICE_ROUTER_TOKEN")
    sr_status = {"online": False, "healthy_slots": 0, "total_slots": 0}

    try:
        with urllib.request.urlopen("http://127.0.0.1:20135/health", timeout=4) as r:
            sr_status = json.loads(r.read().decode("utf-8", errors="ignore"))
            sr_status["online"] = True
    except Exception:
        sr_status["online"] = False

    # If Smart Router is online but ALL slots got cooled down simultaneously (transient WAN blip), auto-clear cooldowns!
    if sr_status.get("online") and sr_status.get("total_slots", 0) > 0 and sr_status.get("healthy_slots", 0) == 0:
        if sr_tok and (now - last_restart_ts.get("sr_reset_cd", 0) >= 120):
            last_restart_ts["sr_reset_cd"] = now
            try:
                req = urllib.request.Request(
                    "http://127.0.0.1:20135/admin/reset-cooldowns",
                    data=b"{}",
                    headers={"Authorization": f"Bearer {sr_tok}", "Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=4):
                    record_heal("alice-smart-router", "auto_reset_cooldowns (0 healthy slots)", "RECOVERED")
            except Exception as e:
                record_heal("alice-smart-router", "auto_reset_cooldowns", f"ERR: {str(e)[:50]}")

    # Watch Hermes errors.log for sudden critical Telegram disconnection spikes
    try:
        if os.path.exists(HERMES_ERRORS_LOG):
            sz = os.path.getsize(HERMES_ERRORS_LOG)
            if last_err_size > 0 and sz > last_err_size:
                with open(HERMES_ERRORS_LOG, "rb") as f:
                    f.seek(max(0, sz - 8192))
                    tail = f.read().decode("utf-8", errors="ignore")
                if ("Conflict: terminated by other getUpdates" in tail or "Event loop is closed" in tail) and (now - last_restart_ts.get("hermes-gateway", 0) >= 180):
                    last_restart_ts["hermes-gateway"] = now
                    subprocess.run(["systemctl", "restart", "hermes-gateway"], capture_output=True, timeout=20)
                    record_heal("hermes-gateway", "auto_restart (telegram_loop_error)", "RECOVERED")
            last_err_size = sz
    except Exception:
        pass

    return sr_status


def probe_ai_providers() -> list:
    sr_tok = load_env_key("ALICE_ROUTER_TOKEN")
    or_key = load_env_key("OPENROUTER_API_KEY")
    results = []

    if sr_tok:
        for alias in ["alice/auto", "alice/fast"]:
            t0 = time.time()
            try:
                req = urllib.request.Request(
                    "http://127.0.0.1:20135/v1/chat/completions",
                    data=json.dumps({
                        "model": alias,
                        "messages": [{"role": "user", "content": "OK"}],
                        "max_tokens": 256,
                        "temperature": 0,
                    }).encode(),
                    headers={"Authorization": "Bearer " + sr_tok, "Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=20) as r:
                    d = json.loads(r.read().decode("utf-8", errors="ignore"))
                    xr = d.get("x_alice_router") or {}
                    results.append({
                        "provider": xr.get("provider_id", "alice-smart-router"),
                        "model": f"{alias} -> {xr.get('actual_model', alias)}",
                        "ok": r.status == 200,
                        "ms": int((time.time() - t0) * 1000),
                    })
            except urllib.error.HTTPError as e:
                results.append({"provider": "alice-smart-router", "model": alias, "ok": False, "status": e.code, "ms": int((time.time() - t0) * 1000)})
            except Exception as e:
                results.append({"provider": "alice-smart-router", "model": alias, "ok": False, "error": str(e)[:60]})

    if or_key:
        t0 = time.time()
        try:
            req = urllib.request.Request(
                "https://openrouter.ai/api/v1/chat/completions",
                data=json.dumps({"model": "openrouter/free", "messages": [{"role": "user", "content": "OK"}], "max_tokens": 4}).encode(),
                headers={"Authorization": "Bearer " + or_key, "Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as r:
                results.append({"provider": "openrouter", "model": "openrouter/free", "ok": r.status == 200, "ms": int((time.time() - t0) * 1000)})
        except urllib.error.HTTPError as e:
            results.append({"provider": "openrouter", "model": "openrouter/free", "ok": False, "status": e.code, "ms": int((time.time() - t0) * 1000)})
        except Exception as e:
            results.append({"provider": "openrouter", "model": "openrouter/free", "ok": False, "error": str(e)[:60]})

    return results


def run_cycle():
    global last_ai_probe_ts, cached_ai_health
    now = time.time()
    svc_states = []

    for svc, label, port in SERVICES:
        st = subprocess.run(["systemctl", "is-active", svc], capture_output=True, text=True, timeout=5).stdout.strip()
        port_ok = True if port is None else tcp_open(port)
        healthy = (st == "active") and port_ok

        if not healthy:
            fail_streaks[svc] = fail_streaks.get(svc, 0) + 1
            if (st != "active" or fail_streaks[svc] >= 2) and (now - last_restart_ts.get(svc, 0) >= 60):
                last_restart_ts[svc] = now
                subprocess.run(["systemctl", "restart", svc], capture_output=True, timeout=20)
                time.sleep(2)
                st2 = subprocess.run(["systemctl", "is-active", svc], capture_output=True, text=True, timeout=5).stdout.strip()
                port_ok2 = True if port is None else tcp_open(port)
                healthy = (st2 == "active") and port_ok2
                st = st2
                port_ok = port_ok2
                record_heal(svc, "auto_restart", "RECOVERED" if healthy else f"STILL_{st2}")
        else:
            fail_streaks[svc] = 0

        svc_states.append({
            "service": svc,
            "label": label,
            "state": st,
            "port": port,
            "port_ok": port_ok,
            "healthy": healthy
        })

    sr_status = check_smart_router_and_alice(now)

    # Disk pressure auto-remediation (>80% used)
    total_b, used_b, free_b = shutil.disk_usage("/")
    disk_pct = round((used_b / total_b) * 100, 1)
    if disk_pct > 80.0:
        subprocess.run(["journalctl", "--vacuum-time=2d"], capture_output=True, timeout=10)
        subprocess.run(["bash", "-c", "rm -f /tmp/*.py /tmp/*.sh /tmp/*.log /tmp/*.json 2>/dev/null || true"], timeout=8)
        total_b, used_b, free_b = shutil.disk_usage("/")
        new_pct = round((used_b / total_b) * 100, 1)
        record_heal("disk", f"auto_vacuum ({disk_pct}% -> {new_pct}%)", "CLEANED")
        disk_pct = new_pct

    # Memory check
    mem_avail_mb = 0
    try:
        for line in open("/proc/meminfo"):
            if line.startswith("MemAvailable:"):
                mem_avail_mb = int(line.split()[1]) // 1024
                break
    except Exception:
        pass

    # Web probes
    webs = []
    for wid, wlabel, wurl in WEB_PROBES:
        res = check_url(wurl)
        webs.append({"id": wid, "label": wlabel, "url": wurl, **res})

    # Periodic AI provider check (every 10 minutes to preserve free/paid quota)
    if now - last_ai_probe_ts >= 600 or not cached_ai_health:
        cached_ai_health = probe_ai_providers()
        last_ai_probe_ts = now

    snapshot = {
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "healer_status": "ACTIVE_247",
        "disk_used_pct": disk_pct,
        "disk_free_gb": round(free_b / (1024 ** 3), 2),
        "mem_avail_mb": mem_avail_mb,
        "services_healthy": sum(1 for s in svc_states if s["healthy"]),
        "services_total": len(svc_states),
        "services": svc_states,
        "smart_router": {
            "online": bool(sr_status.get("online")),
            "healthy_slots": sr_status.get("healthy_slots", 0),
            "total_slots": sr_status.get("total_slots", 0),
            "total_failovers": sr_status.get("total_failovers", 0),
        },
        "webs": webs,
        "ai_models": cached_ai_health,
        "heal_history": heal_history
    }
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, ensure_ascii=False, indent=2)
    os.replace(tmp, STATE_PATH)


def main():
    print("AI Factory 24/7 Self-Healing Sentinel v3.0 (Alice Smart Router) started.", flush=True)
    while True:
        try:
            run_cycle()
        except Exception as e:
            print(f"Healer cycle error: {e}", flush=True)
        time.sleep(30)


if __name__ == "__main__":
    main()
