#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
ALICE SMART AI ROUTER v1.0 — AUTO-MODEL-SWITCHING & SELF-HEALING GATEWAY (24/7)
Bound strictly to 127.0.0.1:20135 (Zero external exposure, Zero-PII telemetry)
================================================================================
Capabilities:
1. Full OpenAI-compatible API:
   - POST /v1/chat/completions (supports non-streaming, SSE stream=true, tools/function calling)
   - GET  /v1/models (exposes accurate context_length metadata so Hermes never logs probe-down)
   - GET  /health & GET /status (redacted live JSON telemetry for Master Hub & Self-Healer)
   - POST /admin/test-failover (authenticated live failover drill)
   - POST /admin/reset-cooldowns (authenticated manual cooldown clear)
2. Multi-Tier Google Cloud + OpenRouter Auto-Switching Pool:
   - Tier 1 (Google Cloud Vertex AI Global — Paid GCP Billing via short-lived Compute Metadata OAuth2):
       google/gemini-3.8-flash, google/gemini-3.1-pro-preview, google/gemini-3.7-flash, google/gemini-3.6-flash, ...
   - Tier 2 (Multi-Project Google Cloud Gemini API Pool — 3 independent GCP projects, round-robin!):
       gemini-3.6-flash, gemini-3.5-flash, gemini-3-flash-preview, gemini-3.5-flash-lite, gemini-3.1-flash-lite, gemini-2.5-flash
   - Tier 3 (OpenRouter Free Fallback — 0 VND safety net):
       baidu/ernie-5.5-flash-preview:free, openrouter/free, google/gemma-4-31b-it:free
3. Self-Healing Circuit Breaker & Request Sanitizer:
   - Automatically rotates away on HTTP 429 (quota/RPM/RPD), 402 (credits), 401/403 (auth),
     404 (deprecated/unavailable model), 500/502/503/504, timeout, or empty content.
   - Smart per-(provider_id, model) cooldowns with automatic recovery & earliest-expiry fallback.
   - Sanitizes OpenAI-only parameters before sending to Google Gemini/Vertex endpoints so Hermes
     tool-calling never hits HTTP 400.
================================================================================
"""

import copy
import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

HOST = os.environ.get("ALICE_ROUTER_HOST", "127.0.0.1")
PORT = int(os.environ.get("ALICE_ROUTER_PORT", "20135"))
POOL_PATH = os.environ.get("ALICE_POOL_PATH", "/opt/ai-factory/data/smart_router_pool.json")
STATE_PATH = os.environ.get("ALICE_STATE_PATH", "/opt/ai-factory/data/smart_router_state.json")
HERMES_ENV_PATH = os.environ.get("HERMES_ENV_PATH", "/opt/ai-factory/hermes/.env")

VN_TZ = timezone(timedelta(hours=7))
START_TIME = time.time()


def now_vn_str() -> str:
    return datetime.now(VN_TZ).strftime("%Y-%m-%d %H:%M:%S ICT")


def load_env_var(name: str, default: str = "") -> str:
    v = os.environ.get(name, "").strip()
    if v:
        return v
    if os.path.exists(HERMES_ENV_PATH):
        try:
            with open(HERMES_ENV_PATH, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    s = line.strip()
                    if s.startswith(name + "="):
                        return s.split("=", 1)[1].strip().strip('"').strip("'")
        except Exception:
            pass
    return default


def redact_text(s: str) -> str:
    if not isinstance(s, str):
        return str(s)
    s = re.sub(r"(AIza[a-zA-Z0-9\-_]{5})[a-zA-Z0-9\-_]+", r"\1***", s)
    s = re.sub(r"(sk-[a-zA-Z0-9\-_]{6})[a-zA-Z0-9\-_]+", r"\1***", s)
    s = re.sub(r"(ya29\.[a-zA-Z0-9\-_]{8})[a-zA-Z0-9\-_\.]+", r"\1***", s)
    return s


# ==============================================================================
# VERTEX AI COMPUTE METADATA OAUTH2 TOKEN MANAGER (ZERO STATIC SECRETS)
# ==============================================================================
class VertexMetadataAuth:
    def __init__(self):
        self._lock = threading.Lock()
        self._token = ""
        self._expires_at = 0.0
        self._last_error = ""

    def get_token(self, force_refresh: bool = False) -> str:
        now = time.time()
        with self._lock:
            if not force_refresh and self._token and now < self._expires_at - 180:
                return self._token
            try:
                req = urllib.request.Request(
                    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                    headers={"Metadata-Flavor": "Google"},
                )
                with urllib.request.urlopen(req, timeout=4) as r:
                    data = json.loads(r.read().decode("utf-8"))
                    self._token = str(data.get("access_token", ""))
                    expires_in = int(data.get("expires_in", 1800))
                    self._expires_at = now + max(120, expires_in)
                    self._last_error = ""
                    return self._token
            except Exception as e:
                self._last_error = str(e)[:120]
                return ""


VERTEX_AUTH = VertexMetadataAuth()


# ==============================================================================
# SMART ROUTER ENGINE (ROUND-ROBIN + TIERED CASCADE + SELF-HEALING COOLDOWNS)
# ==============================================================================
class SmartRouterEngine:
    def __init__(self):
        self._lock = threading.Lock()
        self.router_token = ""
        self.vertex_project = "project-104b6acd-1607-4a2d-ac5"
        self.vertex_models = [
            "google/gemini-3.8-flash",
            "google/gemini-3.1-pro-preview",
        ]
        self.gcp_free_keys = []       # list of dicts {id, label, project, api_key, working_models}
        self.openrouter_key = ""
        self.openrouter_models = [
            "baidu/ernie-5.5-flash-preview:free",
            "openrouter/free",
            "google/gemma-4-31b-it:free",
        ]

        # Runtime state & circuit breakers
        self.cooldowns = {}           # (provider_id, model) -> {"until": ts, "reason": str, "code": int, "hits": int}
        self.rr_index = 0             # Round-robin cursor across GCP free projects
        self.total_requests = 0
        self.total_success = 0
        self.total_failovers = 0
        self.total_errors = 0
        self.last_route = {}
        self.recent_events = []       # Last 30 routing/failover events (redacted)
        self.per_model_stats = {}     # model -> {ok, err, avg_ms, last_used}

        self.reload_pool()

    def reload_pool(self):
        with self._lock:
            self.router_token = load_env_var("ALICE_ROUTER_TOKEN", "")
            self.openrouter_key = load_env_var("OPENROUTER_API_KEY", "")
            self.gcp_free_keys = []
            if os.path.exists(POOL_PATH):
                try:
                    with open(POOL_PATH, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if data.get("router_token") and not self.router_token:
                        self.router_token = str(data["router_token"])
                    if data.get("vertex_project"):
                        self.vertex_project = str(data["vertex_project"])
                    if isinstance(data.get("vertex_models"), list) and data["vertex_models"]:
                        self.vertex_models = [str(m) for m in data["vertex_models"]]
                    if isinstance(data.get("openrouter_models"), list) and data["openrouter_models"]:
                        self.openrouter_models = [str(m) for m in data["openrouter_models"]]
                    for k in data.get("keys", []):
                        if k.get("api_key"):
                            self.gcp_free_keys.append(k)
                except Exception as e:
                    self._log_event("POOL_LOAD_ERR", str(e)[:120])
            if not self.router_token:
                self.router_token = "sk-alice-smart-router-local-2026"
        self._persist_state()

    def _log_event(self, kind: str, detail: str):
        self.recent_events.insert(0, {
            "ts": now_vn_str(),
            "kind": kind,
            "detail": redact_text(detail)[:220],
        })
        del self.recent_events[35:]

    def _next_rr_free_keys(self) -> list:
        """Rotate starting GCP free project every call so RPM/RPD distributes evenly across all 3 projects."""
        with self._lock:
            n = len(self.gcp_free_keys)
            if n == 0:
                return []
            start = self.rr_index % n
            self.rr_index = (self.rr_index + 1) % n
            return self.gcp_free_keys[start:] + self.gcp_free_keys[:start]

    def _is_cooled_down(self, provider_id: str, model: str) -> tuple[bool, float]:
        now = time.time()
        with self._lock:
            cd = self.cooldowns.get((provider_id, model))
            if not cd:
                return False, 0.0
            rem = cd["until"] - now
            if rem <= 0:
                self.cooldowns.pop((provider_id, model), None)
                return False, 0.0
            return True, rem

    def set_cooldown(self, provider_id: str, model: str, code: int, reason: str, custom_sec: int = 0):
        low = (reason or "").lower()
        if custom_sec > 0:
            sec = custom_sec
        elif code == 429:
            if any(x in low for x in ("day", "daily", "rpd", "exhausted", "plan and billing")):
                sec = 900   # 15 minutes for daily quota
            else:
                sec = 65    # 65s for RPM/TPM burst limit
        elif code == 402:
            sec = 3600      # 60 minutes for depleted credits
        elif code in (401, 403):
            sec = 900       # 15 minutes for auth/IAM errors
        elif code == 404:
            sec = 21600     # 6 hours for unavailable model on that key
        elif code in (500, 502, 503, 504):
            sec = 45        # 45s for upstream overload
        elif code == 400:
            sec = 120       # 2m for model-specific schema incompatibility
        else:
            sec = 45

        now = time.time()
        with self._lock:
            prev = self.cooldowns.get((provider_id, model), {})
            hits = int(prev.get("hits", 0)) + 1
            # Backoff cap if repeated failures occur
            effective_sec = min(3600, int(sec * min(3, 1 + (hits - 1) * 0.5))) if custom_sec == 0 else sec
            self.cooldowns[(provider_id, model)] = {
                "until": now + effective_sec,
                "reason": redact_text(reason)[:160],
                "code": code,
                "hits": hits,
                "set_at": now_vn_str(),
            }
            st = self.per_model_stats.setdefault(f"{provider_id}:{model}", {"ok": 0, "err": 0, "avg_ms": 0, "last_used": ""})
            st["err"] += 1
            st["last_used"] = now_vn_str()
            self._log_event("COOLDOWN", f"{provider_id}/{model} -> HTTP {code} ({effective_sec}s): {reason[:90]}")

    def record_success(self, provider_id: str, model: str, tier: str, ms: int, failovers_in_req: int, requested_alias: str):
        with self._lock:
            self.total_success += 1
            self.cooldowns.pop((provider_id, model), None)
            self.last_route = {
                "ts": now_vn_str(),
                "requested": requested_alias,
                "provider_id": provider_id,
                "model": model,
                "tier": tier,
                "latency_ms": ms,
                "failovers": failovers_in_req,
            }
            key = f"{provider_id}:{model}"
            st = self.per_model_stats.setdefault(key, {"ok": 0, "err": 0, "avg_ms": 0, "last_used": ""})
            prev_ok = st["ok"]
            st["ok"] = prev_ok + 1
            st["avg_ms"] = int(((st["avg_ms"] * prev_ok) + ms) / (prev_ok + 1)) if prev_ok > 0 else ms
            st["last_used"] = now_vn_str()
            if failovers_in_req > 0:
                self._log_event("AUTO_SWITCH_OK", f"{requested_alias} auto-switched ({failovers_in_req} retry) -> {provider_id}/{model} ({ms}ms)")
        self._persist_state()

    def build_candidates(self, requested_model: str, messages: list | None = None) -> list:
        """
        Builds ordered list of candidate dicts:
        {"provider_id", "tier", "kind", "url", "model", "api_key"}
        """
        req = (requested_model or "alice/auto").strip()
        free_keys = self._next_rr_free_keys()
        vertex_url = (
            f"https://aiplatform.googleapis.com/v1beta1/projects/{self.vertex_project}"
            f"/locations/global/endpoints/openapi/chat/completions"
        )

        def make_vertex_list(models_order: list) -> list:
            out = []
            for m in models_order:
                vm = m if m.startswith("google/") else f"google/{m}"
                out.append({
                    "provider_id": "gcp-vertex-paid",
                    "tier": "TIER1_VERTEX_PRO",
                    "kind": "vertex_metadata",
                    "url": vertex_url,
                    "model": vm,
                    "api_key": "",
                })
            return out

        def make_free_gcp_list(model_tiers: list) -> list:
            out = []
            for m in model_tiers:
                for k in free_keys:
                    wm = k.get("working_models") or []
                    if wm and m not in wm:
                        continue
                    out.append({
                        "provider_id": k["id"],
                        "tier": "TIER2_GCP_FREE_POOL",
                        "kind": "google_gemini",
                        "url": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
                        "model": m,
                        "api_key": k["api_key"],
                    })
            return out

        def make_openrouter_list(models_order: list | None = None) -> list:
            if not self.openrouter_key:
                return []
            out = []
            for m in (models_order or self.openrouter_models):
                out.append({
                    "provider_id": "openrouter-free",
                    "tier": "TIER3_OPENROUTER_FREE",
                    "kind": "openrouter",
                    "url": "https://openrouter.ai/api/v1/chat/completions",
                    "model": m,
                    "api_key": self.openrouter_key,
                })
            return out

        # Heuristic: detect deep reasoning requests for alice/auto
        deep_hint = False
        if req == "alice/auto" and isinstance(messages, list) and messages:
            last_user = ""
            for msg in reversed(messages):
                if isinstance(msg, dict) and msg.get("role") == "user":
                    c = msg.get("content", "")
                    if isinstance(c, str):
                        last_user = c
                    elif isinstance(c, list):
                        last_user = " ".join(str(p.get("text", "")) for p in c if isinstance(p, dict))
                    break
            low = last_user.lower()
            if len(last_user) > 1200 or any(kw in low for kw in (
                "kiến trúc", "phân tích sâu", "code phức tạp", "debug sâu", "refactor toàn bộ",
                "chiến lược chi tiết", "deep analysis", "architecture review", "tối ưu thuật toán",
            )):
                deep_hint = True

        # Standard model lists
        vx_auto = list(self.vertex_models)
        # Prefer fastest flagship Flash first for chat, Pro second (or Pro first if deep_hint)
        vx_flash_first = [m for m in vx_auto if "flash" in m] + [m for m in vx_auto if "pro" in m]
        vx_pro_first = [m for m in vx_auto if "pro" in m] + [m for m in vx_auto if "flash" in m]

        gcp_free_tiers = [
            "gemini-3-flash-preview",
            "gemini-3.5-flash-lite",
            "gemini-2.5-flash",
            "gemini-3.1-flash-lite",
            "gemini-3.6-flash",
            "gemini-3.5-flash",
        ]

        candidates = []
        if req in ("alice/pro", "gemini-3.1-pro-preview", "google/gemini-3.1-pro-preview", "gemini-2.5-pro", "google/gemini-2.5-pro"):
            candidates = make_vertex_list(vx_pro_first) + make_free_gcp_list(gcp_free_tiers) + make_openrouter_list()
        elif req in ("alice/fast", "alice/lite"):
            # Free-first across 3 GCP projects (0 VND), auto-failover to Vertex Paid -> OpenRouter Free
            candidates = make_free_gcp_list(gcp_free_tiers) + make_vertex_list(vx_flash_first) + make_openrouter_list()
        elif req in ("alice/free", "openrouter/free"):
            candidates = make_free_gcp_list(gcp_free_tiers) + make_openrouter_list()
        elif req == "alice/auto":
            primary_vx = vx_pro_first if deep_hint else vx_flash_first
            candidates = make_vertex_list(primary_vx) + make_free_gcp_list(gcp_free_tiers) + make_openrouter_list()
        else:
            # Direct model request (e.g., gemini-3.8-flash, gemini-3.6-flash, baidu/ernie-5.5-flash-preview:free)
            clean_m = req.replace("google/", "").replace("gemini/", "")
            if req.endswith(":free") or "/" in req and not req.startswith("google/") and not req.startswith("gemini/"):
                candidates = make_openrouter_list([req]) + make_free_gcp_list(gcp_free_tiers) + make_vertex_list(vx_flash_first)
            else:
                if f"google/{clean_m}" in self.vertex_models:
                    candidates += make_vertex_list([f"google/{clean_m}"])
                candidates += make_free_gcp_list([clean_m])
                candidates += make_vertex_list(vx_flash_first) + make_free_gcp_list(gcp_free_tiers) + make_openrouter_list()

        # Deduplicate preserving priority order
        seen = set()
        dedup = []
        for c in candidates:
            key = (c["provider_id"], c["model"])
            if key not in seen:
                seen.add(key)
                dedup.append(c)

        # Split into healthy vs cooled-down (earliest-expiry last resort)
        healthy = []
        cooled = []
        for c in dedup:
            is_cd, rem = self._is_cooled_down(c["provider_id"], c["model"])
            if is_cd:
                cooled.append((rem, c))
            else:
                healthy.append(c)
        cooled.sort(key=lambda x: x[0])
        return healthy + [c for _, c in cooled[:3]]

    def sanitize_payload(self, body: dict, candidate: dict) -> dict:
        """
        Cleans OpenAI-specific fields that cause HTTP 400 on Google Gemini/Vertex OpenAI endpoints
        while preserving tool calling, streaming, temperature, and message history cleanly.
        """
        p = copy.deepcopy(body)
        p["model"] = candidate["model"]
        kind = candidate["kind"]

        # Normalize max_completion_tokens -> max_tokens
        if "max_completion_tokens" in p and "max_tokens" not in p:
            p["max_tokens"] = p.pop("max_completion_tokens")
        else:
            p.pop("max_completion_tokens", None)

        if kind in ("vertex_metadata", "google_gemini"):
            # Strip OpenAI-only parameters rejected by Gemini OpenAI shim
            for bad_k in (
                "store", "metadata", "parallel_tool_calls", "service_tier",
                "prompt_cache_key", "safety_identifier", "reasoning", "include",
                "user", "logit_bias", "logprobs", "top_logprobs", "prediction",
                "modalities", "audio", "web_search_options", "extra_body",
            ):
                p.pop(bad_k, None)

            if not p.get("stream"):
                p.pop("stream_options", None)

            # Gemini 3.x thinking models need headroom so thinking tokens don't starve output!
            if "max_tokens" in p:
                try:
                    mt = int(p["max_tokens"])
                    if mt < 256 and not p.get("_strict_tiny"):
                        p["max_tokens"] = 512
                    elif mt > 65536:
                        p["max_tokens"] = 65536
                except Exception:
                    p.pop("max_tokens", None)

            # Map "developer" role -> "system" & clean null tool content
            msgs = p.get("messages")
            if isinstance(msgs, list):
                cleaned_msgs = []
                for m in msgs:
                    if not isinstance(m, dict):
                        continue
                    mc = copy.deepcopy(m)
                    if mc.get("role") == "developer":
                        mc["role"] = "system"
                    # Gemini OpenAI shim prefers empty string over None for content when no tool_calls
                    if mc.get("content") is None and not mc.get("tool_calls"):
                        mc["content"] = ""
                    # Remove unsupported extra keys on tool messages
                    if mc.get("role") == "tool":
                        mc = {
                            "role": "tool",
                            "tool_call_id": mc.get("tool_call_id", "call_0"),
                            "content": mc.get("content") if isinstance(mc.get("content"), str) else json.dumps(mc.get("content", ""), ensure_ascii=False),
                        }
                    cleaned_msgs.append(mc)
                p["messages"] = cleaned_msgs

            # Clean tool schemas recursively for Gemini strict JSON schema parser
            if isinstance(p.get("tools"), list):
                if len(p["tools"]) == 0:
                    p.pop("tools", None)
                    p.pop("tool_choice", None)
                else:
                    p["tools"] = [self._clean_tool_def(t) for t in p["tools"]]

        p.pop("_strict_tiny", None)
        return p

    def _clean_schema(self, node):
        if isinstance(node, list):
            return [self._clean_schema(x) for x in node]
        if not isinstance(node, dict):
            return node
        out = {}
        for k, v in node.items():
            if k in ("$schema", "$defs", "definitions", "additionalProperties", "strict", "examples", "default", "const"):
                continue
            # Convert nullable ["string", "null"] -> "string"
            if k == "type" and isinstance(v, list):
                non_null = [t for t in v if t != "null"]
                out[k] = non_null[0] if non_null else "string"
                continue
            out[k] = self._clean_schema(v)
        return out

    def _clean_tool_def(self, t: dict) -> dict:
        tc = copy.deepcopy(t)
        fn = tc.get("function")
        if isinstance(fn, dict):
            fn.pop("strict", None)
            if isinstance(fn.get("parameters"), dict):
                fn["parameters"] = self._clean_schema(fn["parameters"])
        return tc

    def get_auth_header(self, candidate: dict, force_refresh: bool = False) -> str:
        if candidate["kind"] == "vertex_metadata":
            tok = VERTEX_AUTH.get_token(force_refresh=force_refresh)
            return f"Bearer {tok}" if tok else ""
        return f"Bearer {candidate['api_key']}"

    def get_status(self) -> dict:
        now = time.time()
        with self._lock:
            active_cooldowns = []
            for (pid, m), info in list(self.cooldowns.items()):
                rem = int(info["until"] - now)
                if rem > 0:
                    active_cooldowns.append({
                        "provider_id": pid,
                        "model": m,
                        "remaining_sec": rem,
                        "code": info.get("code"),
                        "reason": info.get("reason", ""),
                        "hits": info.get("hits", 1),
                    })
                else:
                    self.cooldowns.pop((pid, m), None)

            pool_summary = [
                {
                    "id": "gcp-vertex-paid",
                    "tier": "TIER1_VERTEX_PRO",
                    "project": "[GCP-VERTEX-PROTECTED]",
                    "auth": "Compute Metadata OAuth2 (Zero Static Key)",
                    "models": self.vertex_models,
                    "healthy_models": sum(1 for m in self.vertex_models if ("gcp-vertex-paid", m) not in self.cooldowns),
                }
            ]
            for k in self.gcp_free_keys:
                wm = k.get("working_models") or []
                pool_summary.append({
                    "id": k["id"],
                    "tier": "TIER2_GCP_FREE_POOL",
                    "label": k.get("label", k["id"]),
                    "project": "[GCP-PROJECT-PROTECTED]",
                    "models": wm,
                    "healthy_models": sum(1 for m in wm if (k["id"], m) not in self.cooldowns),
                })
            if self.openrouter_key:
                pool_summary.append({
                    "id": "openrouter-free",
                    "tier": "TIER3_OPENROUTER_FREE",
                    "models": self.openrouter_models,
                    "healthy_models": sum(1 for m in self.openrouter_models if ("openrouter-free", m) not in self.cooldowns),
                })

            total_slots = sum(len(p["models"]) for p in pool_summary)
            healthy_slots = sum(p["healthy_models"] for p in pool_summary)

            return {
                "ok": True,
                "service": "alice-smart-router",
                "version": "1.0.0",
                "port": PORT,
                "uptime_sec": int(now - START_TIME),
                "updated_at": now_vn_str(),
                "total_requests": self.total_requests,
                "total_success": self.total_success,
                "total_failovers": self.total_failovers,
                "total_errors": self.total_errors,
                "healthy_slots": healthy_slots,
                "total_slots": total_slots,
                "active_cooldowns": active_cooldowns,
                "last_route": self.last_route,
                "pool": pool_summary,
                "per_model_stats": self.per_model_stats,
                "recent_events": self.recent_events[:15],
            }

    def _persist_state(self):
        try:
            st = self.get_status()
            os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
            tmp = STATE_PATH + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(st, f, ensure_ascii=False, indent=2)
            os.replace(tmp, STATE_PATH)
        except Exception:
            pass


ENGINE = SmartRouterEngine()


# ==============================================================================
# HTTP HANDLER (STRICT LOOPBACK + BEARER AUTH + STREAMING PASS-THROUGH)
# ==============================================================================
class SmartRouterHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        # Quiet clean stdout logging
        sys.stdout.write(f"[{now_vn_str()}] {self.address_string()} {fmt % args}\n")
        sys.stdout.flush()

    def _send_json(self, code: int, obj: dict):
        raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)

    def _check_auth(self) -> bool:
        expected = ENGINE.router_token
        if not expected:
            return True
        auth = (self.headers.get("Authorization") or "").strip()
        if auth.lower().startswith("bearer "):
            cand = auth[7:].strip()
            if hmac.compare_digest(cand, expected):
                return True
        xkey = (self.headers.get("x-api-key") or "").strip()
        if xkey and hmac.compare_digest(xkey, expected):
            return True
        return False

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/health", "/status"):
            return self._send_json(200, ENGINE.get_status())

        if path == "/v1/models":
            if not self._check_auth():
                return self._send_json(401, {"error": {"message": "Unauthorized", "type": "auth_error"}})
            now_i = int(time.time())
            models = [
                {"id": "alice/auto", "object": "model", "created": now_i, "owned_by": "alice-smart-router", "context_length": 1000000, "max_output_tokens": 65536},
                {"id": "alice/pro", "object": "model", "created": now_i, "owned_by": "alice-smart-router", "context_length": 1000000, "max_output_tokens": 65536},
                {"id": "alice/fast", "object": "model", "created": now_i, "owned_by": "alice-smart-router", "context_length": 1000000, "max_output_tokens": 65536},
                {"id": "alice/free", "object": "model", "created": now_i, "owned_by": "alice-smart-router", "context_length": 1000000, "max_output_tokens": 65536},
            ]
            seen = {m["id"] for m in models}
            for m in ENGINE.vertex_models:
                for mid in (m, m.replace("google/", "")):
                    if mid not in seen:
                        seen.add(mid)
                        models.append({"id": mid, "object": "model", "created": now_i, "owned_by": "google-vertex", "context_length": 1000000, "max_output_tokens": 65536})
            for k in ENGINE.gcp_free_keys:
                for mid in (k.get("working_models") or []):
                    if mid not in seen:
                        seen.add(mid)
                        models.append({"id": mid, "object": "model", "created": now_i, "owned_by": "google-gemini", "context_length": 1000000, "max_output_tokens": 65536})
            for mid in ENGINE.openrouter_models:
                if mid not in seen:
                    seen.add(mid)
                    models.append({"id": mid, "object": "model", "created": now_i, "owned_by": "openrouter-free", "context_length": 128000, "max_output_tokens": 16384})
            return self._send_json(200, {"object": "list", "data": models})

        return self._send_json(404, {"error": {"message": f"Unknown endpoint: {path}"}})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if not self._check_auth():
            return self._send_json(401, {"error": {"message": "Unauthorized", "type": "auth_error"}})

        length = int(self.headers.get("Content-Length") or "0")
        raw_body = self.rfile.read(min(length, 16 * 1024 * 1024)) if length > 0 else b"{}"
        try:
            body = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        except Exception:
            return self._send_json(400, {"error": {"message": "Invalid JSON body"}})

        if path == "/admin/reload":
            ENGINE.reload_pool()
            return self._send_json(200, {"ok": True, "status": ENGINE.get_status()})

        if path == "/admin/reset-cooldowns":
            with ENGINE._lock:
                ENGINE.cooldowns.clear()
                ENGINE._log_event("RESET", "All cooldowns cleared manually")
            ENGINE._persist_state()
            return self._send_json(200, {"ok": True, "message": "Cooldowns cleared"})

        if path == "/admin/test-failover":
            return self._handle_test_failover(body)

        if path == "/v1/chat/completions":
            return self._handle_chat_completions(body)

        return self._send_json(404, {"error": {"message": f"Unknown endpoint: {path}"}})

    def _handle_test_failover(self, body: dict):
        """
        Live E2E failover verification:
        1) Temporarily puts top candidate into 12-second simulated 429 cooldown.
        2) Executes a real chat completion via alice/auto.
        3) Proves router automatically switched to next healthy tier/model & clears simulated cooldown.
        """
        alias = str(body.get("model") or "alice/auto")
        before = ENGINE.build_candidates(alias)
        if len(before) < 2:
            return self._send_json(500, {"ok": False, "error": "Need at least 2 candidates to test failover"})
        first = before[0]
        ENGINE.set_cooldown(first["provider_id"], first["model"], 429, "SIMULATED_429_FAILOVER_DRILL", custom_sec=12)

        t0 = time.time()
        ok, resp_or_err, meta = self._execute_non_streaming({
            "model": alias,
            "messages": [{"role": "user", "content": "Reply with exactly: FAILOVER_OK"}],
            "max_tokens": 256,
            "temperature": 0,
        })
        # Clear simulated cooldown immediately so normal production isn't impacted
        with ENGINE._lock:
            cd = ENGINE.cooldowns.get((first["provider_id"], first["model"]))
            if cd and "SIMULATED_429_FAILOVER_DRILL" in cd.get("reason", ""):
                ENGINE.cooldowns.pop((first["provider_id"], first["model"]), None)
        ENGINE._persist_state()
        return self._send_json(200 if ok else 502, {
            "ok": ok,
            "simulated_failed_primary": f"{first['provider_id']}/{first['model']}",
            "switched_to": meta,
            "elapsed_ms": int((time.time() - t0) * 1000),
            "reply": (resp_or_err.get("choices", [{}])[0].get("message", {}).get("content", "") if isinstance(resp_or_err, dict) else str(resp_or_err))[:120],
        })

    def _execute_non_streaming(self, body: dict) -> tuple[bool, dict | str, dict]:
        req_model = str(body.get("model") or "alice/auto")
        candidates = ENGINE.build_candidates(req_model, body.get("messages"))
        with ENGINE._lock:
            ENGINE.total_requests += 1

        failovers = 0
        errors = []
        max_attempts = min(len(candidates), 10)

        for idx, cand in enumerate(candidates[:max_attempts]):
            auth_hdr = ENGINE.get_auth_header(cand)
            if not auth_hdr:
                ENGINE.set_cooldown(cand["provider_id"], cand["model"], 401, "Missing/empty auth token")
                failovers += 1
                errors.append(f"{cand['provider_id']}/{cand['model']}: no_auth")
                continue

            payload = ENGINE.sanitize_payload(body, cand)
            payload["stream"] = False
            data_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers = {
                "Authorization": auth_hdr,
                "Content-Type": "application/json",
                "User-Agent": "AliceSmartRouter/1.0",
            }
            if cand["kind"] == "openrouter":
                headers["HTTP-Referer"] = "https://136.85.54.204.sslip.io"
                headers["X-Title"] = "Alice Smart Router"

            t0 = time.time()
            try:
                req = urllib.request.Request(cand["url"], data=data_bytes, headers=headers, method="POST")
                timeout_s = 45 if "pro" in cand["model"] else (18 if cand["kind"] == "google_gemini" else 28)
                with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                    raw = resp.read().decode("utf-8", errors="replace")
                    parsed = json.loads(raw)
                ms = int((time.time() - t0) * 1000)

                # Validate non-empty content OR tool_calls
                choice0 = (parsed.get("choices") or [{}])[0]
                msg0 = choice0.get("message") or {}
                has_content = bool((msg0.get("content") or "").strip())
                has_tools = bool(msg0.get("tool_calls"))
                if not has_content and not has_tools:
                    ENGINE.set_cooldown(cand["provider_id"], cand["model"], 502, "Empty response (no content/tool_calls)", custom_sec=30)
                    failovers += 1
                    errors.append(f"{cand['provider_id']}/{cand['model']}: empty_response")
                    continue

                # Annotate response with actual routed model cleanly
                parsed["x_alice_router"] = {
                    "provider_id": cand["provider_id"],
                    "tier": cand["tier"],
                    "actual_model": cand["model"],
                    "latency_ms": ms,
                    "failovers": failovers,
                }
                if failovers > 0:
                    with ENGINE._lock:
                        ENGINE.total_failovers += failovers
                ENGINE.record_success(cand["provider_id"], cand["model"], cand["tier"], ms, failovers, req_model)
                return True, parsed, {
                    "provider_id": cand["provider_id"],
                    "tier": cand["tier"],
                    "model": cand["model"],
                    "latency_ms": ms,
                    "failovers": failovers,
                }

            except urllib.error.HTTPError as he:
                err_body = he.read().decode("utf-8", errors="ignore")[:240].replace("\n", " ")
                # If Vertex token expired (401), force refresh once
                if he.code == 401 and cand["kind"] == "vertex_metadata":
                    VERTEX_AUTH.get_token(force_refresh=True)
                ENGINE.set_cooldown(cand["provider_id"], cand["model"], he.code, err_body)
                failovers += 1
                errors.append(f"{cand['provider_id']}/{cand['model']}: HTTP {he.code}")
            except Exception as e:
                ENGINE.set_cooldown(cand["provider_id"], cand["model"], 504, str(e)[:120])
                failovers += 1
                errors.append(f"{cand['provider_id']}/{cand['model']}: {str(e)[:60]}")

        with ENGINE._lock:
            ENGINE.total_errors += 1
            ENGINE._log_event("ALL_FAILED", f"{req_model}: {' | '.join(errors[:5])}")
        ENGINE._persist_state()
        return False, " | ".join(errors[:6]), {}

    def _handle_chat_completions(self, body: dict):
        is_stream = bool(body.get("stream", False))
        if not is_stream:
            ok, result, _meta = self._execute_non_streaming(body)
            if ok and isinstance(result, dict):
                return self._send_json(200, result)
            return self._send_json(502, {
                "error": {
                    "message": f"All AI providers failed after automatic failover: {result}",
                    "type": "upstream_failover_exhausted",
                }
            })

        # Streaming SSE pass-through with pre-header automatic failover!
        req_model = str(body.get("model") or "alice/auto")
        candidates = ENGINE.build_candidates(req_model, body.get("messages"))
        with ENGINE._lock:
            ENGINE.total_requests += 1

        failovers = 0
        errors = []
        max_attempts = min(len(candidates), 10)

        for cand in candidates[:max_attempts]:
            auth_hdr = ENGINE.get_auth_header(cand)
            if not auth_hdr:
                ENGINE.set_cooldown(cand["provider_id"], cand["model"], 401, "Missing/empty auth token")
                failovers += 1
                continue

            payload = ENGINE.sanitize_payload(body, cand)
            payload["stream"] = True
            data_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers = {
                "Authorization": auth_hdr,
                "Content-Type": "application/json",
                "Accept": "text/event-stream",
                "User-Agent": "AliceSmartRouter/1.0",
            }
            if cand["kind"] == "openrouter":
                headers["HTTP-Referer"] = "https://136.85.54.204.sslip.io"
                headers["X-Title"] = "Alice Smart Router"

            t0 = time.time()
            try:
                req = urllib.request.Request(cand["url"], data=data_bytes, headers=headers, method="POST")
                timeout_s = 45 if "pro" in cand["model"] else 30
                resp = urllib.request.urlopen(req, timeout=timeout_s)
                # Connected with 200 OK! Now stream chunks cleanly to client
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.send_header("X-Alice-Provider", cand["provider_id"])
                self.send_header("X-Alice-Model", cand["model"])
                self.end_headers()

                try:
                    while True:
                        chunk = resp.readline()
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        self.wfile.flush()
                finally:
                    resp.close()

                ms = int((time.time() - t0) * 1000)
                if failovers > 0:
                    with ENGINE._lock:
                        ENGINE.total_failovers += failovers
                ENGINE.record_success(cand["provider_id"], cand["model"], cand["tier"], ms, failovers, req_model)
                return

            except urllib.error.HTTPError as he:
                err_body = he.read().decode("utf-8", errors="ignore")[:240].replace("\n", " ")
                if he.code == 401 and cand["kind"] == "vertex_metadata":
                    VERTEX_AUTH.get_token(force_refresh=True)
                ENGINE.set_cooldown(cand["provider_id"], cand["model"], he.code, err_body)
                failovers += 1
                errors.append(f"{cand['provider_id']}/{cand['model']}: HTTP {he.code}")
            except Exception as e:
                ENGINE.set_cooldown(cand["provider_id"], cand["model"], 504, str(e)[:120])
                failovers += 1
                errors.append(f"{cand['provider_id']}/{cand['model']}: {str(e)[:60]}")

        with ENGINE._lock:
            ENGINE.total_errors += 1
            ENGINE._log_event("ALL_STREAM_FAILED", f"{req_model}: {' | '.join(errors[:5])}")
        ENGINE._persist_state()
        return self._send_json(502, {
            "error": {
                "message": f"All streaming providers failed: {' | '.join(errors[:5])}",
                "type": "upstream_failover_exhausted",
            }
        })


def main():
    server = ThreadingHTTPServer((HOST, PORT), SmartRouterHandler)
    server.daemon_threads = True
    print(f"Alice Smart AI Router v1.0 listening strictly on http://{HOST}:{PORT} "
          f"(Vertex={len(ENGINE.vertex_models)} models, GCP_Free_Projects={len(ENGINE.gcp_free_keys)}, "
          f"OpenRouter={'ON' if ENGINE.openrouter_key else 'OFF'})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
