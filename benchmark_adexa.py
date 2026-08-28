# benchmark_adexa.py
from __future__ import annotations

import subprocess
import re
from pathlib import Path

URL = "http://127.0.0.1:4280/vulnerabilities/sqli/"
PARAM = "id"

payloads = [
    line.strip()
    for line in Path("benchmark_payloads.txt").read_text(encoding="utf-8").splitlines()
    if line.strip()
]


def detect_family(payload: str) -> str:
    p = (payload or "").lower()
    if "sleep(" in p or "benchmark(" in p or "if(" in p:
        return "time"
    if "union" in p and "select" in p:
        return "union"
    if re.search(r"\b(and|or)\b", p):
        return "boolean"
    return "unknown"


def looks_valid(payload: str) -> bool:
    p = (payload or "").strip()
    if not p or p == "NONE":
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

    broken_patterns = [
        r"^\s*'$",
        r'^\s*"$',
        r"\bAND\s*$",
        r"\bOR\s*$",
        r"\bOR\s*=\s*\d+",
        r"\bAND\s*=\s*\d+",
        r"\bOR\s*=\s*'[^']*'",
        r"\bAND\s*=\s*'[^']*'",
        r"'\s*or\s*'[^']*\s*$",
        r"'\s*and\s*'[^']*\s*$",
    ]
    if any(re.search(x, p, flags=re.I) for x in broken_patterns):
        return False

    return True


def is_generic_repair(final_payload: str) -> bool:
    generic_set = {
        "1' AND 1=1 -- -",
        "1 OR 1=1",
        "1 AND 1=1",
        "1' AND SLEEP(5) -- -",
    }
    return (final_payload or "").strip() in generic_set


results = []

for payload in payloads:
    cmd = [
        "python3", "adexa.py",
        "--url", URL,
        "--param", PARAM,
        "--payload", payload,
    ]

    proc = subprocess.run(cmd, capture_output=True, text=True)
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")

    status = re.search(r"\[ADEXA\] Status:\s*(.+)", out)
    final_payload = re.search(r"\[ADEXA\] Final Payload:\s*(.+)", out)
    ai_decision = re.search(r"\[ADEXA\] AI Decision:\s*(.+)", out)
    verified = re.search(r"\[ADEXA\] Verified:\s*(.+)", out)

    used_memory_case = re.search(r"\[ADEXA\] Used Memory Case:\s*(.+)", out)
    memory_match_reason = re.search(r"\[ADEXA\] Memory Match Reason:\s*(.+)", out)

    input_payload = payload
    status_val = status.group(1).strip() if status else "UNKNOWN"
    final_payload_val = final_payload.group(1).strip() if final_payload else "NONE"
    ai_decision_val = ai_decision.group(1).strip() if ai_decision else "NONE"
    verified_val = verified.group(1).strip() if verified else "UNKNOWN"
    if status_val.lower() == "success" and verified_val.lower() == "yes" and final_payload_val.lower() in {"none", "null"}:
        final_payload_val = payload
    used_memory_case_val = used_memory_case.group(1).strip() if used_memory_case else "NONE"
    memory_match_reason_val = memory_match_reason.group(1).strip() if memory_match_reason else "NONE"

    input_family = detect_family(input_payload)
    final_family = detect_family(final_payload_val)

    verified_success = status_val.lower() == "success" and verified_val.lower() == "yes"
    family_preserved = (input_family == final_family) or (input_family == "unknown")
    input_was_valid = looks_valid(input_payload)
    final_is_valid = looks_valid(final_payload_val)
    kept_valid_payload = input_was_valid and input_payload.strip() == final_payload_val.strip()
    generic_repair = is_generic_repair(final_payload_val)
    memory_used = used_memory_case_val.upper() != "NONE"

    quality_score = 0
    if verified_success:
        quality_score += 1
    if final_is_valid:
        quality_score += 1
    if family_preserved:
        quality_score += 1
    if kept_valid_payload:
        quality_score += 1
    if verified_success and final_is_valid and family_preserved and not generic_repair:
        quality_score += 1

    results.append({
        "input_payload": input_payload,
        "status": status_val,
        "final_payload": final_payload_val,
        "ai_decision": ai_decision_val,
        "verified": verified_val,
        "input_family": input_family,
        "final_family": final_family,
        "verified_success": verified_success,
        "family_preserved": family_preserved,
        "input_was_valid": input_was_valid,
        "final_is_valid": final_is_valid,
        "kept_valid_payload": kept_valid_payload,
        "generic_repair": generic_repair,
        "quality_score": quality_score,
        "used_memory_case": used_memory_case_val,
        "memory_match_reason": memory_match_reason_val,
        "memory_used": memory_used,
    })

success_count = sum(1 for r in results if r["verified_success"])
total_quality = sum(r["quality_score"] for r in results)
max_quality = len(results) * 5
generic_count = sum(1 for r in results if r["generic_repair"])
family_preserved_count = sum(1 for r in results if r["family_preserved"])
memory_used_count = sum(1 for r in results if r["memory_used"])
unique_final_payloads = len({r["final_payload"] for r in results if r["final_payload"] and r["final_payload"] != "NONE"})
repeated_payloads = len(results) - unique_final_payloads

print("\n===== ADEXA BENCHMARK RESULTS =====\n")
for i, r in enumerate(results, 1):
    print(f"Test {i}")
    print(f"Input:            {r['input_payload']}")
    print(f"Status:           {r['status']}")
    print(f"Final Payload:    {r['final_payload']}")
    print(f"AI Decision:      {r['ai_decision']}")
    print(f"Verified:         {r['verified']}")
    print(f"Input Family:     {r['input_family']}")
    print(f"Final Family:     {r['final_family']}")
    print(f"Final Valid:      {r['final_is_valid']}")
    print(f"Family Preserved: {r['family_preserved']}")
    print(f"Kept Valid Input: {r['kept_valid_payload']}")
    print(f"Generic Repair:   {r['generic_repair']}")
    print(f"Memory Used:      {r['memory_used']}")
    print(f"Used Memory Case: {r['used_memory_case']}")
    print(f"Memory Reason:    {r['memory_match_reason']}")
    print(f"Quality Score:    {r['quality_score']}/5")
    print("-" * 60)

print(f"\nTotal tests: {len(results)}")
print(f"Verified successes: {success_count}/{len(results)}")
print(f"Family preserved: {family_preserved_count}/{len(results)}")
print(f"Generic repairs: {generic_count}/{len(results)}")
print(f"Memory used: {memory_used_count}/{len(results)}")
print(f"Unique final payloads: {unique_final_payloads}")
print(f"Repeated final payloads: {repeated_payloads}")
print(f"Quality score: {total_quality}/{max_quality}")
