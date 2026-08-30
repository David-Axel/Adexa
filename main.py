from __future__ import annotations

import json
import os
import sys
import uuid
import datetime
from typing import Any, Dict

from core.loop_controller import run_loop
from backends.web_backend import WebBackend
from backends.binary_backend import BinaryBackend


def _json_sanitize(obj: Any) -> Any:
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj

    if isinstance(obj, dict):
        return {str(k): _json_sanitize(v) for k, v in obj.items()}

    if isinstance(obj, (list, tuple, set)):
        return [_json_sanitize(x) for x in obj]

    try:
        import dataclasses
        if dataclasses.is_dataclass(obj):
            return _json_sanitize(dataclasses.asdict(obj))
    except Exception:
        pass

    try:
        return str(obj)
    except Exception:
        return repr(obj)


class RunStore:
    def __init__(self, run_dir: str):
        self.run_dir = run_dir
        os.makedirs(self.run_dir, exist_ok=True)
        self.files_dir = os.path.join(self.run_dir, "files")
        os.makedirs(self.files_dir, exist_ok=True)

    def save_iteration(self, iter_idx: int, payload: Dict[str, Any]) -> None:
        p = os.path.join(self.run_dir, f"iter_{iter_idx:02d}.json")
        clean = _json_sanitize(payload)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(clean, f, indent=2)

    def save_file(self, name: str, content: Any) -> str:
        p = os.path.join(self.files_dir, name)
        with open(p, "w", encoding="utf-8") as f:
            if isinstance(content, (dict, list)):
                json.dump(content, f, indent=2)
            else:
                f.write(str(content))
        return p


def load_spec(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def make_run_id() -> str:
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    short = uuid.uuid4().hex[:6]
    return f"{ts}_{short}"


def print_final_summary(run_dir: str, final_state: Dict[str, Any]) -> None:
    verified_payload = None
    strategy = None
    ai_reason = None
    used_memory_case = None
    memory_match_reason = None

    if isinstance(final_state, dict):
        verified_payload = final_state.get("verified_exploit_payload")
        strategy = final_state.get("strategy_used")
        ai_reason = final_state.get("ai_reason")
        used_memory_case = final_state.get("used_memory_case")
        memory_match_reason = final_state.get("memory_match_reason")

    friendly_strategy = {
        "KEEP_CANDIDATE": "Kept the original working payload",
        "KEEP_REPAIRED": "Used the repaired payload",
        "SWITCH_BOOLEAN": "Switched to a boolean-based repair",
        "SWITCH_TIME": "Switched to a time-based repair",
        "CHANGE_QUOTES": "Repaired broken quote syntax",
    }

    try:
        iter_files = sorted(
            f for f in os.listdir(run_dir)
            if f.startswith("iter_") and f.endswith(".json")
        )

        if not iter_files:
            print("[ADEXA] Status: Failed")
            print("[ADEXA] Final Payload: None")
            print("[ADEXA] AI Decision: No run data found")
            print("[ADEXA] Used Memory Case: NONE")
            print("[ADEXA] Memory Match Reason: NONE")
            print("[ADEXA] Verified: No")
            return

        last_iter = None
        baseline_fp = None
        true_fp = None
        false_fp = None

        for name in iter_files:
            p = os.path.join(run_dir, name)
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)

            web = ((data.get("observation") or {}).get("extra") or {}).get("web") or {}
            step_id = web.get("step_id")
            response_fp = web.get("response_fp")

            if step_id == "sqli_baseline":
                baseline_fp = response_fp
            elif step_id == "sqli_true":
                true_fp = response_fp
            elif step_id == "sqli_false":
                false_fp = response_fp

            last_iter = data

        verified = bool((last_iter or {}).get("verified", False))

        if baseline_fp and true_fp and false_fp:
            if true_fp == baseline_fp and false_fp != baseline_fp:
                verified = True

        status = "Success" if verified else "Failed"

        print()
        print("[ADEXA] Execute ✓")
        print("[ADEXA] Observe ✓")
        print("[ADEXA] Analyze ✓")
        print(f"[ADEXA] Repair → {verified_payload or 'None'}")
        print(f"[ADEXA] Verify {'✓' if verified else '✗'}")
        print()
        print(f"[ADEXA] Status: {status}")
        print(f"[ADEXA] Final Payload: {verified_payload or 'None'}")
        print(f"[ADEXA] AI Decision: {ai_reason or friendly_strategy.get(strategy, 'No decision available')}")
        print(f"[ADEXA] Used Memory Case: {used_memory_case or 'NONE'}")
        print(f"[ADEXA] Memory Match Reason: {memory_match_reason or 'NONE'}")
        print(f"[ADEXA] Verified: {'Yes' if verified else 'No'}")

    except Exception:
        print("[ADEXA] Status: Failed")
        print(f"[ADEXA] Final Payload: {verified_payload or 'None'}")
        print(f"[ADEXA] AI Decision: {ai_reason or 'Summary error'}")
        print(f"[ADEXA] Used Memory Case: {used_memory_case or 'NONE'}")
        print(f"[ADEXA] Memory Match Reason: {memory_match_reason or 'NONE'}")
        print("[ADEXA] Verified: No")


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: python3 main.py <poc_spec.json> <web|binary>")
        sys.exit(1)

    spec_path = sys.argv[1]
    mode = sys.argv[2].strip().lower()

    print("[ADEXA] main.py started")
    run_id = make_run_id()
    print(f"[ADEXA] run_id={run_id}")
    print(f"[ADEXA] mode={mode}")

    run_dir = os.path.join("runs", run_id)
    store = RunStore(run_dir)

    spec = load_spec(spec_path)
    store.save_file("poc_spec_final.json", spec)
    print(f"[+] Final PoC spec saved: {run_dir}/files/poc_spec_final.json")
    print(f"[+] Run folder: {run_dir}")

    state: Dict[str, Any] = {
        "run_id": run_id,
        "poc_spec_path": spec_path,
        "poc_spec": spec,
    }

    if mode == "web":
        backend = WebBackend(spec=spec, run_id=run_id)
        max_iters = max(30, len(spec.get("steps", [])) + 15)
        final_state = run_loop(backend, state, store, max_iters=max_iters)
    elif mode == "binary":
        backend = BinaryBackend()
        max_iters = 25
        final_state = run_loop(backend, state, store, max_iters=max_iters)
    else:
        raise ValueError("mode must be 'web' or 'binary'")

    print_final_summary(run_dir, final_state)


if __name__ == "__main__":
    main()
