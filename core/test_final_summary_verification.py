import json

from main import print_final_summary


def test_final_summary_does_not_override_failed_verification(tmp_path, capsys):
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    iterations = [
        ("iter_00.json", "sqli_baseline", "same", None),
        ("iter_01.json", "sqli_true", "same", None),
        ("iter_02.json", "sqli_false", "different", None),
    ]

    for name, step, fp, verified in iterations:
        data = {
            "verified": verified,
            "observation": {
                "extra": {
                    "web": {
                        "step_id": step,
                        "response_fp": fp,
                    }
                }
            },
        }
        (run_dir / name).write_text(json.dumps(data))

    # Final loop result explicitly says verification failed.
    (run_dir / "iter_03.json").write_text(json.dumps({
        "event": "stop",
        "reason": "max_iters",
        "verified": False,
    }))

    final_state = {
        "verified_exploit_payload": "1' OR '1",
        "strategy_used": "SWITCH_BOOLEAN",
    }

    print_final_summary(str(run_dir), final_state)

    output = capsys.readouterr().out
    print(output)

    assert "[ADEXA] Status: Failed" in output
    assert "[ADEXA] Verified: No" in output
