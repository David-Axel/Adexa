from unittest.mock import patch

from backends.web_backend import WebBackend
from core.models import Observation


def test_candidate_not_confirmed_rejects_inconsistent_ai_output():
    spec = {
        "base_url": "http://127.0.0.1:4280",
        "adexa_cli": {
            "param": "id",
            "candidate_step": "sqli_candidate",
        },
        "steps": [
            {
                "id": "sqli_candidate",
                "path": "/vulnerabilities/sqli/?id=1",
            }
        ],
        "success": {},
    }

    backend = WebBackend(spec, "test_ai_validation")

    state = {
        "attempt_history": [],
    }

    obs = Observation(
        mode="web",
        extra={
            "web": {
                "failure_type": "candidate_not_confirmed",
                "step_id": "sqli_candidate",
                "path": "/vulnerabilities/sqli/?id=1",
            }
        }
    )

    bad_ai_result = {
        "analysis": {
            "next_strategy": "SWITCH_BOOLEAN",
            "next_payload": "1' OR '1'='1",
            "explanation": "Switch boolean strategy.",
            "confidence": 0.9,
        }
    }

    with patch("backends.web_backend.analyze_poc", return_value=bad_ai_result):
        plan = backend.ai_plan(obs, state)

    # Numeric input + quoted SWITCH_BOOLEAN output is inconsistent
    # according to ADEXA's existing validator, so fallback should be used.
    assert state["proposed_payload"] != "1' OR '1'='1"
    assert "Fallback decision" in state["ai_reason"]
    assert plan is not None
    assert plan.metadata["candidates"] == [state["proposed_payload"]]


def test_bad_candidate_repair_rejects_inconsistent_ai_output():
    spec = {
        "base_url": "http://127.0.0.1:4280",
        "adexa_cli": {
            "param": "id",
            "candidate_step": "sqli_candidate",
        },
        "steps": [
            {
                "id": "sqli_candidate",
                "path": "/vulnerabilities/sqli/?id=1",
            },
            {
                "id": "sqli_false",
                "path": "/vulnerabilities/sqli/?id=1",
            },
        ],
        "success": {},
    }

    backend = WebBackend(spec, "test_bad_candidate_validation")

    state = {"attempt_history": []}

    obs = Observation(
        mode="web",
        extra={
            "web": {
                "failure_type": "ok_or_unknown",
                "step_id": "sqli_false",
                "path": "/vulnerabilities/sqli/?id=1",
            }
        },
    )

    bad_ai_result = {
        "analysis": {
            "next_strategy": "SWITCH_BOOLEAN",
            "next_payload": "1' OR '1'='1",
            "explanation": "Switch boolean strategy.",
            "confidence": 0.9,
        }
    }

    with patch("backends.web_backend.analyze_poc", return_value=bad_ai_result):
        plan = backend.ai_plan(obs, state)

    assert state["proposed_payload"] != "1' OR '1'='1"
    assert "Fallback decision" in state["ai_reason"]
    assert plan is not None
    assert plan.metadata["candidates"] == [state["proposed_payload"]]


def test_boolean_no_difference_rejects_inconsistent_ai_output():
    spec = {
        "base_url": "http://127.0.0.1:4280",
        "adexa_cli": {
            "param": "id",
            "candidate_step": "sqli_candidate",
        },
        "steps": [
            {
                "id": "sqli_candidate",
                "path": "/vulnerabilities/sqli/?id=1",
            }
        ],
        "success": {
            "boolean_diff": {
                "baseline_step": "sqli_baseline",
            }
        },
    }

    backend = WebBackend(spec, "test_boolean_validation")

    state = {"attempt_history": []}

    obs = Observation(
        mode="web",
        extra={
            "web": {
                "failure_type": "boolean_no_difference",
                "step_id": "sqli_candidate",
                "path": "/vulnerabilities/sqli/?id=1",
            }
        },
    )

    bad_ai_result = {
        "analysis": {
            "next_strategy": "SWITCH_BOOLEAN",
            "next_payload": "1' OR '1'='1",
            "explanation": "Switch boolean strategy.",
            "confidence": 0.9,
        }
    }

    with patch("backends.web_backend.analyze_poc", return_value=bad_ai_result):
        plan = backend.ai_plan(obs, state)

    assert state["proposed_payload"] != "1' OR '1'='1"
    assert "Fallback decision" in state["ai_reason"]
    assert plan is not None
    assert plan.metadata["candidates"] == [state["proposed_payload"]]
