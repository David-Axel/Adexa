from backends.web_backend import WebBackend


def test_strategy_feedback_records_attempt_and_useful_signal():
    backend = WebBackend.__new__(WebBackend)

    state = {
        "strategy_used": "SWITCH_BOOLEAN",
    }

    web = {
        "failure_type": "ok_or_unknown",
        "response_fp": "changed",
        "baseline_fp": "baseline",
    }

    backend._record_strategy_feedback(state, web)

    feedback = state["strategy_feedback"]["SWITCH_BOOLEAN"]

    assert feedback["attempts"] == 1
    assert feedback["useful_signals"] == 1



def test_strategy_feedback_accumulates_multiple_attempts():
    backend = WebBackend.__new__(WebBackend)

    state = {"strategy_used": "SWITCH_BOOLEAN"}

    backend._record_strategy_feedback(
        state,
        {
            "failure_type": "ok_or_unknown",
            "response_fp": "same",
            "baseline_fp": "same",
        },
    )

    backend._record_strategy_feedback(
        state,
        {
            "failure_type": "ok_or_unknown",
            "response_fp": "changed",
            "baseline_fp": "same",
        },
    )

    feedback = state["strategy_feedback"]["SWITCH_BOOLEAN"]

    assert feedback["attempts"] == 2
    assert feedback["useful_signals"] == 1


def test_ai_observation_includes_strategy_feedback():
    backend = WebBackend.__new__(WebBackend)

    backend.spec = {
        "adexa_cli": {
            "param": "id",
            "candidate_step": "sqli_candidate",
            "starting_payload": "1' OR 1=1 -- -",
        },
        "steps": [],
        "success": {},
    }

    state = {
        "strategy_feedback": {
            "CHANGE_QUOTES": {
                "attempts": 2,
                "useful_signals": 0,
            },
            "SWITCH_BOOLEAN": {
                "attempts": 1,
                "useful_signals": 1,
            },
        },
        "attempt_history": [],
    }

    web = {
        "path": "/vulnerabilities/sqli/?id=1",
        "method": "GET",
        "auth_state": "authenticated",
        "elapsed_s": 0.1,
        "response_fp": "abc",
        "baseline_fp": "abc",
        "failure_type": "candidate_not_confirmed",
    }

    observation = backend._build_ai_observation(
        state,
        web,
        allowed_strategies=["CHANGE_QUOTES", "SWITCH_BOOLEAN", "SWITCH_TIME"],
    )

    assert observation["strategy_feedback"] == state["strategy_feedback"]


def test_observe_automatically_records_strategy_feedback():
    from unittest.mock import Mock

    spec = {
        "base_url": "http://127.0.0.1:4280",
        "steps": [{
            "id": "sqli_candidate",
            "path": "/vulnerabilities/sqli/?id=1%27%20OR%201%3D1--",
        }],
    }

    backend = WebBackend(spec, "test_strategy_feedback_observe")

    response = Mock()
    response.status_code = 200
    response.text = "changed response"
    response.headers = {}
    backend.session.get = Mock(return_value=response)

    state = {
        "step_index": 0,
        "strategy_used": "SWITCH_BOOLEAN",
        "response_fingerprints": {
            "baseline": "different-fingerprint",
        },
    }

    backend.observe(state)

    feedback = state["strategy_feedback"]["SWITCH_BOOLEAN"]

    assert feedback["attempts"] == 1


def test_failed_changed_response_is_not_counted_as_useful():
    backend = WebBackend.__new__(WebBackend)

    state = {"strategy_used": "SWITCH_BOOLEAN"}

    web = {
        "failure_type": "candidate_not_confirmed",
        "response_fp": "changed",
        "baseline_fp": "baseline",
    }

    backend._record_strategy_feedback(state, web)

    feedback = state["strategy_feedback"]["SWITCH_BOOLEAN"]

    assert feedback["attempts"] == 1
    assert feedback["useful_signals"] == 0
