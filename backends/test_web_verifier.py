from backends.web_backend import WebBackend
from core.models import Observation


def test_single_slow_request_should_not_verify_time_sqli():
    spec = {
        "base_url": "http://127.0.0.1:4280",
        "success": {
            "time_diff": {
                "baseline_step": "baseline",
                "probe_step": "probe",
                "min_delta_s": 3.0,
            }
        },
        "adexa_cli": {
            "param": "id",
            "candidate_step": "probe",
        },
        "steps": [
            {
                "id": "probe",
                "path": "/vulnerabilities/sqli/?id=1%27+AND+SLEEP%285%29+--+-",
            }
        ],
    }

    backend = WebBackend(spec, "test_single_slow_request")

    state = {
        "step_elapsed": {
            "baseline": 0.2,
            "probe": 5.2,
        },
        "time_probe_active": True,
        "time_probe_confirmations": 0,
    }

    obs = Observation(
        mode="web",
        raw_log_path="",
        extra={
            "web": {
                "failure_type": "time_probe_success",
                "step_id": "probe",
            }
        },
    )

    result = backend.is_success(state, obs)

    print("\nVERIFIED:", result)

    assert result is False


def test_repeated_slow_request_can_verify_time_sqli():
    spec = {
        "base_url": "http://127.0.0.1:4280",
        "success": {
            "time_diff": {
                "baseline_step": "baseline",
                "probe_step": "probe",
                "min_delta_s": 3.0,
            }
        },
        "adexa_cli": {
            "param": "id",
            "candidate_step": "probe",
        },
        "steps": [
            {
                "id": "probe",
                "path": "/vulnerabilities/sqli/?id=1%27+AND+SLEEP%285%29+--+-",
            }
        ],
    }

    backend = WebBackend(spec, "test_repeated_slow_request")

    state = {
        "step_elapsed": {
            "baseline": 0.2,
            "probe": 5.2,
        },
        "time_probe_active": True,
        "time_probe_confirmations": 1,
    }

    obs = Observation(
        mode="web",
        raw_log_path="",
        extra={
            "web": {
                "failure_type": "time_probe_success",
                "step_id": "probe",
            }
        },
    )

    assert backend.is_success(state, obs) is True


def test_first_time_probe_success_requests_confirmation_retry():
    spec = {
        "base_url": "http://127.0.0.1:4280",
        "success": {
            "boolean_diff": {
                "baseline_step": "baseline",
            }
        },
    }

    backend = WebBackend(spec, "test_time_confirmation_plan")

    state = {
        "time_probe_active": True,
        "time_probe_attempts": 0,
        "time_probe_confirmations": 0,
        "time_probe_sleep": 5,
        "time_probe_step_id": "probe",
        "time_probe_baseline_step": "baseline",
    }

    obs = Observation(
        mode="web",
        raw_log_path="",
        extra={
            "web": {
                "step_id": "probe",
                "failure_type": "time_probe_success",
            }
        },
    )

    plan = backend.ai_plan(obs, state)

    assert plan is not None
    assert plan.root_cause == "time_probe_confirmation"
    assert state["time_probe_confirmations"] == 1
    assert state["strategy_used"] == "TIME_CONFIRMATION_RETRY"
    assert any(action.type == "retest" for action in plan.actions)
