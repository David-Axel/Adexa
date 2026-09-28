from core.loop_controller import _maybe_select_candidate
from core.models import PatchAction, PatchPlan


def test_candidate_selection_does_not_mark_payload_verified():
    candidate = "1' AND 2=2 -- -"

    plan = PatchPlan(
        root_cause="candidate_not_confirmed",
        confidence=0.9,
        actions=[
            PatchAction(
                type="mutate_step_query_param",
                value={
                    "step_id": "sqli_candidate",
                    "param": "id",
                    "new_value": candidate,
                },
            )
        ],
        metadata={
            "candidates": [candidate],
            "current_payload": "1' AND 1=2 -- -",
            "target_step_id": "sqli_candidate",
            "target_param": "id",
        },
    )

    state = {
        "verified": False,
        "attempt_history": [],
    }

    _maybe_select_candidate(plan, state)

    assert state["selected_payload"] == candidate
    assert state.get("verified_exploit_payload") is None
    assert state["verified"] is False


def test_generated_fallback_must_not_be_marked_verified():
    from backends.web_backend import WebBackend
    from core.models import Observation

    spec = {
        "base_url": "http://127.0.0.1:4280",
        "adexa_cli": {
            "param": "id",
            "candidate_step": "sqli_candidate",
        },
        "steps": [
            {
                "id": "sqli_candidate",
                "path": "/vulnerabilities/sqli/?id=invalid",
            }
        ],
    }

    backend = WebBackend(spec, "test_unverified_fallback")

    state = {
        "verified": False,
        "proposed_payload": "invalid",
    }

    obs = Observation(
        mode="web",
        extra={"web": {"step_id": "sqli_candidate"}},
    )

    result = backend.finalize_success(state, obs)

    assert result.get("verified_exploit_payload") is None
    assert result.get("verified") is not True


def test_loop_must_not_report_success_when_finalization_fails():
    from core.loop_controller import run_loop
    from core.models import Observation

    class FakeBackend:
        name = "fake-web"

        def observe(self, state):
            return Observation(mode="web")

        def is_success(self, state, obs):
            return True

        def finalize_success(self, state, obs):
            state["verified"] = False
            state.pop("verified_exploit_payload", None)
            return state

    class RecordingStore:
        def __init__(self):
            self.records = []

        def save_iteration(self, index, record):
            self.records.append(record)

    store = RecordingStore()
    state = run_loop(FakeBackend(), {}, store, max_iters=1)

    assert state["verified"] is False

    success_records = [
        record for record in store.records
        if record.get("event") == "stop"
        and record.get("verified") is True
    ]

    assert success_records == []


def test_loop_records_success_after_verified_finalization():
    from core.loop_controller import run_loop
    from core.models import Observation

    class Backend:
        name = "fake-web"

        def observe(self, state):
            return Observation(mode="web")

        def is_success(self, state, obs):
            return True

        def finalize_success(self, state, obs):
            state["verified"] = True
            state["verified_exploit_payload"] = "confirmed-payload"
            return state

    class Store:
        records = []

        def save_iteration(self, index, record):
            self.records.append(record)

    store = Store()
    result = run_loop(Backend(), {}, store, max_iters=1)

    assert result["verified"] is True
    assert result["verified_exploit_payload"] == "confirmed-payload"
    assert len(store.records) == 1
    assert store.records[0]["event"] == "stop"
    assert store.records[0]["reason"] == "success"
    assert store.records[0]["verified"] is True


def test_finalization_does_not_verify_untested_proposal():
    from backends.web_backend import WebBackend
    from core.models import Observation

    spec = {
        "base_url": "http://127.0.0.1:4280",
        "adexa_cli": {
            "param": "id",
            "candidate_step": "sqli_candidate",
        },
        "steps": [
            {
                "id": "sqli_candidate",
                "path": "/vulnerabilities/sqli/?id=invalid",
            }
        ],
    }

    backend = WebBackend(spec, "test_untested_proposal")
    state = {
        "verified": False,
        "proposed_payload": "1' AND 1=1 -- -",
    }
    obs = Observation(
        mode="web",
        extra={"web": {"step_id": "sqli_candidate"}},
    )

    result = backend.finalize_success(state, obs)

    assert result["verified"] is False
    assert result.get("verified_exploit_payload") is None


def test_observation_records_executed_payload():
    from unittest.mock import Mock
    from backends.web_backend import WebBackend

    spec = {
        "base_url": "http://127.0.0.1:4280",
        "steps": [{
            "id": "sqli_candidate",
            "path": "/vulnerabilities/sqli/?id=1",
        }],
    }

    backend = WebBackend(spec, "test_executed_payload")
    response = Mock()
    response.status_code = 200
    response.text = "test response"
    response.headers = {}
    backend.session.get = Mock(return_value=response)

    state = {"step_index": 0}
    obs = backend.observe(state)

    assert obs.extra["web"]["executed_payload"] == "1"


def test_finalization_rejects_changed_untested_payload():
    from backends.web_backend import WebBackend
    from core.models import Observation

    spec = {
        "base_url": "http://127.0.0.1:4280",
        "adexa_cli": {
            "param": "id",
            "candidate_step": "sqli_candidate",
        },
        "steps": [{
            "id": "sqli_candidate",
            "path": "/vulnerabilities/sqli/?id=1%27%20AND%201%3D1--",
        }],
    }

    backend = WebBackend(spec, "test_stale_payload")
    state = {
        "verified": False,
        "executed_payloads": {
            "sqli_candidate": "1' AND 1=2--",
        },
    }

    obs = Observation(
        mode="web",
        extra={"web": {"step_id": "sqli_candidate"}},
    )

    result = backend.finalize_success(state, obs)

    assert result["verified"] is False
    assert result.get("verified_exploit_payload") is None


def test_boolean_finalization_uses_evidence_payload():
    from backends.web_backend import WebBackend
    from core.models import Observation

    true_payload = "1' AND 1=1 -- -"
    candidate = "1' OR 1=1 -- -"

    spec = {
        "base_url": "http://127.0.0.1:4280",
        "adexa_cli": {
            "param": "id",
            "candidate_step": "sqli_candidate",
        },
        "success": {
            "boolean_diff": {
                "baseline_step": "sqli_baseline",
                "true_step": "sqli_true",
                "false_step": "sqli_false",
            }
        },
        "steps": [
            {"id": "sqli_true",
             "path": "/?id=1%27%20AND%201%3D1%20--%20-"},
            {"id": "sqli_candidate",
             "path": "/?id=1%27%20OR%201%3D1%20--%20-"},
        ],
    }

    backend = WebBackend(spec, "test_boolean_evidence")
    state = {
        "verified": False,
        "response_fingerprints": {
            "sqli_baseline": "same",
            "sqli_true": "same",
            "sqli_false": "different",
        },
        "executed_payloads": {
            "sqli_true": true_payload,
            "sqli_candidate": candidate,
        },
    }
    obs = Observation(
        mode="web",
        extra={"web": {"step_id": "sqli_false"}},
    )

    assert backend.is_success(state, obs) is True

    result = backend.finalize_success(state, obs)

    assert result["verified_exploit_payload"] == true_payload


def test_time_finalization_uses_probe_payload():
    from backends.web_backend import WebBackend
    from core.models import Observation

    probe = "1' AND SLEEP(5) -- -"
    candidate = "1' OR 1=1 -- -"

    spec = {
        "base_url": "http://127.0.0.1:4280",
        "adexa_cli": {
            "param": "id",
            "candidate_step": "sqli_candidate",
        },
        "success": {
            "time_diff": {
                "baseline_step": "baseline",
                "probe_step": "probe",
                "min_delta_s": 3.0,
            }
        },
        "steps": [
            {"id": "probe",
             "path": "/?id=1%27%20AND%20SLEEP%285%29%20--%20-"},
            {"id": "sqli_candidate",
             "path": "/?id=1%27%20OR%201%3D1%20--%20-"},
        ],
    }

    backend = WebBackend(spec, "test_time_evidence")
    state = {
        "verified": False,
        "step_elapsed": {
            "baseline": 0.1,
            "probe": 5.1,
        },
        "executed_payloads": {
            "probe": probe,
            "sqli_candidate": candidate,
        },
        "time_probe_active": True,
        "time_probe_confirmations": 1,
    }

    obs = Observation(
        mode="web",
        extra={"web": {"step_id": "probe"}},
    )

    assert backend.is_success(state, obs) is True

    result = backend.finalize_success(state, obs)

    assert result["verified"] is True
    assert result["verified_exploit_payload"] == probe


def test_changing_time_probe_clears_stale_evidence():
    from backends.web_backend import WebBackend
    from core.models import PatchAction, PatchPlan

    spec = {
        "base_url": "http://127.0.0.1:4280",
        "success": {
            "time_diff": {
                "baseline_step": "baseline",
                "probe_step": "probe",
                "min_delta_s": 3.0,
            }
        },
        "steps": [
            {"id": "probe", "path": "/?id=1"},
        ],
    }

    backend = WebBackend(spec, "test_stale_timing")
    state = {
        "executed_payloads": {"probe": "1"},
        "response_fingerprints": {"probe": "old"},
        "step_elapsed": {"probe": 5.1},
        "time_probe_confirmations": 1,
    }

    plan = PatchPlan(
        root_cause="time_probe_retry",
        confidence=1.0,
        actions=[
            PatchAction(
                type="mutate_step_query_param",
                value={
                    "step_id": "probe",
                    "param": "id",
                    "new_value": "1' AND SLEEP(7) -- -",
                },
            )
        ],
        explanation="Change time-probe payload",
    )

    backend.apply(plan, state)

    assert "probe" not in state["executed_payloads"]
    assert "probe" not in state["response_fingerprints"]
    assert "probe" not in state["step_elapsed"]
    assert state["time_probe_confirmations"] == 0



def test_time_evidence_overrides_unrelated_current_candidate():
    from backends.web_backend import WebBackend
    from core.models import Observation

    probe = "1' AND SLEEP(5) -- -"
    candidate = "1' OR 1=1 -- -"

    spec = {
        "base_url": "http://127.0.0.1:4280",
        "adexa_cli": {
            "param": "id",
            "candidate_step": "sqli_candidate",
        },
        "success": {
            "time_diff": {
                "baseline_step": "baseline",
                "probe_step": "probe",
                "min_delta_s": 3.0,
            }
        },
        "steps": [
            {"id": "probe", "path": "/?id=1%27%20AND%20SLEEP%285%29%20--%20-"},
            {"id": "sqli_candidate", "path": "/?id=1%27%20OR%201%3D1%20--%20-"},
        ],
    }

    backend = WebBackend(spec, "test_time_priority")
    state = {
        "step_elapsed": {"baseline": 0.1, "probe": 5.1},
        "executed_payloads": {
            "probe": probe,
            "sqli_candidate": candidate,
        },
        "time_probe_active": True,
        "time_probe_confirmations": 1,
    }

    obs = Observation(
        mode="web",
        extra={"web": {"step_id": "sqli_candidate"}},
    )

    assert backend.is_success(state, obs) is True
    result = backend.finalize_success(state, obs)

    assert result["verified"] is True
    assert result["verified_exploit_payload"] == probe
    assert result["final_payload_source"] == "probe_step"
