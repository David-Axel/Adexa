from core.loop_controller import run_loop
from core.models import Observation, PatchAction, PatchPlan


class _RecordingStore:
    def __init__(self):
        self.records = []

    def save_iteration(self, index, record):
        self.records.append(record)


class _PlanAlwaysBackend:
    name = "fake-backend"

    def __init__(self):
        self.observe_calls = 0
        self.apply_calls = 0

    def observe(self, state):
        self.observe_calls += 1
        return Observation(mode="web")

    def is_success(self, state, obs):
        return False

    def ai_plan(self, obs, state):
        return PatchPlan(
            root_cause="test plan",
            confidence=1.0,
            actions=[PatchAction(type="retest")],
        )

    def apply(self, plan, state):
        self.apply_calls += 1
        return state


def test_loop_stops_after_max_iters():
    backend = _PlanAlwaysBackend()
    store = _RecordingStore()

    run_loop(backend=backend, state={}, store=store, max_iters=3)

    stop_records = [
        record
        for record in store.records
        if record.get("event") == "stop"
    ]
    assert [record["reason"] for record in stop_records] == ["max_iters"]
    assert stop_records[0]["verified"] is False
    assert backend.observe_calls == 3
    assert backend.apply_calls == 3
