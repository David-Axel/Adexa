from core.loop_controller import run_loop
from core.models import Observation, PatchPlan, PatchAction


class FakeStore:
    def __init__(self):
        self.iterations = []

    def save_iteration(self, i, data):
        self.iterations.append(data)


class FakeRetryBackend:
    name = "web"

    def __init__(self):
        self.observations = 0

    def observe(self, state):
        self.observations += 1
        return Observation(mode="web", extra={"web": {"failure_type": "failed"}})

    def is_success(self, state, obs):
        return False

    def ai_plan(self, obs, state):
        # Simulate normal setup / earlier SQLi work consuming 3 iterations.
        setup = state.get("setup_steps", 0)

        if setup < 3:
            state["setup_steps"] = setup + 1
            return PatchPlan(
                root_cause="setup",
                confidence=1.0,
                actions=[PatchAction(type="advance_step")],
            )

        attempts = state.get("time_probe_attempts", 0)

        if attempts >= 2:
            state["strategy_used"] = "TIME_PROBE_GIVE_UP"
            return None

        state["time_probe_attempts"] = attempts + 1

        return PatchPlan(
            root_cause="time_probe_retry",
            confidence=1.0,
            actions=[PatchAction(type="retest")],
        )

    def apply(self, plan, state):
        return state


def test_default_loop_budget_reaches_explicit_retry_exhaustion():
    backend = FakeRetryBackend()
    store = FakeStore()

    result = run_loop(
        backend,
        {
            "setup_steps": 0,
            "time_probe_attempts": 0,
        },
        store,
        max_iters=6,
    )

    print("\nSTRATEGY:", result.get("strategy_used"))
    print("SETUP:", result.get("setup_steps"))
    print("TIME RETRIES:", result.get("time_probe_attempts"))
    print("OBSERVATIONS:", backend.observations)

    assert result.get("strategy_used") == "TIME_PROBE_GIVE_UP"
