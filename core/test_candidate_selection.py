from core.loop_controller import select_best_candidate


def test_repeated_boolean_failures_should_reduce_boolean_preference():
    candidates = [
        "1' AND 1=1 -- -",
        "1' AND SLEEP(5) -- -",
    ]

    history = [
        {
            "payload": "1' AND 1=2 -- -",
            "normalized_payload": "1' AND 1=2 -- -",
            "failure_type": "boolean_no_difference",
            "likely_result": "no_boolean_difference",
        },
        {
            "payload": "1' OR 1=2 -- -",
            "normalized_payload": "1' OR 1=2 -- -",
            "failure_type": "boolean_no_difference",
            "likely_result": "no_boolean_difference",
        },
    ]

    context = {
        "current_payload": "1' AND 1=2 -- -",
        "preferred_style": "quoted",
    }

    selected, reason = select_best_candidate(
        candidates=candidates,
        history=history,
        context=context,
    )

    print("SELECTED:", selected)
    print("REASON:", reason)

    assert selected == "1' AND SLEEP(5) -- -"
