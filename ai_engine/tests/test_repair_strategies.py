import os

import pytest

# Force ADEXA onto its deterministic no-LLM safe-fallback path so the runtime
# analysis never depends on Ollama being reachable during the test session.
os.environ["ADEXA_NO_AI"] = "1"

from ai_engine.poc_ai import (
    _is_structurally_valid_candidate,
    _score_candidate_local,
    _heuristic_ranked_candidates,
    _choose_heuristic_decision,
    expand_candidates,
    _build_candidate_list,
    _call_ollama_repair,
    _call_ollama_diagnose,
    analyze_poc,
    ALLOWED_STRATEGIES,
)
from ai_engine.repair_memory import load_repair_memory, _detect_intent, _normalize_payload


class TestSQLInjectionRepairStrategies:
    """Unit tests for SQL injection repair strategies."""

    def test_structural_validation_basic(self):
        """Test basic structural validation of SQL candidates."""
        # Valid candidates
        assert _is_structurally_valid_candidate("1' OR '1'='1") == True
        assert _is_structurally_valid_candidate("1 AND SLEEP(5)") == True
        assert _is_structurally_valid_candidate("1' AND IF(1=1,SLEEP(5),0) -- -") == True
        
        # Invalid candidates
        assert _is_structurally_valid_candidate("1' OR") == False  # Unfinished
        assert _is_structurally_valid_candidate("1' AND") == False  # Unfinished
        assert _is_structurally_valid_candidate("1' OR '1'='1'") == False  # Unbalanced quotes
        assert _is_structurally_valid_candidate("1 AND SLEEP(5") == False  # Unbalanced parenthesis

    def test_scoring_boolean_based(self):
        """Test scoring logic for boolean-based injections."""
        candidate = "1' OR '1'='1"
        current = "1' OR '1'='2"
        likely_intent = "boolean_based"
        likely_damage = ["false_condition"]
        memory_case = None
        
        score, reason = _score_candidate_local(
            candidate=candidate,
            current_payload=current,
            likely_intent=likely_intent,
            likely_damage=likely_damage,
            memory_case=memory_case
        )
        
        # Should get positive score for preserving boolean family
        assert score > 0
        assert "preserved boolean family" in reason

    def test_scoring_time_based(self):
        """Test scoring logic for time-based injections."""
        candidate = "1' AND SLEEP(5) -- -"
        current = "1' AND SLP(5)"
        likely_intent = "time_based"
        likely_damage = ["misspelled_function"]
        memory_case = None
        
        score, reason = _score_candidate_local(
            candidate=candidate,
            current_payload=current,
            likely_intent=likely_intent,
            likely_damage=likely_damage,
            memory_case=memory_case
        )
        
        # Should get positive score for repairing time syntax
        assert score > 0
        assert "repairs time syntax" in reason or "preserved time-based family" in reason

    def test_expand_candidates_boolean(self):
        """Test candidate generation for boolean strategy."""
        base_payload = "1' OR '1'='2"
        strategy = "SWITCH_BOOLEAN"
        current_payload = "1' OR '1'='2"
        
        candidates = expand_candidates(base_payload, strategy, current_payload)
        
        # Should generate boolean candidates
        assert len(candidates) > 0
        assert any("OR" in c and "1=1" in c for c in candidates)
        assert any("'" in c for c in candidates)  # Should preserve quotes

    def test_expand_candidates_time(self):
        """Test candidate generation for time strategy."""
        base_payload = "1' AND SLP(3)"
        strategy = "SWITCH_TIME"
        current_payload = "1' AND SLP(3)"
        
        candidates = expand_candidates(base_payload, strategy, current_payload)
        
        # Should generate time-based candidates
        assert len(candidates) > 0
        assert any("SLEEP" in c for c in candidates)
        assert any("'" in c for c in candidates)  # Should preserve quotes

    def test_build_candidate_list_boolean_with_quotes(self):
        """Test building candidate list for boolean strategy with quotes."""
        primary = "1' OR '1'='2"
        strategy = "SWITCH_BOOLEAN"
        has_quote = True
        has_or = True
        looks_if = False
        
        candidates = _build_candidate_list(primary, strategy, has_quote, has_or, looks_if)
        
        # Should contain boolean repair candidates
        assert len(candidates) > 0
        assert any("1' OR '1'='1" in c for c in candidates)
        assert any("1' AND 1=1 -- -" in c for c in candidates)

    def test_build_candidate_list_time_with_quotes(self):
        """Test building candidate list for time strategy with quotes."""
        primary = "1' AND SLP(3)"
        strategy = "SWITCH_TIME"
        has_quote = True
        has_or = False
        looks_if = False
        
        candidates = _build_candidate_list(primary, strategy, has_quote, has_or, looks_if)
        
        # Should contain time-based repair candidates
        assert len(candidates) > 0
        assert any("SLEEP" in c for c in candidates)
        assert any("'" in c for c in candidates)

    def test_heuristic_ranked_candidates_boolean(self):
        """Test heuristic ranking for boolean candidates."""
        current_payload = "1' OR '1'='2"
        likely_intent = "boolean_based"
        likely_damage = ["false_condition"]
        strategy = "SWITCH_BOOLEAN"
        base_candidates = ["1' OR '1'='1", "1' AND 1=1 -- -", "invalid'"]
        memory_case = None
        
        ranked, best_reason = _heuristic_ranked_candidates(
            current_payload=current_payload,
            likely_intent=likely_intent,
            likely_damage=likely_damage,
            strategy=strategy,
            base_candidates=base_candidates,
            memory_case=memory_case
        )
        
        # Should return ranked candidates
        assert len(ranked) > 0
        assert ranked[0]["payload"] == "1' OR '1'='1"  # Best candidate
        assert ranked[0]["score"] > 0
        assert "payload" in ranked[0]
        assert "score" in ranked[0]
        assert "reason" in ranked[0]

    def test_detect_intent_functions(self):
        """Test intent detection for various payloads."""
        # Boolean-based
        assert _detect_intent("1' OR '1'='1") == "boolean_based"
        assert _detect_intent("1 AND 1=1") == "boolean_based"
        
        # Time-based
        assert _detect_intent("1' AND SLEEP(5)") == "time_based"
        assert _detect_intent("1' AND IF(1=1,SLEEP(5),0)") == "time_based"
        
        # Union-based
        assert _detect_intent("' UNION SELECT username, password FROM users--") == "union_based"
        
        # Unknown
        assert _detect_intent("random text") == "unknown"

    def test_normalize_payload(self):
        """Test payload normalization."""
        # Should lowercase and normalize whitespace
        assert _normalize_payload("1' OR '1'='1") == "1' or '1'='1"
        assert _normalize_payload("  1'   OR   '1'='1  ") == "1' or '1'='1"
        assert _normalize_payload("1'AND'SLEEP(5)") == "1'and'sleep(5)"

    def test_injection_patterns_comprehensive(self):
        """Test comprehensive SQL injection patterns through ADEXA's runtime path."""
        test_cases = [
            # Basic boolean injections
            {
                "broken": "1' OR '1'='2",
                "strategy": "SWITCH_BOOLEAN",
                "expected_intent": "boolean_based",
                "description": "Basic boolean OR injection"
            },
            {
                "broken": "1' AND '1'='2",
                "strategy": "SWITCH_BOOLEAN",
                "expected_intent": "boolean_based",
                "description": "Basic boolean AND injection"
            },
            # Time-based injections
            {
                "broken": "1' AND SLEEP(3)",
                "strategy": "SWITCH_TIME",
                "expected_intent": "time_based",
                "description": "Basic time-based injection"
            },
            {
                "broken": "1' AND SLP(5)",
                "strategy": "SWITCH_TIME",
                "expected_intent": "unknown",
                "description": "Misspelled SLEEP function"
            },
            # IF-based time injections
            {
                "broken": "1' AND IF(1=0,SLEEP(5),0)",
                "strategy": "SWITCH_TIME",
                "expected_intent": "time_based",
                "description": "IF-based time injection"
            },
            # Quote variations
            {
                "broken": '" OR "1"="2',
                "strategy": "SWITCH_BOOLEAN",
                "expected_intent": "boolean_based",
                "description": "Double-quoted boolean injection"
            }
        ]

        for case in test_cases:
            detection = _detect_intent(case["broken"])
            normalized = _normalize_payload(case["broken"])
            assert detection == case["expected_intent"]
            assert isinstance(normalized, str) and normalized

            observation = {
                "payload": {
                    "current_payload_raw": case["broken"],
                    "current_payload_normalized": normalized,
                },
                "payload_features": {
                    "likely_intent": detection,
                    "likely_damage_types": ["unknown"],
                },
                "constraints": {"allowed_strategies": list(ALLOWED_STRATEGIES)},
            }
            result = analyze_poc(observation)
            analysis = result["analysis"]

            assert analysis["next_strategy"] == case["strategy"]
            assert analysis["next_strategy"] in ALLOWED_STRATEGIES
            assert analysis["diagnosis"]["likely_intent"] == detection

            assert 0.0 <= analysis["confidence"] <= 1.0
            assert isinstance(analysis["candidate_scores"], list)
            assert len(analysis["candidate_scores"]) > 0
            for scored in analysis["candidate_scores"]:
                assert isinstance(scored["payload"], str) and scored["payload"].strip()
                assert isinstance(scored["score"], (int, float))
                assert isinstance(scored["reason"], str) and scored["reason"]

            assert analysis["next_payload"] == analysis["candidate_scores"][0]["payload"]
            assert _is_structurally_valid_candidate(analysis["next_payload"])

    def test_edge_cases_and_malformed_inputs(self):
        """Test edge cases and malformed SQL injection attempts."""
        edge_cases = [
            ("", False, "", "unknown"),  # Empty string
            (" ", False, "", "unknown"),  # Whitespace only
            ("1'", False, "1'", "unknown"),  # Unfinished quote
            ("1' OR", False, "1' or", "unknown"),  # Unfinished OR
            ("1 AND SLEEP(", False, "1 and sleep(", "time_based"),  # Unfinished function
            ("1' OR '1'='1'", False, "1' or '1'='1'", "boolean_based"),  # Extra quote
            ("1/*comment*/OR'1'='1", False, "1/*comment*/or'1'='1", "boolean_based"),  # With comment
            (
                "1' OR '1'='1'; DROP TABLE users--",
                True,
                "1' or '1'='1'; drop table users--",
                "boolean_based",
            ),  # Multiple statements
        ]

        for payload, expected_valid, expected_normalized, expected_intent in edge_cases:
            assert _is_structurally_valid_candidate(payload) == expected_valid
            assert _normalize_payload(payload) == expected_normalized
            assert _detect_intent(payload) == expected_intent

            observation = {
                "payload": {"current_payload_raw": payload},
                "payload_features": {
                    "likely_intent": _detect_intent(payload),
                    "likely_damage_types": ["unknown"],
                },
                "constraints": {"allowed_strategies": list(ALLOWED_STRATEGIES)},
            }
            result = analyze_poc(observation)
            analysis = result["analysis"]

            assert analysis["next_strategy"] in ALLOWED_STRATEGIES
            assert 0.0 <= analysis["confidence"] <= 1.0
            assert isinstance(analysis["next_payload"], str) and analysis["next_payload"].strip()
            assert _is_structurally_valid_candidate(analysis["next_payload"])
            assert isinstance(analysis["candidate_scores"], list)
            assert len(analysis["candidate_scores"]) > 0
            for scored in analysis["candidate_scores"]:
                assert isinstance(scored["payload"], str) and scored["payload"].strip()
                assert isinstance(scored["score"], (int, float))
                assert isinstance(scored["reason"], str) and scored["reason"]

    def test_repair_strategy_constraints(self):
        """Test that repair strategies respect constraints."""
        allowed_strategies = {"SWITCH_BOOLEAN"}
        observation = {
            "payload": {"current_payload_raw": "1' OR '1'='2"},
            "payload_features": {
                "likely_intent": "boolean_based",
                "likely_damage_types": ["false_condition"]
            }
        }
        
        # Mock the strategy constraint checking
        from ai_engine.poc_ai import _get_allowed_strategies
        
        # Test with restricted strategies
        constrained_observation = observation.copy()
        constrained_observation["constraints"] = {"allowed_strategies": ["SWITCH_BOOLEAN"]}
        
        allowed = _get_allowed_strategies(constrained_observation)
        assert allowed == {"SWITCH_BOOLEAN"}
        
        # Test fallback to defaults
        default_observation = observation.copy()
        default_observation["constraints"] = {}  # Empty constraints
        
        allowed_default = _get_allowed_strategies(default_observation)
        from ai_engine.poc_ai import ALLOWED_STRATEGIES
        assert allowed_default == ALLOWED_STRATEGIES

    def test_memory_integration_basic(self):
        """Test basic memory integration functions."""
        # Test loading repair memory (should return empty list if no runs directory)
        memory = load_repair_memory(
            current_payload="1' OR '1'='1",
            current_intent="boolean_based",
            runs_dir="nonexistent_directory",
            limit=3
        )
        assert isinstance(memory, list)
        # Should be empty since directory doesn't exist
        assert len(memory) == 0

    def test_sql_injection_specific_patterns(self):
        """Test SQL injection specific patterns mentioned in issue."""
        # Common SQL injection patterns that should be handled
        sqli_patterns = [
            "' OR '1'='1",
            '" OR "1"="1"',
            "' OR '1'='1'--",
            '" OR "1"="1"',
            "' UNION SELECT NULL, NULL, NULL--",
            "' UNION SELECT username, password FROM users--",
            "'; EXEC xp_cmdshell('dir'); --",
            "'; WAITFOR DELAY '00:00:05'--",
            "1' AND SLEEP(5)--",
            "1' OR SLEEP(5)--",
            "1' AND IF(1=1,SLEEP(5),0)--",
            "1' OR IF(1=1,SLEEP(5),0)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5))))--",
            "1' OR (SELECT * FROM (SELECT(SLEEP(5))))--",
        ]
        
        for pattern in sqli_patterns:
            # Test that we can at least analyze the structure
            normalized = _normalize_payload(pattern)
            intent = _detect_intent(normalized)
            valid = _is_structurally_valid_candidate(pattern)
            
            # All should produce some result without crashing
            assert isinstance(normalized, str)
            assert isinstance(intent, str)
            assert isinstance(valid, bool)
            
            # Most common patterns should be structurally valid or detectably invalid
            # in a meaningful way (not crashing)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
