import pytest

from verifier import DVWAVerifier


DVWA_URL = "http://192.168.64.7"


@pytest.fixture
def verifier():
    v = DVWAVerifier(
        base_host=DVWA_URL,
        username="admin",
        password="password",
    )

    if not v.login():
        pytest.skip(
            "DVWA is not available. "
            "Start the authorized DVWA laboratory to run integration tests."
        )

    return v


def test_boolean_repair(verifier):
    entry = {
        "broken_payload": "1' AND 1=0 -- -",
        "strategy": "SWITCH_BOOLEAN",
        "repaired_payload": "1' AND 1=1 -- -",
    }

    verified, details = verifier.verify_repair(entry)

    assert verified, details


def test_time_repair(verifier):
    entry = {
        "broken_payload": "1' AND SLEP(3) -- -",
        "strategy": "SWITCH_TIME",
        "repaired_payload": "1' AND SLEEP(3) -- -",
    }

    verified, details = verifier.verify_repair(entry)

    assert verified, details
