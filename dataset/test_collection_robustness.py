"""Regression tests for pytest collection without a running DVWA instance.

Issue #11: importing dataset/test_verifier.py during pytest collection must
never terminate the test session (no exit()/SystemExit), and the DVWA
integration tests must skip cleanly when the authorized local DVWA lab is
unreachable.

The end-to-end checks run pytest in a subprocess so that a regression
(exit(), SystemExit, a collection crash) reproduces here instead of breaking
the suite.
"""

import os
import subprocess
import sys
from unittest import mock

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# dataset/test_verifier.py lives next to this file, not at the repo root.
TEST_FILE = os.path.join(os.path.dirname(__file__), "test_verifier.py")
DATASET_DIR = os.path.dirname(TEST_FILE)


def _subprocess_env():
    """Env for subprocess probes: repo root + dataset/ on PYTHONPATH."""
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([REPO_ROOT, DATASET_DIR])
    return env


# Path bootstrap embedded into ``python -c`` probe sources: some Python
# distributions (embeddable builds) ignore PYTHONPATH entirely, so probes
# must not depend on the environment to import dataset modules.
_BOOTSTRAP = (
    "import sys; sys.path.insert(0, " + repr(REPO_ROOT) + "); "
    "sys.path.insert(0, " + repr(DATASET_DIR) + ")\n"
)


def _run_pytest_on_verifier():
    """Run pytest against dataset/test_verifier.py in a clean subprocess.

    Mirrors how the suite is run from the repo root:
    ``PYTHONPATH=. python -m pytest -v``. dataset/ is added to PYTHONPATH so
    the module imports resolve the same way they do under that invocation
    (pytest inserts the rootdir-relative test file's parent directory).
    """
    env = _subprocess_env()

    return subprocess.run(
        [sys.executable, "-m", "pytest", TEST_FILE, "-q"],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=300,
    )


def test_verifier_test_module_has_no_exit_calls():
    """dataset/test_verifier.py must not call exit() (issue #11)."""
    with open(TEST_FILE, "r", encoding="utf-8") as handle:
        source = handle.read()

    forbidden = ["exit(", "sys.exit(", "os._exit(", "quit("]
    for token in forbidden:
        assert token not in source, (
            f"test_verifier.py must not call {token!r} during collection"
        )


def test_verifier_module_import_is_safe_without_dvwa():
    """Importing test_verifier must not connect anywhere or terminate."""
    result = subprocess.run(
        [sys.executable, "-c", _BOOTSTRAP + "import test_verifier"],
        cwd=REPO_ROOT,
        env=_subprocess_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, (
        "importing dataset/test_verifier.py failed:\n" f"{result.stdout}"
    )


def test_pytest_run_is_clean_when_dvwa_is_unreachable():
    """Full run on test_verifier.py: pass or clean skip, never a crash.

    Exit codes: 0 = tests ran, 5 = all tests skipped (no DVWA lab). Any
    other code means collection or execution blew up.
    """
    result = _run_pytest_on_verifier()

    assert result.returncode in (0, 5), (
        "pytest did not finish cleanly without DVWA:\n" f"{result.stdout}"
    )
    assert "Traceback" not in result.stdout
    assert (
        "skipped" in result.stdout.lower() or "passed" in result.stdout.lower()
    )


@pytest.mark.parametrize(
    "exc_name",
    [
        "urllib.error.URLError",
        "ConnectionResetError",
        "OSError",
        "TimeoutError",
    ],
)
def test_fixture_skips_cleanly_on_any_connection_failure(exc_name):
    """Any connection-level failure must produce a skip, not an error.

    Runs the real dataset/test_verifier.py under pytest.main with login
    patched to raise. Direct fixture invocation is not used: pytest >= 8
    forbids calling fixtures directly, which would fail the probe for the
    wrong reason.
    """
    probe = (
        _BOOTSTRAP
        + "import urllib.error\n"
        + "from unittest import mock\n"
        + "import pytest\n"
        + "import verifier\n"
        + "EXCS = {\n"
        + "    'urllib.error.URLError': urllib.error.URLError,\n"
        + "    'ConnectionResetError': ConnectionResetError,\n"
        + "    'OSError': OSError,\n"
        + "    'TimeoutError': TimeoutError,\n"
        + "}\n"
        + "with mock.patch.object(verifier.DVWAVerifier, 'login',"
        + " side_effect=EXCS['" + exc_name + "']('unreachable')):\n"
        + "    rc = pytest.main([" + repr(TEST_FILE) + ", '-q',"
        + " '-p', 'no:cacheprovider'])\n"
        + "print('RC=%d' % rc)\n"
    )

    result = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=REPO_ROOT,
        env=_subprocess_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=120,
    )

    assert "RC=0" in result.stdout, (
        f"{exc_name} was not handled cleanly:\n{result.stdout}"
    )
    assert "2 skipped" in result.stdout
    assert "error" not in result.stdout.lower().replace("errors=", "")
