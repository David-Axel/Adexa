"""Regression tests for ADEXA CLI error handling (#23).

Covers previously unhandled failure modes:
* run_doctor() no longer raises FileNotFoundError when docker is missing.
* Guided mode (no args, closed stdin) no longer dumps an EOFError traceback.
* Non-guided mode with invalid URL / unsupported method exits with code 2 and
  an actionable message.
"""
import builtins
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adexa  # noqa: E402
from adexa import build_dvwa_poc_spec, main, run_doctor  # noqa: E402


def _eof_input(*_a, **_k):
    raise EOFError()


def _capture_main(argv):
    """Run main() with a forced argv and an EOF-raising input()."""
    old_argv = sys.argv
    old_input = builtins.input
    sys.argv = argv
    builtins.input = _eof_input
    try:
        with pytest.raises(SystemExit) as exc_info:
            main()
    finally:
        sys.argv = old_argv
        builtins.input = old_input
    return exc_info


def test_doctor_without_docker_does_not_raise(monkeypatch, capsys):
    """run_doctor must report, not crash, when docker is not installed."""
    monkeypatch.setattr(adexa.shutil, "which", lambda _name: None)
    monkeypatch.setattr(
        adexa.urllib.request,
        "urlopen",
        lambda *_a, **_k: (_ for _ in ()).throw(OSError("no network")),
    )
    rc = run_doctor()
    out = capsys.readouterr()
    assert rc == 1
    assert "Docker not found" in out.out
    assert "Docker Compose not available" in out.out
    assert "DVWA is not reachable" in out.out


def test_doctor_with_docker_present(monkeypatch, capsys):
    """run_doctor still succeeds the Docker/Compose sub-checks when installed."""

    class _FakeProc:
        returncode = 0

    monkeypatch.setattr(adexa.shutil, "which", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(adexa.subprocess, "run", lambda *a, **k: _FakeProc())
    monkeypatch.setattr(
        adexa.urllib.request,
        "urlopen",
        lambda *_a, **_k: (_ for _ in ()).throw(OSError("no network")),
    )
    rc = run_doctor()
    out = capsys.readouterr()
    assert rc == 1  # DVWA unreachable in test env
    assert "Docker is running" in out.out
    assert "Docker Compose" in out.out


def test_guided_mode_eof_exits_cleanly(capsys, monkeypatch):
    """Guided mode with closed stdin exits with code 130, no traceback."""
    monkeypatch.setattr(builtins, "input", _eof_input)
    old_argv = sys.argv
    sys.argv = ["adexa.py"]
    try:
        with pytest.raises(SystemExit) as exc_info:
            main()
    finally:
        sys.argv = old_argv
    assert exc_info.value.code == 130
    out = capsys.readouterr()
    assert "Cancelled" in out.out
    assert "Traceback" not in out.err


def test_invalid_url_is_actionable_error(capsys):
    """A missing-scheme --url exits code 2 with a helpful message."""
    exc = _capture_main(
        ["adexa.py", "--url", "no-scheme", "--param", "id",
         "--payload", "'", "--method", "GET"],
    )
    assert exc.value.code == 2
    out = capsys.readouterr()
    combined = out.out + out.err
    assert "URL must include scheme and host" in combined
    assert "adexa.py: error:" in combined


def test_url_without_vulnerabilities_marker_rejected(capsys):
    """A valid URL without /vulnerabilities/ is rejected with a clear hint."""
    exc = _capture_main(
        ["adexa.py", "--url", "http://localhost/sqli/", "--param", "id",
         "--payload", "'", "--method", "GET"],
    )
    assert exc.value.code == 2
    out = capsys.readouterr()
    combined = out.out + out.err
    assert "DVWA vulnerability page" in combined


def test_post_method_rejected(capsys):
    """--method POST is rejected (GET-only)."""
    exc = _capture_main(
        ["adexa.py", "--url", "http://localhost/dvwa/vulnerabilities/sqli/",
         "--param", "id", "--payload", "'", "--method", "POST"],
    )
    assert exc.value.code == 2
    out = capsys.readouterr()
    combined = out.out + out.err
    assert "GET mode only" in combined


def test_missing_required_args_use_argparse_error(capsys):
    """Non-guided mode missing --param / --payload -> argparse error (code 2)."""
    exc = _capture_main(
        ["adexa.py", "--url", "http://localhost/dvwa/vulnerabilities/sqli/"],
    )
    assert exc.value.code == 2
    out = capsys.readouterr()
    combined = out.out + out.err
    assert "--param is required" in combined


def test_build_dvwa_poc_spec_rejects_missing_vuln_marker():
    with pytest.raises(ValueError, match="DVWA vulnerability page"):
        build_dvwa_poc_spec(
            url="http://localhost/sqli/",
            param="id",
            payload="'",
            method="GET",
            username="admin",
            password="password",
        )


def test_build_dvwa_poc_spec_rejects_no_scheme():
    with pytest.raises(ValueError, match="scheme and host"):
        build_dvwa_poc_spec(
            url="no-scheme",
            param="id",
            payload="'",
            method="GET",
            username="admin",
            password="password",
        )
