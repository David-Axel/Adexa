from backends.web_backend import _extract_security_level


def test_extract_security_level_current_dvwa_format():
    html = "<p>Security level is currently: <em>low</em>.<p>"

    assert _extract_security_level(html) == "low"
