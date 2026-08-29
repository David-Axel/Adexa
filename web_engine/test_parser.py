from web_engine.request_parser import parse_request


def test_parse_raw_http():
    raw_http = """POST /login HTTP/1.1
Host: target.com
User-Agent: Mozilla
Content-Type: application/x-www-form-urlencoded

username=admin&password=admin
"""

    result = parse_request(raw_http)

    assert result is not None


def test_parse_curl_command():
    curl_cmd = (
        'curl -X POST http://example.com/api/login '
        '-d "user=test&pass=1234"'
    )

    result = parse_request(curl_cmd)

    assert result is not None


def test_parse_get_request():
    raw_get = """GET /search?q=test HTTP/1.1
Host: site.com
Accept: */*
"""

    result = parse_request(raw_get)

    assert result is not None
