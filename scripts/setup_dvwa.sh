#!/usr/bin/env bash
set -euo pipefail

DVWA_URL="${DVWA_URL:-http://127.0.0.1:4280}"
COOKIE_FILE="$(mktemp)"
trap 'rm -f "$COOKIE_FILE"' EXIT

echo "[ADEXA] Waiting for DVWA..."

for _ in $(seq 1 30); do
  if curl -fsS "$DVWA_URL/setup.php" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

TOKEN="$(
  curl -fsS -c "$COOKIE_FILE" "$DVWA_URL/setup.php" \
  | grep -o "user_token' value='[^']*" \
  | cut -d"'" -f3
)"

if [ -z "$TOKEN" ]; then
  echo "[ADEXA] Could not get DVWA setup token."
  exit 1
fi

curl -fsS \
  -b "$COOKIE_FILE" \
  -c "$COOKIE_FILE" \
  -d "create_db=Create+%2F+Reset+Database&user_token=$TOKEN" \
  "$DVWA_URL/setup.php" \
  >/dev/null

echo "[ADEXA] DVWA database initialized."
