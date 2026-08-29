#!/usr/bin/env bash

set -euo pipefail

echo "======================================"
echo "          ADEXA SETUP"
echo "======================================"
echo

# Check required commands
echo "[1/5] Checking required tools..."

for cmd in python3 git docker; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "❌ Missing required command: $cmd"
        echo "Please install $cmd and run ./setup.sh again."
        exit 1
    fi
done

if ! docker compose version >/dev/null 2>&1; then
    echo "❌ Docker Compose is not available."
    echo "Please install Docker Compose and run ./setup.sh again."
    exit 1
fi

echo "✅ Python, Git, Docker and Docker Compose detected."
echo

# Python environment
echo "[2/5] Setting up Python environment..."

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo "✅ Virtual environment created."
else
    echo "✅ Virtual environment already exists."
fi

echo

# Python dependencies
echo "[3/5] Installing ADEXA dependencies..."

.venv/bin/python -m pip install --upgrade pip
.venv/bin/pip install -r requirements.txt

echo "✅ Python dependencies installed."
echo

# Docker laboratory
echo "[4/5] Starting the DVWA laboratory..."

docker compose -f compose.yml up -d

echo "✅ DVWA containers started."
echo

# DVWA initialization
echo "[5/5] Initializing DVWA..."

./scripts/setup_dvwa.sh

echo
echo "======================================"
echo "       ADEXA SETUP COMPLETE"
echo "======================================"
echo
echo "DVWA: http://127.0.0.1:4280"
echo
echo "To activate the Python environment:"
echo "source .venv/bin/activate"
echo
echo "ADEXA is ready."
echo
echo "Run ADEXA with:"
echo "python3 adexa.py --url http://127.0.0.1:4280/vulnerabilities/sqli/ --param id --payload \"'\" --method GET"
echo
echo "To stop the DVWA laboratory:"
echo "docker compose -f compose.yml down"
echo
