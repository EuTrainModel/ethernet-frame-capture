#!/usr/bin/env bash
# run.sh — launcher for the Ethernet Frame Capture project

set -euo pipefail

# Prefer the local venv if it exists
if [[ -x ".venv/bin/python" ]]; then
  PY=".venv/bin/python"
else
  # fallback to system python
  PY="$(command -v python3)"
fi

# Need root for packet capture on Linux/macOS
if [[ "$EUID" -ne 0 ]]; then
  echo "⚡ Running with sudo for packet capture privileges..."
  exec sudo -E "$PY" ethernet_cap.py "$@"
else
  exec "$PY" ethernet_cap.py "$@"
fi
