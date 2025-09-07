#!/usr/bin/env bash
# setup.sh — one-time setup for the Ethernet Frame Capture project

set -euo pipefail   # safer bash (exit on error, unset vars, or pipefail)

echo "📦 Setting up project virtual environment..."

# 1. Create a virtual environment in the project folder
python3 -m venv .venv

# 2. Activate it for this script run
source .venv/bin/activate

# 3. Upgrade pip
pip install --upgrade pip

# 4. Install dependencies
pip install -r requirements.txt

echo "✅ Setup complete!"
echo "👉 Next time, activate with: source .venv/bin/activate"
echo "👉 Or just use ./run.sh to launch directly"
