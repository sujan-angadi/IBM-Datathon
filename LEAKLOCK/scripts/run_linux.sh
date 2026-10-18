#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

PYTHON_BIN="${PYTHON_BIN:-python3}"

if [ ! -d ".venv" ]; then
    echo "[LEAKLOCK] Creating Python virtual environment in .venv..."
    "${PYTHON_BIN}" -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

echo "[LEAKLOCK] Installing dependencies from requirements.txt..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[LEAKLOCK] Starting LEAKLOCK Gateway UI on http://localhost:8501 ..."
exec streamlit run app.py --server.headless=true
