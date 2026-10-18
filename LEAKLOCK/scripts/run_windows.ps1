$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

if (-not (Test-Path ".venv")) {
    Write-Host "[LEAKLOCK] Creating Python virtual environment in .venv..."
    python -m venv .venv
}

$VenvActivate = Join-Path $RepoRoot ".venv\Scripts\Activate.ps1"
. $VenvActivate

Write-Host "[LEAKLOCK] Installing dependencies from requirements.txt..."
python -m pip install --upgrade pip
pip install -r requirements.txt

Write-Host "[LEAKLOCK] Starting LEAKLOCK Gateway UI..."
streamlit run app.py
