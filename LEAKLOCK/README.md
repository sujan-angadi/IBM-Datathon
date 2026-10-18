# 🛡️ LEAKLOCK — AI Data Protection Gateway

## 1. Problem Statement
Organizations adopting generative AI face critical data-leakage and security risks: employees and automated pipelines routinely paste API keys, private credentials, customer PII, internal IPv4 addresses, or confidential project codenames into external LLM prompts, while adversaries attempt prompt injection and system-prompt extraction.

## 2. Solution & Key Features
**LEAKLOCK** is an application-layer AI Data Protection Gateway that intercepts, inspects, scores, sanitizes, or blocks prompts locally **before** they reach any external AI provider:
- **Multi-Category Sensitive Data Detection**: Detects emails, phone numbers, API keys/tokens, employee & customer IDs, confidential project IDs, Luhn-validated credit cards, PEM private keys, JWTs, government IDs, PAN numbers, and private IPv4 addresses.
- **Adversarial Threat Detection**: Flags instruction overrides, system-prompt extraction, data exfiltration, jailbreak framing, and Base64/encoding bypass patterns.
- **Explainable 0–100 Risk Scorer**: Computes a deterministic risk score and severity level (`NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Role-Based Policy Enforcement (Fail-Closed)**: Evaluates requests under `PUBLIC_ASSISTANT`, `INTERNAL_ANALYST`, `PRIVILEGED_DEBUGGER`, or `AUTOMATED_PIPELINE` policies to produce `ALLOW`, `REDACT`, or `BLOCK`.
- **Overlap-Safe Redaction & Downstream Provider Gate**: Replaces sensitive spans right-to-left and forwards **only** approved or redacted payloads to the configured downstream provider. Blocked requests never leave the gateway.
- **Privacy-Preserving Audit Telemetry**: Records metadata-only audit events with SHA-256 prompt fingerprints (`sha256:<16-hex>`) and JSONL export—never storing raw prompts or secret values.
- **Centralized Design System**: Modern, accessibility-checked official pastel light palette (`#FEF8DD` canvas, `#90D5FF` sky blue, `#FFDBBB` peach, `#E1F8DC` peppermint, `#F1CFE3` blush, `#F7D8BA` soft peach, and `#30343B` dark text).

## 3. Architecture & 10-Step Request Workflow

```text
[User / Pipeline Prompt]
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│                   LEAKLOCK SECURITY GATEWAY                     │
│                                                                 │
│  1. Input Validator (Empty / Null-Byte / 10,000-Char Guard)     │
│  2. Sensitive-Data Detector (core/detector.py)                  │
│  3. Prompt Threat Detector (core/threat_detector.py)            │
│  4. Explainable Risk Scorer 0-100 (core/risk_scorer.py)         │
│  5. Role Policy Engine (core/policy_engine.py — Fail-Closed)    │
│  6. Decision Gate:                                              │
│       ├── ALLOW  ──► Keep approved prompt                       │
│       ├── REDACT ──► Overlap-safe right-to-left span masking    │
│       └── BLOCK  ──► Halt immediately (Never forwarded)         │
│  9. Metadata-Only Audit Logger (core/audit_logger.py + JSONL)   │
└─────────┬───────────────────────────────────────────────────────┘
          │ (Only ALLOW or REDACT payloads)
          ▼
┌─────────────────────────────────────────────────────────────────┐
│  8. Downstream AI Provider Adapter (services/__init__.py)       │
│     • Default: Deterministic Mock Demo Provider (Local)         │
│     • Optional: OpenAI-Compatible Endpoint via .env             │
└─────────────────────────────────────────────────────────────────┘
```

## 4. Installation & Startup Instructions

### Linux (Rocky Linux 10.x, Ubuntu/Debian, IBM LinuxONE `s390x`)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
# Or use the startup script:
bash scripts/run_linux.sh
```

### Windows 11 (PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
# Or use the startup script:
.\scripts\run_windows.ps1
```

## 5. Optional External AI Provider Configuration

By default, LEAKLOCK uses its built-in **Mock Downstream Provider** (`LEAKLOCK_PROVIDER_MODE=mock`) so demonstrations require zero external credentials. To connect an optional OpenAI-compatible API endpoint, copy `.env.example` to `.env` and set:

```bash
export LEAKLOCK_PROVIDER_MODE=openai_compatible
export LEAKLOCK_API_KEY="your-api-key"
export LEAKLOCK_API_BASE_URL="https://api.openai.com/v1/chat/completions"
export LEAKLOCK_MODEL="gpt-4o-mini"
```

## 6. Running the Automated Test Suite

```bash
pytest -v
```

## 7. Known Limitations

* **Pattern & Heuristic Scope**: Regex and heuristic rules provide deterministic detection for structured secrets and known injection phrases, but cannot guarantee detection of all novel semantic jailbreaks or custom encodings.
* **In-Memory Default Audit Store**: Audit records are held in memory during the active process lifecycle unless exported via the **Export Audit Log (JSONL)** button on the Audit Dashboard.