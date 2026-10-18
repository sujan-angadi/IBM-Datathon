# LEAKLOCK Architecture Specification

## 1. High-Level System Overview

LEAKLOCK is a modular AI Data Protection Gateway built for the **IBM Z Datathon 2026** ('AI Secured: Innovation Without Exposure').

```text
Streamlit UI (app.py, pages/)
       │
       ▼
core/detector.py          ← Regex engine: 12 sensitive-data categories
core/threat_detector.py   ← Prompt injection / exfiltration rule engine
core/risk_scorer.py       ← Explainable 0–100 contextual risk scoring
core/policy_engine.py     ← RBAC ALLOW / REDACT / BLOCK enforcement
core/audit_logger.py      ← SHA-256 fingerprint + metadata-only logging
       │
       ▼
services/                 ← Phase 3+ Decision & Bridge services
       │
       ▼
hardware/interface/       ← Future: Python ↔ Verilog/FPGA bridge
```

## 2. Phase 2 Boundary Guarantees

- **Zero Prompt Storage:** Prompts are processed strictly in memory and are never written to disk.
- **Zero Secret Leakage in Logs:** Audit records store SHA-256 fingerprints, category counts, risk scores, and policy decisions — never raw prompt text or matched secrets.
- **Pre-Redacted AI Analysis:** When Hybrid AI analysis is enabled, all sensitive spans are replaced with `[REDACTED_<CATEGORY>]` before the text reaches the AI analysis layer.
- **Fail-Closed Policy:** Categories not explicitly in a role's redactable or blocked set default to BLOCK.
- **Hardware Independence:** Runs cleanly on Windows 11, Rocky Linux 10.x, and IBM LinuxONE using only Python 3.10+ and Streamlit.

## 3. Data Flow

```text
User Prompt (untrusted input)
       │
       ▼
detect_sensitive_data()
   ├── Run _RULES regex patterns → raw_candidates
   ├── Secondary validation (Luhn, IPv4 octets, phone digit count)
   ├── _resolve_overlaps() → findings (non-overlapping, sorted by offset)
   ├── _mask_spans_for_ai() → sanitized text (for optional AI layer)
   ├── detect_prompt_threats() → threat_report
   └── calculate_contextual_risk() → risk_eval
       │
       ▼
evaluate_policy(prompt, scan_result, agent_role)
   ├── Check for threats → BLOCK
   ├── Check findings against blocked_categories → BLOCK
   ├── Check findings against redactable_categories → REDACT
   └── No violations → ALLOW
       │
       ▼
audit_logger.log_scan_event()
   ├── SHA-256(prompt) → prompt_sha256
   ├── Category counts (no matched_text)
   ├── Risk score and level
   └── Policy action and role
```

## 4. Detection Priority System

Rules are sorted by priority (higher = evaluated first for overlap resolution):

| Priority | Category |
|---|---|
| 110 | `PRIVATE_KEY_HEADER` |
| 105 | `JWT_TOKEN` |
| 100 | `API_KEY` (assignment form) |
| 95 | `API_KEY` (prefixed form: sk-, gh-, AKIA) |
| 92 | `CREDIT_CARD` (Luhn validated) |
| 91 | `PAN_ID` |
| 90 | `EMPLOYEE_ID`, `CUSTOMER_ID` |
| 88 | `AADHAAR_ID` |
| 85 | `CONFIDENTIAL_IDENTIFIER` |
| 80 | `EMAIL` |
| 75 | `IPV4_ADDRESS` |
| 70 | `PHONE` (Indian) |
| 65 | `PHONE` (International) |


## 5. Phase 4: Security Validation, Limitations & Reliability

### 1. Validated Test Categories
- **Sensitive-Data Detection (`tests/test_detector.py`)**: Positive and negative synthetic test coverage across emails, phone numbers, API keys/tokens, employee/customer IDs, confidential project IDs, Luhn-validated credit-card numbers, PEM private keys, JWT tokens, government ID placeholders (`[Aadhaar Redacted]`), synthetic PAN identifiers (`ABCDE1234F`), and private IPv4 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
- **Overlap-Safe Redaction**: Verified via `redact_spans_safely()`, which sorts character spans by `(start ASC, end DESC)`, merges overlapping intervals while preserving all detected category names (`[REDACTED:CAT1+CAT2]`), and replaces spans right-to-left so character offsets and surrounding Unicode characters never drift.
- **Threat Detection & False-Positive Resistance (`tests/test_security_workflow.py`)**: Covers instruction overrides, system-prompt extraction, data exfiltration, jailbreak framing, and Base64/encoding bypass cues alongside benign programming lookalikes.
- **Fail-Closed Resilience**: Simulated exceptions across detection, threat scanning, risk scoring, and policy evaluation verify that failures always produce `BLOCK`, suppress `sanitized_prompt` (`None`), and never leak raw secrets or file paths in error messages.
- **Audit Privacy & Concurrency**: Verified that audit events and JSONL exports strip all raw prompt and secret fields, record deterministic SHA-256 prompt fingerprints (`sha256:<16-hex-chars>`), and synchronize concurrent access via `threading.RLock`.

### 2. Documented Input Limits
- **Maximum Prompt Size**: `10,000` characters (`MAX_PROMPT_LENGTH` in `config/settings.py`). Requests exceeding `10,000` characters or containing null bytes (`\x00`) are rejected before regex evaluation with a `BLOCK` decision and an `INPUT_LIMIT_EXCEEDED` / `MALFORMED_INPUT_NULL_BYTE` audit event.

### 3. Known Detection Limitations
- **Pattern & Heuristic Scope**: Regex and heuristic detectors provide fast, deterministic defense-in-depth for structured secrets and known adversarial phrases, but cannot guarantee detection of novel semantic prompt injections, custom cipher/steganographic encodings, or unstructured confidential business logic.
- **Pattern Match != Verified Live Identity**: A regex or Luhn match indicates structural similarity to a credential or identifier, not proof that an active credential or real identity exists.

### 4. Audit Retention Behavior
- **In-Memory Default**: By default, audit events are stored in memory for the lifetime of the running Python process and reset upon application restart. Operators should use the **Export Audit Log (JSONL)** control in the Audit Dashboard for external retention.

### 5. Running the Validation Suite
```bash
# Run full test suite with verbose output
pytest -v

# Run detector and redaction span tests only
pytest tests/test_detector.py -v

# Run security workflow, fail-safe, concurrency, and latency harness tests
pytest tests/test_security_workflow.py -v
```
