"""
Automated pytest suite for LEAKLOCK Phase 2: Sensitive Data Detection Engine.
Uses strictly synthetic data to verify detection accuracy, offsets, risk levels,
overlap resolution, and edge-case handling.
"""

from __future__ import annotations

import pytest

from core.detector import detect_sensitive_data


def test_detect_email_address() -> None:
    prompt = "Contact me at sujan@example.com for project updates."
    result = detect_sensitive_data(prompt)

    assert result["has_sensitive_data"] is True
    assert result["risk_level"] == "MEDIUM"
    assert len(result["findings"]) == 1

    finding = result["findings"][0]
    assert finding["category"] == "EMAIL"
    assert finding["risk_level"] == "MEDIUM"
    assert finding["matched_text"] == "sujan@example.com"
    assert prompt[finding["start"] : finding["end"]] == "sujan@example.com"
    assert result["category_counts"] == {"EMAIL": 1}


@pytest.mark.parametrize(
    "phone_sample",
    [
        "+91 98765 43210",
        "+91-9876543210",
        "9876543210",
        "+1-415-555-0199",
        "(415) 555-0199",
    ],
)
def test_detect_supported_phone_formats(phone_sample: str) -> None:
    prompt = f"Reach the on-call engineer at {phone_sample} immediately."
    result = detect_sensitive_data(prompt)

    assert result["has_sensitive_data"] is True
    assert result["risk_level"] == "MEDIUM"
    assert len(result["findings"]) == 1

    finding = result["findings"][0]
    assert finding["category"] == "PHONE"
    assert finding["matched_text"] == phone_sample
    assert prompt[finding["start"] : finding["end"]] == phone_sample


def test_arbitrary_digit_sequences_not_flagged_as_phone() -> None:
    # Starts with 1-5 without country/area formatting or has fewer/more digits
    prompt = "Invoice 1234567890 and build ID 44556677 were deployed at 20261017."
    result = detect_sensitive_data(prompt)

    assert result["has_sensitive_data"] is False
    assert result["findings"] == []
    assert result["risk_level"] == "LOW"


@pytest.mark.parametrize(
    "credential_snippet",
    [
        "sk-demo-123456789abcdef",
        "api_key=DEMO_SECRET_123456",
        "token: DEMO_TOKEN_ABC123",
    ],
)
def test_detect_api_key_like_strings(credential_snippet: str) -> None:
    prompt = f"Debug config with {credential_snippet} in local test."
    result = detect_sensitive_data(prompt)

    assert result["has_sensitive_data"] is True
    assert result["risk_level"] == "HIGH"
    assert len(result["findings"]) == 1

    finding = result["findings"][0]
    assert finding["category"] == "API_KEY"
    assert finding["risk_level"] == "HIGH"
    assert finding["matched_text"] == credential_snippet
    assert prompt[finding["start"] : finding["end"]] == credential_snippet


def test_detect_employee_customer_and_confidential_identifiers() -> None:
    prompt = (
        "Assign EMP-12345 to review ticket for CUST-98765 "
        "under PROJECT-ALPHA-CONFIDENTIAL."
    )
    result = detect_sensitive_data(prompt)

    assert result["has_sensitive_data"] is True
    assert result["risk_level"] == "HIGH"
    assert len(result["findings"]) == 3

    categories = [f["category"] for f in result["findings"]]
    assert categories == ["EMPLOYEE_ID", "CUSTOMER_ID", "CONFIDENTIAL_IDENTIFIER"]

    matched_texts = [f["matched_text"] for f in result["findings"]]
    assert matched_texts == [
        "EMP-12345",
        "CUST-98765",
        "PROJECT-ALPHA-CONFIDENTIAL",
    ]

    for finding in result["findings"]:
        assert prompt[finding["start"] : finding["end"]] == finding["matched_text"]


def test_multiple_categories_and_risk_escalation() -> None:
    prompt = (
        "Email sujan@example.com or call +91 98765 43210 "
        "to rotate sk-demo-123456789abcdef for EMP-12345."
    )
    result = detect_sensitive_data(prompt)

    assert result["has_sensitive_data"] is True
    # MEDIUM (email, phone) + HIGH (api_key, employee_id) -> overall HIGH
    assert result["risk_level"] == "HIGH"
    assert len(result["findings"]) == 4
    assert result["category_counts"] == {
        "EMAIL": 1,
        "PHONE": 1,
        "API_KEY": 1,
        "EMPLOYEE_ID": 1,
    }


def test_multiple_occurrences_of_same_category() -> None:
    prompt = "Copy alice@example.com, bob@example.org, and charlie@example.net."
    result = detect_sensitive_data(prompt)

    assert result["has_sensitive_data"] is True
    assert result["risk_level"] == "MEDIUM"
    assert len(result["findings"]) == 3
    assert result["category_counts"] == {"EMAIL": 3}
    assert [f["matched_text"] for f in result["findings"]] == [
        "alice@example.com",
        "bob@example.org",
        "charlie@example.net",
    ]


def test_prompt_with_no_sensitive_patterns() -> None:
    prompt = "Write a Python function to compute Fibonacci numbers iteratively."
    result = detect_sensitive_data(prompt)

    assert result["has_sensitive_data"] is False
    assert result["risk_level"] == "LOW"
    assert result["findings"] == []
    assert result["category_counts"] == {}
    assert "No supported sensitive-data patterns" in result["summary"]


@pytest.mark.parametrize("empty_value", ["", "   ", "\n\t  "])
def test_empty_or_whitespace_input(empty_value: str) -> None:
    result = detect_sensitive_data(empty_value)

    assert result["has_sensitive_data"] is False
    assert result["risk_level"] == "LOW"
    assert result["findings"] == []
    assert result["category_counts"] == {}


@pytest.mark.parametrize("invalid_input", [None, 12345, ["prompt"], {"text": "hi"}])
def test_invalid_input_types_raise_type_error(invalid_input: object) -> None:
    with pytest.raises(TypeError):
        detect_sensitive_data(invalid_input)  # type: ignore[arg-type]


def test_overlapping_patterns_do_not_duplicate() -> None:
    # `token: sk-demo-123456789abcdef` matches both `api_key_assignment` (whole span)
    # and `api_key_prefixed` (inner `sk-demo-...` span). Only the outer span should remain.
    prompt = "Header uses token: sk-demo-123456789abcdef for auth."
    result = detect_sensitive_data(prompt)

    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["category"] == "API_KEY"
    assert finding["matched_text"] == "token: sk-demo-123456789abcdef"
    assert prompt[finding["start"] : finding["end"]] == "token: sk-demo-123456789abcdef"


def test_adjacent_matches_and_deterministic_ordering() -> None:
    prompt = "EMP-12345,CUST-98765,sujan@example.com"
    first_run = detect_sensitive_data(prompt)
    second_run = detect_sensitive_data(prompt)

    assert first_run == second_run
    starts = [f["start"] for f in first_run["findings"]]
    assert starts == sorted(starts)
    assert [f["matched_text"] for f in first_run["findings"]] == [
        "EMP-12345",
        "CUST-98765",
        "sujan@example.com",
    ]


def test_configurable_risk_override_for_future_policy_phases() -> None:
    prompt = "Project lead email: lead@example.com under PROJECT-ALPHA-CONFIDENTIAL"
    custom_map = {
        "EMAIL": "LOW",
        "CONFIDENTIAL_IDENTIFIER": "CRITICAL",
    }
    result = detect_sensitive_data(prompt, risk_map=custom_map)

    assert result["risk_level"] == "CRITICAL"
    assert result["findings"][0]["risk_level"] == "LOW"
    assert result["findings"][1]["risk_level"] == "CRITICAL"


def test_invalid_risk_map_raises_value_error() -> None:
    with pytest.raises(ValueError):
        detect_sensitive_data("sujan@example.com", risk_map={"EMAIL": "EXTREME"}) 


# ---------------------------------------------------------------------------
# Phase 4 Sensitive-Data Detection & Redaction Validation Suite
# ---------------------------------------------------------------------------
from services import (
    analyze_prompt_pipeline,
    get_max_prompt_length,
    is_luhn_valid,
    redact_spans_safely,
    run_detection,
    to_dict,
)


def _extract_detected_text_and_categories(result) -> tuple[list[str], str]:
    d = to_dict(result)
    cats: list[str] = []
    if isinstance(result, list):
        for item in result:
            idict = to_dict(item)
            c = idict.get("category") or idict.get("type") or idict.get("label") or str(item)
            cats.append(str(c).upper())
    else:
        for key in ("findings", "matches", "detections", "entities", "items"):
            if isinstance(d.get(key), list):
                for item in d[key]:
                    idict = to_dict(item)
                    c = idict.get("category") or idict.get("type") or idict.get("label") or str(item)
                    cats.append(str(c).upper())
        if isinstance(d.get("categories"), (list, tuple, set)):
            for c in d["categories"]:
                cats.append(str(c).upper())
    return cats, str(result).upper()


# ---------------------------------------------------------------------------
# 1. Positive Synthetic Detection Coverage Across Supported Categories
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "category_label,synthetic_prompt",
    [
        ("EMAIL", "Contact support at sec-ops.team+alerts@example.org for escalation."),
        ("PHONE", "Reach the on-call engineer at +1-415-555-0199 or +91 98765 43210."),
        ("API_KEY", "Use bearer secret sk-proj-ABCDEF1234567890abcdef1234567890abcdef and AKIAIOSFODNN7EXAMPLE."),
        ("EMPLOYEE_CUSTOMER_ID", "Assign ticket to employee EMP-904218 and customer CUST-773819."),
        ("PROJECT_ID", "Confidential codename PROJ-SECRET-4401 / PRJ-INTERNAL-9981."),
        ("CREDIT_CARD_LUHN_VALID", "Charge synthetic test card 4532015112830366 for staging checkout."),
        ("PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0syntheticKeyData==\n-----END RSA PRIVATE KEY-----"),
        ("JWT", "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlN5bnRoZXRpYyJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
        ("PAN", "Synthetic tax identifier ABCDE1234F submitted in form."),
        ("PRIVATE_IPV4", "Database replica listening on 10.24.16.88 and 192.168.100.42."),
    ],
)
def test_positive_sensitive_data_categories(category_label: str, synthetic_prompt: str):
    """Verify the detector or pipeline flags representative synthetic sensitive inputs."""
    res = analyze_prompt_pipeline(synthetic_prompt, "PUBLIC_ASSISTANT")
    assert res["ok"] is True
    # Must either detect categories or enforce non-ALLOW / risk > 0 on sensitive inputs
    cats_upper = [c.upper() for c in res["categories"]]
    assert len(cats_upper) > 0 or res["decision"] in ("REDACT", "BLOCK")


def test_aadhaar_placeholder_handling():
    """Verify prompts referencing [Aadhaar Redacted] placeholders are handled without crashing."""
    prompt = "Customer submitted government ID placeholder: [Aadhaar Redacted] for KYC verification."
    res = analyze_prompt_pipeline(prompt, "PUBLIC_ASSISTANT")
    assert res["ok"] is True
    assert res["decision"] in ("ALLOW", "REDACT", "BLOCK")


# ---------------------------------------------------------------------------
# 2. Negative Matches & Benign Lookalikes
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "benign_prompt",
    [
        "Please summarize the key milestones for Q3 software release.",
        "Our public documentation server IP example is 8.8.8.8 and version is 1.2.3.4.",
        "Order quantity is 12345 units across 42 warehouses.",
        "Use function calculate_total(price, tax_rate) in Python.",
    ],
)
def test_negative_benign_prompts_do_not_false_positive_sensitive_categories(benign_prompt: str):
    """Benign text without credentials or PII should not trigger sensitive category matches."""
    res = analyze_prompt_pipeline(benign_prompt, "PUBLIC_ASSISTANT")
    assert res["ok"] is True
    assert res["categories"] == []
    assert res["decision"] == "ALLOW"


def test_luhn_checksum_validator_distinguishes_valid_and_invalid_cards():
    """Verify Luhn helper accurately separates valid synthetic test numbers from invalid ones."""
    assert is_luhn_valid("4532015112830366") is True
    assert is_luhn_valid("4532-0151-1283-0366") is True
    assert is_luhn_valid("4532015112830367") is False  # Altered check digit
    assert is_luhn_valid("0000000000000000") is False
    assert is_luhn_valid("12345") is False


# ---------------------------------------------------------------------------
# 3. Case Variations, Punctuation Boundaries & Multiple Findings
# ---------------------------------------------------------------------------
def test_case_variations_and_punctuation_boundaries():
    """Detector handles uppercase/lowercase emails and credentials wrapped in punctuation."""
    prompt = "Contact (ADMIN.USER@EXAMPLE.COM), [sec_user@sub.example.co.uk], or key='sk-proj-ABCDEF1234567890abcdef1234567890abcdef'."
    res = analyze_prompt_pipeline(prompt, "INTERNAL_ANALYST")
    assert res["ok"] is True
    assert len(res["categories"]) >= 1
    if res["decision"] == "REDACT":
        assert "ADMIN.USER@EXAMPLE.COM" not in res["sanitized_prompt"]
        assert "sec_user@sub.example.co.uk" not in res["sanitized_prompt"]
        assert "sk-proj-ABCDEF1234567890abcdef1234567890abcdef" not in res["sanitized_prompt"]


# ---------------------------------------------------------------------------
# 4. Redaction Span Accuracy, Overlapping Spans & Unicode Preservation
# ---------------------------------------------------------------------------
def test_redact_spans_exact_boundaries_and_surrounding_text_preservation():
    """Each redaction replaces only the target character span and preserves surrounding text."""
    original = "Hello Alice (alice@example.com), your host is 10.0.0.12!"
    email_start = original.index("alice@example.com")
    email_end = email_start + len("alice@example.com")
    ip_start = original.index("10.0.0.12")
    ip_end = ip_start + len("10.0.0.12")

    spans = [
        {"start": email_start, "end": email_end, "category": "EMAIL"},
        {"start": ip_start, "end": ip_end, "category": "PRIVATE_IP"},
    ]
    sanitized = redact_spans_safely(original, spans)
    assert sanitized == "Hello Alice ([REDACTED:EMAIL]), your host is [REDACTED:PRIVATE_IP]!"
    assert "alice@example.com" not in sanitized
    assert "10.0.0.12" not in sanitized


def test_overlapping_and_nested_spans_do_not_corrupt_text():
    """Overlapping detections merge cleanly without duplicating or corrupting surrounding text."""
    original = "Token: Bearer_sk-1234567890abcdef_end"
    spans = [
        {"start": 7, "end": 33, "category": "AUTH_HEADER"},
        {"start": 14, "end": 33, "category": "API_KEY"},
        {"start": 10, "end": 25, "category": "CREDENTIAL"},
    ]
    sanitized = redact_spans_safely(original, spans)
    assert sanitized == "Token: [REDACTED:AUTH_HEADER+CREDENTIAL+API_KEY]_end"
    assert "sk-1234567890abcdef" not in sanitized


def test_unicode_and_multibyte_preservation_during_redaction():
    """Unicode characters (accents, CJK, emojis) outside matched spans remain intact."""
    original = "こんにちは 🔒 Utilisateur: jean.dupont@example.fr — проверено ✅"
    start = original.index("jean.dupont@example.fr")
    end = start + len("jean.dupont@example.fr")
    sanitized = redact_spans_safely(original, [{"start": start, "end": end, "category": "EMAIL"}])
    assert sanitized == "こんにちは 🔒 Utilisateur: [REDACTED:EMAIL] — проверено ✅"
    assert "jean.dupont@example.fr" not in sanitized


def test_empty_and_boundary_length_inputs():
    """Empty inputs fail closed cleanly; max-length benign inputs succeed; oversized inputs fail closed."""
    max_len = get_max_prompt_length()

    empty_res = analyze_prompt_pipeline("", "PUBLIC_ASSISTANT")
    assert empty_res["ok"] is False
    assert empty_res["decision"] == "BLOCK"

    exact_limit_prompt = "A" * max_len
    valid_res = analyze_prompt_pipeline(exact_limit_prompt, "PUBLIC_ASSISTANT")
    assert valid_res["ok"] is True

    oversized_prompt = "A" * (max_len + 1)
    over_res = analyze_prompt_pipeline(oversized_prompt, "PUBLIC_ASSISTANT")
    assert over_res["ok"] is False
    assert over_res["decision"] == "BLOCK"
    assert "INPUT_LIMIT_EXCEEDED" in over_res["threat_indicators"]