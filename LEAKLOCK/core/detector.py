"""
LEAKLOCK — Phase 2 (Enhanced): Sensitive Data & Threat Detection Engine
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional, Pattern, Tuple

from core.risk_scorer import RISK_LEVEL_ORDER, calculate_contextual_risk
from core.threat_detector import detect_prompt_threats

DEFAULT_CATEGORY_RISK_MAP: Dict[str, str] = {
    "EMAIL": "MEDIUM",
    "PHONE": "MEDIUM",
    "API_KEY": "HIGH",
    "EMPLOYEE_ID": "HIGH",
    "CUSTOMER_ID": "HIGH",
    "CONFIDENTIAL_IDENTIFIER": "HIGH",
    "CREDIT_CARD": "CRITICAL",
    "PRIVATE_KEY_HEADER": "CRITICAL",
    "JWT_TOKEN": "HIGH",
    "AADHAAR_ID": "HIGH",
    "PAN_ID": "HIGH",
    "IPV4_ADDRESS": "MEDIUM",
}


@dataclass(frozen=True)
class _DetectionRule:
    """Internal definition for a regex detection pattern."""

    name: str
    category: str
    pattern: Pattern[str]
    priority: int
    target_group: int = 0


_RULES: Tuple[_DetectionRule, ...] = (
    _DetectionRule(
        name="private_key_header",
        category="PRIVATE_KEY_HEADER",
        pattern=re.compile(
            r"-----BEGIN\s+(?:RSA\s+|OPENSSH\s+|EC\s+|DSA\s+|ENCRYPTED\s+)?PRIVATE\s+KEY-----"
        ),
        priority=110,
    ),
    _DetectionRule(
        name="jwt_token",
        category="JWT_TOKEN",
        pattern=re.compile(
            r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"
        ),
        priority=105,
    ),
    _DetectionRule(
        name="api_key_assignment",
        category="API_KEY",
        pattern=re.compile(
            r"\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key|token)"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{8,64})['\"]?",
            re.IGNORECASE,
        ),
        priority=100,
    ),
    _DetectionRule(
        name="api_key_prefixed",
        category="API_KEY",
        pattern=re.compile(
            r"\b(?:sk-(?:demo|live|test|proj)-[A-Za-z0-9_\-]{8,64}"
            r"|pk-(?:demo|live|test)-[A-Za-z0-9_\-]{8,64}"
            r"|gh[pousr]_[A-Za-z0-9]{12,64}"
            r"|AIza[0-9A-Za-z_\-]{20,40}"
            r"|AKIA[0-9A-Z]{16})\b"
        ),
        priority=95,
    ),
    _DetectionRule(
        name="credit_card",
        category="CREDIT_CARD",
        pattern=re.compile(r"(?<!\w)(?:\d{4}[\s\-]?){3}\d{4}(?!\w)"),
        priority=92,
    ),
    _DetectionRule(
        name="pan_id",
        category="PAN_ID",
        pattern=re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
        priority=91,
    ),
    _DetectionRule(
        name="aadhaar_id",
        category="AADHAAR_ID",
        pattern=re.compile(r"(?<!\w)[2-9]\d{3}[\s\-]\d{4}[\s\-]\d{4}(?!\w)"),
        priority=88,
    ),
    _DetectionRule(
        name="employee_id",
        category="EMPLOYEE_ID",
        pattern=re.compile(r"\bEMP-\d{4,8}\b"),
        priority=90,
    ),
    _DetectionRule(
        name="customer_id",
        category="CUSTOMER_ID",
        pattern=re.compile(r"\bCUST-\d{4,8}\b"),
        priority=90,
    ),
    _DetectionRule(
        name="confidential_identifier",
        category="CONFIDENTIAL_IDENTIFIER",
        pattern=re.compile(
            r"\b(?:PROJECT-[A-Z0-9]+(?:-[A-Z0-9]+)*-(?:CONFIDENTIAL|SECRET|RESTRICTED)"
            r"|CONFIDENTIAL-[A-Z0-9]+(?:-[A-Z0-9]+)+"
            r"|(?:PROJ|PROJECT|PRJ)-(?:SECRET|INTERNAL|CONFIDENTIAL|RESTRICTED)-[A-Z0-9]+)\b"
        ),
        priority=85,
    ),
    _DetectionRule(
        name="email_address",
        category="EMAIL",
        pattern=re.compile(
            r"(?<![A-Za-z0-9._%+\-])"
            r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,24}"
            r"(?![A-Za-z0-9_%+\-])"
        ),
        priority=80,
    ),
    _DetectionRule(
        name="ipv4_private",
        category="IPV4_ADDRESS",
        pattern=re.compile(
            r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b"
        ),
        priority=75,
    ),
    _DetectionRule(
        name="phone_indian",
        category="PHONE",
        pattern=re.compile(
            r"(?<!\w)"
            r"(?:(?:\+91[\s\-]?|0)?[6-9]\d{4}[\s\-]?\d{5})"
            r"(?!\w)"
        ),
        priority=70,
    ),
    _DetectionRule(
        name="phone_international",
        category="PHONE",
        pattern=re.compile(
            r"(?<!\w)"
            r"(?:"
            r"\+\d{1,3}[\s.\-]?\(?\d{2,4}\)?[\s.\-]?\d{3,4}[\s.\-]?\d{3,4}"
            r"|\(\d{3}\)[\s.\-]?\d{3}[\s.\-]\d{4}"
            r"|\b\d{3}-\d{3}-\d{4}\b"
            r")"
            r"(?!\w)"
        ),
        priority=65,
    ),
)


def _passes_luhn(card_text: str) -> bool:
    """Validates a 13-to-19 digit payment card candidate using the Luhn checksum."""
    digits = [int(ch) for ch in card_text if ch.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    if len(set(digits)) == 1:
        return False

    checksum = 0
    parity = len(digits) % 2
    for idx, digit in enumerate(digits):
        if idx % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _is_valid_ipv4(ip_text: str) -> bool:
    """Ensures every octet in an IPv4 match is between 0 and 255."""
    parts = ip_text.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or not (0 <= int(part) <= 255):
            return False
    return True


def _is_valid_phone_candidate(matched_text: str) -> bool:
    """Secondary validation for phone numbers to filter out arbitrary digit runs."""
    digits = [ch for ch in matched_text if ch.isdigit()]
    num_digits = len(digits)
    if num_digits < 10 or num_digits > 15:
        return False
    if matched_text.isdigit() and num_digits == 10:
        return matched_text[0] in {"6", "7", "8", "9"}
    return True


def _resolve_overlaps(raw_candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicates overlapping regex matches deterministically."""
    if not raw_candidates:
        return []

    sorted_candidates = sorted(
        raw_candidates,
        key=lambda item: (
            item["start"],
            -(item["end"] - item["start"]),
            -item["_priority"],
            item["category"],
        ),
    )

    accepted: List[Dict[str, Any]] = []
    for candidate in sorted_candidates:
        if not accepted:
            accepted.append(candidate)
            continue
        last = accepted[-1]
        if candidate["start"] >= last["end"]:
            accepted.append(candidate)

    cleaned: List[Dict[str, Any]] = [
        {
            "category": item["category"],
            "start": item["start"],
            "end": item["end"],
            "risk_level": item["risk_level"],
            "matched_text": item["matched_text"],
        }
        for item in accepted
    ]
    cleaned.sort(key=lambda f: (f["start"], f["end"], f["category"]))
    return cleaned


def _validate_risk_map(
    custom_map: Optional[Mapping[str, str]],
) -> Dict[str, str]:
    """Merges and validates the active category-to-risk mapping."""
    effective_map = dict(DEFAULT_CATEGORY_RISK_MAP)
    if custom_map is not None:
        if not isinstance(custom_map, Mapping):
            raise TypeError("risk_map must be a mapping of category -> risk_level.")
        for category, level in custom_map.items():
            normalized_level = str(level).upper().strip()
            if normalized_level not in RISK_LEVEL_ORDER:
                raise ValueError(
                    f"Unsupported risk level '{level}' for category '{category}'. "
                    f"Expected one of {list(RISK_LEVEL_ORDER.keys())}."
                )
            effective_map[str(category).upper().strip()] = normalized_level
    return effective_map


def _mask_spans_for_ai(text: str, findings: List[Dict[str, Any]]) -> str:
    """Replaces detected sensitive spans with `[REDACTED_<CATEGORY>]` before AI analysis."""
    if not findings:
        return text
    pieces: List[str] = []
    cursor = 0
    for item in findings:
        start, end = item["start"], item["end"]
        pieces.append(text[cursor:start])
        pieces.append(f"[REDACTED_{item['category']}]")
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def _build_summary(
    findings: List[Dict[str, Any]],
    overall_risk: str,
    category_counts: Dict[str, int],
    threat_report: Dict[str, Any],
) -> str:
    """Builds a concise human-readable summary without exposing raw secret values."""
    has_threats = bool(threat_report.get("has_threats"))
    if not findings and not has_threats:
        return (
            "No supported sensitive-data patterns were detected. "
            "Note: This scan checks explicit regex patterns only and does not "
            "guarantee the absence of all confidential information."
        )

    parts: List[str] = []
    if findings:
        total = len(findings)
        noun = "finding" if total == 1 else "findings"
        breakdown = ", ".join(
            f"{cat} ({count})" for cat, count in sorted(category_counts.items())
        )
        parts.append(f"Detected {total} sensitive-data {noun} across [{breakdown}].")

    if has_threats:
        t_counts = threat_report.get("threat_counts", {})
        if t_counts:
            t_breakdown = ", ".join(
                f"{cat} ({cnt})" for cat, cnt in sorted(t_counts.items())
            )
            parts.append(f"Detected adversarial/exfiltration signals [{t_breakdown}].")
        elif threat_report.get("ai_analysis", {}).get("flagged"):
            parts.append("Hybrid AI contextual analysis flagged coercive/exfiltration intent.")

    parts.append(f"Overall prompt risk classified as {overall_risk}.")
    return " ".join(parts)


def detect_sensitive_data(
    text: str,
    risk_map: Optional[Mapping[str, str]] = None,
    *,
    enable_ai_analysis: bool = False,
    ai_callable: Optional[Callable[[str], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Scans `text` for sensitive-data categories, prompt injection/exfiltration threats,
    and computes an explainable contextual risk score.
    """
    if not isinstance(text, str):
        raise TypeError(
            f"Expected 'text' to be of type 'str', but received '{type(text).__name__}'."
        )

    effective_risk_map = _validate_risk_map(risk_map)

    if not text or not text.strip():
        empty_threat = detect_prompt_threats("", enable_ai_analysis=enable_ai_analysis)
        empty_risk = calculate_contextual_risk("", [], empty_threat)
        return {
            "findings": [],
            "risk_level": "LOW",
            "has_sensitive_data": False,
            "summary": _build_summary([], "LOW", {}, empty_threat),
            "category_counts": {},
            "risk_score": empty_risk["risk_score"],
            "hardware_risk_code": empty_risk["hardware_risk_code"],
            "risk_breakdown": {
                "factors": empty_risk["factors"],
                "explanation": empty_risk["explanation"],
            },
            "threats": [],
            "has_threats": False,
            "threat_level": "LOW",
            "threat_counts": {},
            "analysis_mode": empty_threat["analysis_mode"],
            "ai_analysis": None,
        }

    raw_candidates: List[Dict[str, Any]] = []

    for rule in _RULES:
        for match in rule.pattern.finditer(text):
            start, end = match.span(rule.target_group)
            matched_text = text[start:end]

            if rule.category == "PHONE" and not _is_valid_phone_candidate(matched_text):
                continue
            if rule.category == "CREDIT_CARD" and not _passes_luhn(matched_text):
                continue
            if rule.category == "IPV4_ADDRESS" and not _is_valid_ipv4(matched_text):
                continue

            category_risk = effective_risk_map.get(rule.category, "MEDIUM")
            raw_candidates.append(
                {
                    "category": rule.category,
                    "start": start,
                    "end": end,
                    "risk_level": category_risk,
                    "matched_text": matched_text,
                    "_priority": rule.priority,
                }
            )

    findings = _resolve_overlaps(raw_candidates)

    category_counts: Dict[str, int] = {}
    for item in findings:
        cat = item["category"]
        category_counts[cat] = category_counts.get(cat, 0) + 1

    sanitized_for_ai = _mask_spans_for_ai(text, findings)
    threat_report = detect_prompt_threats(
        text,
        enable_ai_analysis=enable_ai_analysis,
        sanitized_text_for_ai=sanitized_for_ai,
        ai_callable=ai_callable,
    )

    risk_eval = calculate_contextual_risk(text, findings, threat_report)
    overall_risk = risk_eval["risk_level"]
    has_sensitive = len(findings) > 0
    summary = _build_summary(findings, overall_risk, category_counts, threat_report)

    return {
        "findings": findings,
        "risk_level": overall_risk,
        "has_sensitive_data": has_sensitive,
        "summary": summary,
        "category_counts": category_counts,
        "risk_score": risk_eval["risk_score"],
        "hardware_risk_code": risk_eval["hardware_risk_code"],
        "risk_breakdown": {
            "factors": risk_eval["factors"],
            "explanation": risk_eval["explanation"],
        },
        "threats": threat_report["threats"],
        "has_threats": threat_report["has_threats"],
        "threat_level": threat_report["threat_level"],
        "threat_counts": threat_report["threat_counts"],
        "analysis_mode": threat_report["analysis_mode"],
        "ai_analysis": threat_report["ai_analysis"],
    }