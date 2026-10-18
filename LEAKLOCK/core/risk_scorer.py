"""
LEAKLOCK — Explainable Contextual Risk Scorer
Produces a transparent 0-100 risk score, structured contributing factors,
and hardware-compatible 2-bit risk encoding (`00` LOW, `01` MEDIUM, `10` HIGH, `11` CRITICAL).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

RISK_LEVEL_ORDER: Dict[str, int] = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}

HARDWARE_RISK_ENCODING: Dict[str, str] = {
    "LOW": "00",
    "MEDIUM": "01",
    "HIGH": "10",
    "CRITICAL": "11",
}

_BASE_SCORE_BY_LEVEL: Dict[str, int] = {
    "LOW": 0,
    "MEDIUM": 35,
    "HIGH": 65,
    "CRITICAL": 90,
}

_CONTEXTUAL_CO_OCCURRENCE_KEYWORDS: Tuple[str, ...] = (
    "production",
    "prod",
    "root",
    "admin",
    "master",
    "private",
    "payroll",
    "ssn",
    "confidential",
    "secret",
)


def calculate_contextual_risk(
    text: str,
    findings: List[Dict[str, Any]],
    threat_report: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Computes an explainable 0-100 risk score and overall risk classification.
    """
    factors: List[Dict[str, Any]] = []
    highest_finding_level = "LOW"

    for item in findings:
        lvl = item.get("risk_level", "MEDIUM")
        if RISK_LEVEL_ORDER.get(lvl, 0) > RISK_LEVEL_ORDER[highest_finding_level]:
            highest_finding_level = lvl

    score = _BASE_SCORE_BY_LEVEL[highest_finding_level]
    if findings:
        factors.append(
            {
                "factor": "Base Highest Finding Severity",
                "points": score,
                "detail": f"Highest detected sensitive category has severity {highest_finding_level}.",
            }
        )

    # Volume multiplier: additional findings increase exposure surface
    extra_findings = max(0, len(findings) - 1)
    if extra_findings > 0:
        volume_points = min(extra_findings * 4, 12)
        score += volume_points
        factors.append(
            {
                "factor": "Multiple Findings Volume",
                "points": volume_points,
                "detail": f"{extra_findings} additional sensitive item(s) detected (+4 pts each, max 12).",
            }
        )

    # Multi-category compounding bonus
    distinct_categories = {f["category"] for f in findings}
    if len(distinct_categories) >= 2:
        compound_points = min((len(distinct_categories) - 1) * 5, 10)
        score += compound_points
        factors.append(
            {
                "factor": "Cross-Category Compounding",
                "points": compound_points,
                "detail": (
                    f"{len(distinct_categories)} distinct categories combined "
                    f"({', '.join(sorted(distinct_categories))})."
                ),
            }
        )

    # High-sensitivity contextual keywords near findings
    lowered = text.lower() if isinstance(text, str) else ""
    matched_keywords = [
        kw for kw in _CONTEXTUAL_CO_OCCURRENCE_KEYWORDS if kw in lowered
    ]
    if findings and matched_keywords:
        context_points = min(len(matched_keywords) * 4, 12)
        score += context_points
        factors.append(
            {
                "factor": "Sensitive Context Keywords",
                "points": context_points,
                "detail": f"Prompt contains high-sensitivity context markers: {', '.join(matched_keywords[:4])}.",
            }
        )

    # Prompt Injection / Exfiltration Threat Boost
    has_threats = bool(threat_report and threat_report.get("has_threats"))
    threat_level = "LOW"
    if has_threats and threat_report is not None:
        threat_level = threat_report.get("threat_level", "LOW")
        threat_points = int(threat_report.get("threat_score_impact", 0))
        if threat_points > 0:
            score += threat_points
            threat_cats = list(threat_report.get("threat_counts", {}).keys())
            factors.append(
                {
                    "factor": "Prompt Injection / Exfiltration Signals",
                    "points": threat_points,
                    "detail": (
                        f"Detected adversarial/exfiltration patterns: "
                        f"{', '.join(threat_cats) if threat_cats else 'AI Contextual Flag'}."
                    ),
                }
            )

    score = max(0, min(score, 100))

    # Determine final_level:
    # Preserve Phase 2 deterministic category risk mapping (`highest_finding_level`)
    # unless an adversarial threat escalates it further.
    final_level = highest_finding_level
    if RISK_LEVEL_ORDER[threat_level] > RISK_LEVEL_ORDER[final_level]:
        final_level = threat_level

    # Cap numeric score at 84 when final_level is HIGH (no CRITICAL finding or threat)
    if final_level == "HIGH" and score >= 85 and not has_threats:
        score = 84

    if final_level == "CRITICAL" and score < 85:
        score = 85
    elif final_level == "HIGH" and score < 65:
        score = 65
    elif final_level == "MEDIUM" and score < 35:
        score = 35

    if not factors:
        explanation = "Score 0/100 (LOW): No sensitive data patterns or adversarial prompt threats detected."
    else:
        parts = [f"{item['factor']} (+{item['points']})" for item in factors]
        explanation = f"Score {score}/100 ({final_level}): Derived from " + "; ".join(parts) + "."

    return {
        "risk_score": score,
        "risk_level": final_level,
        "hardware_risk_code": HARDWARE_RISK_ENCODING[final_level],
        "factors": factors,
        "explanation": explanation,
    }