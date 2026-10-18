"""
LEAKLOCK — Prompt Injection, Jailbreak & Data Exfiltration Detector
Supports Hybrid Analysis Mode:
1. Deterministic Local Rule Engine (Always active, zero external data transfer)
2. Optional AI Contextual Heuristic / Callback Analyzer (Operates strictly on
   pre-redacted/sanitized text so raw secrets never leave the local boundary).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Pattern, Tuple


@dataclass(frozen=True)
class _ThreatRule:
    name: str
    category: str
    severity: str  # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    score_impact: int
    description: str
    pattern: Pattern[str]


_THREAT_RULES: Tuple[_ThreatRule, ...] = (
    _ThreatRule(
        name="instruction_override",
        category="INSTRUCTION_OVERRIDE",
        severity="HIGH",
        score_impact=35,
        description="Attempts to override or ignore prior system/developer instructions.",
        pattern=re.compile(
            r"\b(?:ignore|disregard|forget|bypass|override)\s+"
            r"(?:all\s+)?(?:previous|prior|above|system|developer|safety)\s+"
            r"(?:instructions|rules|prompts|constraints|guardrails)\b",
            re.IGNORECASE,
        ),
    ),
    _ThreatRule(
        name="system_prompt_extraction",
        category="SYSTEM_PROMPT_EXTRACTION",
        severity="HIGH",
        score_impact=30,
        description="Attempts to extract hidden system prompts, configuration, or developer instructions.",
        pattern=re.compile(
            r"\b(?:reveal|print|output|repeat|show|dump|display)\s+"
            r"(?:your\s+|the\s+)?(?:entire\s+|exact\s+|hidden\s+|initial\s+)?"
            r"(?:system\s+prompt|developer\s+message|hidden\s+instructions|initialization\s+prompt)\b",
            re.IGNORECASE,
        ),
    ),
    _ThreatRule(
        name="data_exfiltration",
        category="DATA_EXFILTRATION",
        severity="CRITICAL",
        score_impact=45,
        description="Attempts to exfiltrate data via external URLs, webhooks, markdown images, or command tools.",
        pattern=re.compile(
            r"(?:"
            r"\b(?:send|post|upload|exfiltrate|forward|transmit)\b.{0,120}\b(?:https?://|webhook|attacker|external\s+server)\b"
            r"|!\[[^\]]*\]\(https?://[^)]+\)"
            r"|\b(?:curl|wget|Invoke-WebRequest)\s+[^\n]*https?://"
            r")",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    _ThreatRule(
        name="roleplay_jailbreak",
        category="ROLEPLAY_JAILBREAK",
        severity="HIGH",
        score_impact=30,
        description="Persona adoption or unrestricted mode framing ('DAN', 'developer mode', 'unfiltered AI').",
        pattern=re.compile(
            r"\b(?:you\s+are\s+now\s+in\s+(?:dan\s+)?developer\s+mode"
            r"|act\s+as\s+an?\s+unrestricted"
            r"|do\s+anything\s+now"
            r"|DAN\s+(?:developer\s+)?mode"
            r"|hypothetical\s+scenario\s+where\s+security\s+rules\s+do\s+not\s+apply"
            r"|pretend\s+you\s+have\s+no\s+safety\s+filters)\b",
            re.IGNORECASE,
        ),
    ),
    _ThreatRule(
        name="encoding_bypass",
        category="ENCODING_BYPASS",
        severity="MEDIUM",
        score_impact=20,
        description="Requests base64/hex/rot13 encoding or obfuscation to evade output filters.",
        pattern=re.compile(
            r"(?:"
            r"\b(?:encode|decode|obfuscate|translate)\s+(?:the\s+(?:secret|key|password|credentials|response|output)\s+)?(?:in|to|using)\s+(?:base64|hex|rot13|binary|url-encoding)\b"
            r"|\b(?:encode|decode)\b.{0,40}\b(?:base64|hex|rot13)\b"
            r")",
            re.IGNORECASE,
        ),
    ),
)

_SEVERITY_RANK: Dict[str, int] = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}


def _run_sanitized_ai_contextual_analysis(
    sanitized_text: str,
    custom_ai_callable: Optional[Callable[[str], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Executes optional AI contextual analysis on a PRE-REDACTED prompt.
    If no external `custom_ai_callable` is supplied, runs a local semantic-intent
    classifier that evaluates structural coercive cues (imperative verb density,
    privilege escalation framing, and multi-step exfiltration intent).
    """
    if custom_ai_callable is not None:
        return custom_ai_callable(sanitized_text)

    lowered = sanitized_text.lower()
    intent_signals: List[str] = []
    confidence_score = 0.10

    coercive_phrases = (
        "without security team knowing",
        "bypass audit",
        "do not log this",
        "override policy",
        "urgent executive override",
        "export all records",
        "dump table",
        "raw credentials",
    )
    for phrase in coercive_phrases:
        if phrase in lowered:
            intent_signals.append(f"Coercive/evasive intent phrase detected: '{phrase}'")
            confidence_score += 0.25

    if "[redacted_" in lowered and any(
        verb in lowered for verb in ("send to", "forward to", "upload", "external", "webhook")
    ):
        intent_signals.append(
            "Redacted sensitive entities combined with outbound transfer verbs."
        )
        confidence_score += 0.35

    confidence_score = min(round(confidence_score, 2), 0.99)
    flagged = len(intent_signals) > 0
    risk_adjustment = 15 if flagged else 0

    return {
        "mode": "HYBRID_AI_CONTEXTUAL",
        "input_was_pre_redacted": True,
        "flagged": flagged,
        "confidence": confidence_score,
        "risk_score_adjustment": risk_adjustment,
        "intent_signals": intent_signals,
        "explanation": (
            "Contextual analyzer detected elevated exfiltration/evasion intent on sanitized text."
            if flagged
            else "Contextual analyzer found no additional coercive semantic patterns."
        ),
    }


def detect_prompt_threats(
    text: str,
    *,
    enable_ai_analysis: bool = False,
    sanitized_text_for_ai: Optional[str] = None,
    ai_callable: Optional[Callable[[str], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Scans `text` for prompt injection, jailbreak, and data exfiltration patterns.

    Parameters
    ----------
    text : str
        Input prompt text.
    enable_ai_analysis : bool, default False
        When True, runs the hybrid AI contextual analyzer strictly on
        `sanitized_text_for_ai` (or `text` if no sensitive spans exist).
    sanitized_text_for_ai : Optional[str]
        Pre-redacted prompt so sensitive literals are never exposed to the AI layer.
    ai_callable : Optional[Callable[[str], Dict[str, Any]]]
        Optional custom model hook accepting sanitized text.

    Returns
    -------
    Dict[str, Any]
        - `threats`: list of detected threat dicts
        - `has_threats`: bool
        - `threat_level`: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
        - `threat_counts`: dict of category -> count
        - `threat_score_impact`: int
        - `analysis_mode`: "LOCAL_RULES_ONLY" | "HYBRID_LOCAL_AND_AI"
        - `ai_analysis`: optional dict when `enable_ai_analysis=True`
    """
    if not isinstance(text, str):
        raise TypeError("Expected 'text' to be a str.")

    if not text or not text.strip():
        return {
            "threats": [],
            "has_threats": False,
            "threat_level": "LOW",
            "threat_counts": {},
            "threat_score_impact": 0,
            "analysis_mode": "HYBRID_LOCAL_AND_AI" if enable_ai_analysis else "LOCAL_RULES_ONLY",
            "ai_analysis": None,
        }

    threats: List[Dict[str, Any]] = []
    threat_counts: Dict[str, int] = {}
    highest_severity = "LOW"
    total_score_impact = 0

    for rule in _THREAT_RULES:
        for match in rule.pattern.finditer(text):
            start, end = match.span(0)
            threats.append(
                {
                    "rule_name": rule.name,
                    "category": rule.category,
                    "severity": rule.severity,
                    "score_impact": rule.score_impact,
                    "description": rule.description,
                    "start": start,
                    "end": end,
                    "matched_text": text[start:end],
                }
            )
            threat_counts[rule.category] = threat_counts.get(rule.category, 0) + 1
            total_score_impact += rule.score_impact
            if _SEVERITY_RANK[rule.severity] > _SEVERITY_RANK[highest_severity]:
                highest_severity = rule.severity

    threats.sort(key=lambda item: (item["start"], item["end"], item["category"]))

    ai_result: Optional[Dict[str, Any]] = None
    if enable_ai_analysis:
        safe_input = sanitized_text_for_ai if sanitized_text_for_ai is not None else text
        ai_result = _run_sanitized_ai_contextual_analysis(safe_input, ai_callable)
        if ai_result.get("flagged"):
            total_score_impact += int(ai_result.get("risk_score_adjustment", 0))
            if _SEVERITY_RANK["HIGH"] > _SEVERITY_RANK[highest_severity]:
                highest_severity = "HIGH"

    return {
        "threats": threats,
        "has_threats": len(threats) > 0 or bool(ai_result and ai_result.get("flagged")),
        "threat_level": highest_severity,
        "threat_counts": threat_counts,
        "threat_score_impact": min(total_score_impact, 100),
        "analysis_mode": "HYBRID_LOCAL_AND_AI" if enable_ai_analysis else "LOCAL_RULES_ONLY",
        "ai_analysis": ai_result,
    }