"""
LEAKLOCK — Policy Engine & Role-Based Agent Authorization
Evaluates detection results + prompt threat telemetry against the caller's
agent role clearance to produce a deterministic policy decision:
`ALLOW`, `REDACT`, or `BLOCK`.
"""

from __future__ import annotations

from typing import Any, Dict, List, Set

from core.risk_scorer import RISK_LEVEL_ORDER

AGENT_ROLES: Dict[str, Dict[str, Any]] = {
    "PUBLIC_ASSISTANT": {
        "label": "Public Assistant (Untrusted External LLM)",
        "max_allowed_risk": "LOW",
        "redactable_categories": {"EMAIL", "PHONE", "IPV4_ADDRESS"},
        "blocked_categories": {
            "API_KEY",
            "CREDIT_CARD",
            "PRIVATE_KEY_HEADER",
            "JWT_TOKEN",
            "AADHAAR_ID",
            "PAN_ID",
            "EMPLOYEE_ID",
            "CUSTOMER_ID",
            "CONFIDENTIAL_IDENTIFIER",
        },
        "description": "Strict external boundary. Blocks credentials/enterprise IDs; redacts basic contact PII.",
    },
    "INTERNAL_ANALYST": {
        "label": "Internal Enterprise Analyst Agent",
        "max_allowed_risk": "MEDIUM",
        "redactable_categories": {
            "EMAIL",
            "PHONE",
            "IPV4_ADDRESS",
            "EMPLOYEE_ID",
            "CUSTOMER_ID",
            "AADHAAR_ID",
            "PAN_ID",
            "API_KEY",
        },
        "blocked_categories": {
            "CREDIT_CARD",
            "PRIVATE_KEY_HEADER",
            "JWT_TOKEN",
            "CONFIDENTIAL_IDENTIFIER",
        },
        "description": "Internal workspace assistant. Redacts PII, API tokens, and internal IDs; blocks raw private keys, cards, and confidential projects.",
    },
    "PRIVILEGED_DEBUGGER": {
        "label": "Privileged SecOps / Debugger Agent",
        "max_allowed_risk": "HIGH",
        "redactable_categories": {
            "EMAIL",
            "PHONE",
            "IPV4_ADDRESS",
            "EMPLOYEE_ID",
            "CUSTOMER_ID",
            "AADHAAR_ID",
            "PAN_ID",
            "API_KEY",
            "JWT_TOKEN",
            "CONFIDENTIAL_IDENTIFIER",
        },
        "blocked_categories": {
            "CREDIT_CARD",
            "PRIVATE_KEY_HEADER",
        },
        "description": "Authorized SecOps agent. Redacts tokens/keys for safe diagnostics; blocks raw private keys & payment cards.",
    },
    "AUTOMATED_PIPELINE": {
        "label": "Zero-Trust Automated Batch Pipeline",
        "max_allowed_risk": "LOW",
        "redactable_categories": set(),
        "blocked_categories": {
            "EMAIL",
            "PHONE",
            "IPV4_ADDRESS",
            "EMPLOYEE_ID",
            "CUSTOMER_ID",
            "AADHAAR_ID",
            "PAN_ID",
            "API_KEY",
            "JWT_TOKEN",
            "CREDIT_CARD",
            "PRIVATE_KEY_HEADER",
            "CONFIDENTIAL_IDENTIFIER",
        },
        "description": "Unattended CI/CD or batch ingestion pipeline. Fails closed (BLOCK) on any sensitive finding.",
    },
}


def redact_prompt(text: str, findings: List[Dict[str, Any]]) -> str:
    """
    Replaces every finding's `[start:end]` span with `<REDACTED:CATEGORY>`.
    """
    if not isinstance(text, str) or not findings:
        return text

    ordered = sorted(findings, key=lambda f: (f["start"], f["end"]))
    chunks: List[str] = []
    cursor = 0
    for item in ordered:
        start, end = item["start"], item["end"]
        if start < cursor:
            continue
        chunks.append(text[cursor:start])
        chunks.append(f"[REDACTED_{item['category']}]")
        cursor = end
    chunks.append(text[cursor:])
    return "".join(chunks)


def evaluate_policy(
    prompt_text: str,
    scan_result: Dict[str, Any],
    agent_role: str = "PUBLIC_ASSISTANT",
) -> Dict[str, Any]:
    """
    Determines whether the prompt is ALLOWED, REDACTED, or BLOCKED for `agent_role`.

    Returns
    -------
    Dict[str, Any]
        - `action`: "ALLOW" | "REDACT" | "BLOCK"
        - `authorized`: bool (True if ALLOW or REDACT, False if BLOCK)
        - `agent_role`: str
        - `role_label`: str
        - `reasons`: List[str]
        - `sanitized_prompt`: str (Redacted prompt text, or empty if blocked)
        - `blocked_categories_triggered`: List[str]
        - `redacted_categories_triggered`: List[str]
        - `hardware_policy_signal`: str ("00"=ALLOW, "01"=REDACT, "10"=BLOCK)
    """
    normalized_role = str(agent_role).upper().strip()
    if normalized_role not in AGENT_ROLES:
        raise ValueError(
            f"Unknown agent_role '{agent_role}'. Valid roles: {list(AGENT_ROLES.keys())}."
        )

    role_spec = AGENT_ROLES[normalized_role]
    findings: List[Dict[str, Any]] = scan_result.get("findings", [])
    has_threats: bool = bool(scan_result.get("has_threats", False))
    threats: List[Dict[str, Any]] = scan_result.get("threats", [])

    reasons: List[str] = []
    blocked_cats_hit: Set[str] = set()
    redacted_cats_hit: Set[str] = set()

    # 1. Any prompt injection / exfiltration threat immediately triggers BLOCK
    if has_threats:
        threat_names = sorted({t["category"] for t in threats})
        if threat_names:
            reasons.append(
                f"Adversarial prompt threat detected ({', '.join(threat_names)}). Zero-tolerance block enforced."
            )
        else:
            reasons.append(
                "Hybrid AI contextual analysis flagged high-risk exfiltration/coercive intent."
            )

    # 2. Check findings against role's blocked & redactable sets
    for item in findings:
        cat = item["category"]
        if cat in role_spec["blocked_categories"]:
            blocked_cats_hit.add(cat)
        elif cat in role_spec["redactable_categories"]:
            redacted_cats_hit.add(cat)
        else:
            blocked_cats_hit.add(cat)

    if blocked_cats_hit:
        reasons.append(
            f"Role '{normalized_role}' is not authorized to transmit categories: "
            f"{', '.join(sorted(blocked_cats_hit))}."
        )

    if has_threats or blocked_cats_hit:
        action = "BLOCK"
        authorized = False
        sanitized = "[BLOCKED BY LEAKLOCK POLICY ENGINE — TRANSMISSION PROHIBITED]"
        hw_signal = "10"
    elif redacted_cats_hit:
        action = "REDACT"
        authorized = True
        sanitized = redact_prompt(prompt_text, findings)
        reasons.append(
            f"Role '{normalized_role}' requires automatic redaction for categories: "
            f"{', '.join(sorted(redacted_cats_hit))}."
        )
        hw_signal = "01"
    else:
        action = "ALLOW"
        authorized = True
        sanitized = prompt_text
        reasons.append(
            f"No policy violations detected for role '{normalized_role}' "
            f"(clearance up to {role_spec['max_allowed_risk']})."
        )
        hw_signal = "00"

    return {
        "action": action,
        "authorized": authorized,
        "agent_role": normalized_role,
        "role_label": role_spec["label"],
        "reasons": reasons,
        "sanitized_prompt": sanitized,
        "blocked_categories_triggered": sorted(blocked_cats_hit),
        "redacted_categories_triggered": sorted(redacted_cats_hit),
        "hardware_policy_signal": hw_signal,
    }