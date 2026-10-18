"""
LEAKLOCK Core Package
Phase 2 + Phase 2 Enhancements
"""

__version__ = "0.2.0"

from core.audit_logger import AuditLogger, get_audit_logger
from core.detector import (
    DEFAULT_CATEGORY_RISK_MAP,
    RISK_LEVEL_ORDER,
    detect_sensitive_data,
)
from core.policy_engine import (
    AGENT_ROLES,
    evaluate_policy,
    redact_prompt,
)
from core.risk_scorer import calculate_contextual_risk
from core.threat_detector import detect_prompt_threats

__all__ = [
    "__version__",
    "AGENT_ROLES",
    "AuditLogger",
    "DEFAULT_CATEGORY_RISK_MAP",
    "RISK_LEVEL_ORDER",
    "calculate_contextual_risk",
    "detect_prompt_threats",
    "detect_sensitive_data",
    "evaluate_policy",
    "get_audit_logger",
    "redact_prompt",
]