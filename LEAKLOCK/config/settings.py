# Centralized configuration settings for LEAKLOCK.
# Uses Python standard library only to remain lightweight and portable.

from __future__ import annotations

import os

APP_NAME: str = 'LEAKLOCK'
APP_SUBTITLE: str = 'AI Data Protection Gateway'
APP_THEME: str = 'IBM Z Datathon 2026 — AI Secured: Innovation Without Exposure'
APP_VERSION: str = '0.2.0-phase2'
CURRENT_PHASE: str = os.getenv(
    'LEAKLOCK_PHASE', 'Phase 2 Enhanced: Detection, Policy & Audit'
)

# Architectural Feature Flags
SCANNER_ENABLED: bool = True
POLICY_ENGINE_ENABLED: bool = True
HARDWARE_CONTROLLER_ENABLED: bool = False
AUDIT_LOGGING_ENABLED: bool = True


# Decision Backend Mode ('software_fallback' or 'verilog_controller')
DECISION_BACKEND: str = os.getenv('LEAKLOCK_DECISION_BACKEND', 'software_fallback')

# Input limits
MAX_PROMPT_LENGTH: int = int(os.getenv('LEAKLOCK_MAX_PROMPT_LENGTH', '10000'))

# Planned Policies for Phase 2 & Phase 3
PLANNED_POLICIES: dict[str, dict[str, str]] = {
    'ALLOW': {
        'code': "2'b00",
        'summary': 'Safe to transmit.',
        'description': (
            'The prompt contains no detected sensitive entities. '
            'It passes unmodified to the downstream AI model.'
        ),
    },
    'REDACT': {
        'code': "2'b01",
        'summary': 'Mask sensitive tokens before transmission.',
        'description': (
            'Sensitive entities (such as emails, phone numbers, or IDs) are '
            'replaced with safe placeholders (e.g., [REDACTED_EMAIL]) before '
            'the prompt leaves the gateway.'
        ),
    },
    'BLOCK': {
        'code': "2'b10",
        'summary': 'Halt transmission immediately.',
        'description': (
            'High-severity secrets (such as private keys, API tokens, or '
            'regulated financial/health records) trigger an immediate block. '
            'The prompt never leaves the gateway.'
        ),
    },
}
