"""
LEAKLOCK — Privacy-Conscious Audit Logger
Records immutable security telemetry in memory (and optional sanitized JSONL)
WITHOUT ever storing raw prompts or matched sensitive substrings.
Only a non-reversible SHA-256 prompt fingerprint, category counts, threat types,
risk scores, and policy decisions are retained.
"""

from __future__ import annotations

import hashlib
import json
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional
import uuid


class AuditLogger:
    """
    Privacy-preserving audit logger that guarantees zero storage of raw prompts
    or matched secret substrings.
    """

    def __init__(self, max_entries: int = 200) -> None:
        self._max_entries = max_entries
        self._records: Deque[Dict[str, Any]] = deque(maxlen=max_entries)

    @staticmethod
    def hash_prompt(prompt_text: str) -> str:
        """Returns a deterministic SHA-256 hex digest of the prompt."""
        normalized = (prompt_text or "").encode("utf-8", errors="replace")
        return hashlib.sha256(normalized).hexdigest()

    def log_scan_event(
        self,
        prompt_text: str,
        scan_result: Dict[str, Any],
        policy_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Records a sanitized audit event.
        Explicitly strips `matched_text` and raw `prompt_text`.
        """
        event_id = f"AUD-{uuid.uuid4().hex[:10].upper()}"
        timestamp = datetime.now(timezone.utc).isoformat()
        prompt_sha256 = self.hash_prompt(prompt_text)

        # Extract strictly metadata—never `matched_text`
        sanitized_findings_meta = [
            {
                "category": f["category"],
                "risk_level": f["risk_level"],
                "span_length": f["end"] - f["start"],
            }
            for f in scan_result.get("findings", [])
        ]

        record: Dict[str, Any] = {
            "event_id": event_id,
            "timestamp_utc": timestamp,
            "prompt_sha256": prompt_sha256,
            "prompt_length": len(prompt_text) if isinstance(prompt_text, str) else 0,
            "agent_role": (
                policy_result.get("agent_role", "UNSPECIFIED")
                if policy_result
                else "UNSPECIFIED"
            ),
            "policy_action": (
                policy_result.get("action", "SCAN_ONLY")
                if policy_result
                else "SCAN_ONLY"
            ),
            "authorized": (
                bool(policy_result.get("authorized", True))
                if policy_result
                else True
            ),
            "risk_level": scan_result.get("risk_level", "LOW"),
            "risk_score": int(scan_result.get("risk_score", 0)),
            "hardware_risk_code": scan_result.get("hardware_risk_code", "00"),
            "has_sensitive_data": bool(scan_result.get("has_sensitive_data", False)),
            "finding_count": len(sanitized_findings_meta),
            "category_counts": dict(scan_result.get("category_counts", {})),
            "findings_metadata": sanitized_findings_meta,
            "has_threats": bool(scan_result.get("has_threats", False)),
            "threat_counts": dict(scan_result.get("threat_counts", {})),
            "analysis_mode": scan_result.get("analysis_mode", "LOCAL_RULES_ONLY"),
        }

        self._records.appendleft(record)
        return record

    def get_records(self) -> List[Dict[str, Any]]:
        """Returns all audit records in reverse-chronological order."""
        return list(self._records)

    def clear(self) -> None:
        """Clears the in-memory audit log."""
        self._records.clear()

    def export_jsonl(self, target_path: Optional[Path] = None) -> str:
        """
        Serializes sanitized audit records to JSON Lines format.
        If `target_path` is provided, writes the sanitized JSONL to disk.
        """
        lines = [json.dumps(rec, sort_keys=True) for rec in self._records]
        payload = "\n".join(lines)
        if target_path is not None:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_text(payload + ("\n" if payload else ""), encoding="utf-8")
        return payload


_GLOBAL_AUDIT_LOGGER = AuditLogger()


def get_audit_logger() -> AuditLogger:
    """Returns the singleton in-memory privacy-preserving audit logger."""
    return _GLOBAL_AUDIT_LOGGER