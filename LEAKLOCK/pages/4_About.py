"""
LEAKLOCK — Page 4: About & Architecture Documentation
"""

from __future__ import annotations

import streamlit as st

from services import (
    apply_light_theme,
    get_available_roles,
    get_supported_categories,
)

st.set_page_config(
    page_title="About | LEAKLOCK",
    page_icon="ℹ️",
    layout="wide",
)


def render_about_page() -> None:
    apply_light_theme(st)

    st.title("ℹ️ About LEAKLOCK")
    st.markdown(
        "**LEAKLOCK** is an AI Data Protection Gateway designed to inspect, score, sanitize, or block "
        "outbound prompts before sensitive organizational data or credentials reach external AI services."
    )

    st.markdown(
        "<div class='ll-security-notice'>"
        "<strong>Gateway Security Guarantee:</strong> All sensitive-data detection, threat heuristics, "
        "explainable risk scoring, and role policy enforcement execute locally before any downstream request is made."
        "</div>",
        unsafe_allow_html=True,
    )

    st.divider()

    col_arch, col_wf = st.columns(2)
    with col_arch:
        with st.container(border=True):
            st.subheader("Architecture Overview")
            st.markdown(
                """
                - **Presentation Layer (`app.py`, `pages/`)**: Interactive Streamlit UI styled with the unified LEAKLOCK light palette.
                - **Orchestration Bridge (`services/`)**: Connects UI inputs to the core engine with fail-closed exception handling and downstream provider routing.
                - **Core Security Engine (`core/`)**:
                  - `core/detector.py`: Pattern and rule-based sensitive data detection & redaction.
                  - `core/threat_detector.py`: Prompt injection, jailbreak, and exfiltration heuristic detection.
                  - `core/risk_scorer.py`: Explainable 0–100 risk score and severity calculation.
                  - `core/policy_engine.py`: Role-aware policy evaluation (`ALLOW`, `REDACT`, `BLOCK`).
                  - `core/audit_logger.py`: Privacy-preserving, metadata-only event logging and JSONL export.
                - **Configuration (`config/settings.py`, `.streamlit/config.toml`)**: Centralized constants, thresholds, and light theme configuration.
                """
            )

    with col_wf:
        with st.container(border=True):
            st.subheader("Detection & Policy Workflow")
            st.markdown(
                """
                1. **Prompt Intake**: Untrusted user prompt and target agent role are submitted.
                2. **Sensitive Data Scan**: Identifies secrets, API keys, PII, and regulated identifiers.
                3. **Threat Analysis**: Scans for adversarial instructions, system prompt overrides, or exfiltration cues.
                4. **Risk Scoring**: Combines finding severity and threat indicators into a 0–100 score.
                5. **Role Policy Enforcement**: Applies deterministic rules for the chosen role (`ALLOW`, `REDACT`, or `BLOCK`).
                6. **Fail-Closed Guarantee**: Any unexpected engine error forces an immediate `BLOCK` decision.
                7. **Metadata-Only Audit**: Logs timestamp, role, decision, score, SHA-256 fingerprint, and category names without raw secrets.
                """
            )

    st.divider()

    cat_col, role_col = st.columns(2)
    with cat_col:
        with st.container(border=True):
            st.subheader("Supported Sensitive-Data Categories")
            categories = get_supported_categories()
            if categories:
                st.markdown(", ".join(f"`{c}`" for c in categories))

    with role_col:
        with st.container(border=True):
            st.subheader("Configured Agent Roles")
            for role in get_available_roles():
                st.markdown(f"- **`{role}`**")

    st.divider()

    priv_col, lim_col = st.columns(2)
    with priv_col:
        st.markdown("<div class='ll-card-peppermint'><h4>🔒 Audit Privacy Model</h4></div>", unsafe_allow_html=True)
        with st.container(border=True):
            st.markdown(
                """
                - **Zero Raw Prompt Storage**: Raw prompts are never persisted to disk or stored in audit records.
                - **Zero Secret Value Retention**: Matched secret substrings are stripped before audit events are recorded.
                - **Session-Scoped Inspection**: The original prompt is only shown in the active user's immediate scanner session.
                """
            )

    with lim_col:
        st.markdown("<div class='ll-card-peach'><h4>⚠️ Current Prototype Limitations</h4></div>", unsafe_allow_html=True)
        with st.container(border=True):
            st.markdown(
                """
                - **Pattern & Heuristic Scope**: Regex and heuristic rules cannot guarantee detection of all novel obfuscations, encodings, or semantic prompt injections.
                - **In-Memory Telemetry**: Unless exported via JSONL, in-memory audit events clear upon process restart.
                """
            )

    st.divider()

    st.subheader("Technology Stack & Running the Project")
    st.code(
        "# 1. Activate virtual environment and install dependencies\n"
        "pip install -r requirements.txt\n\n"
        "# 2. Run automated test suite\n"
        "pytest -v\n\n"
        "# 3. Launch the interactive gateway\n"
        "streamlit run app.py",
        language="bash",
    )


if __name__ == "__main__":
    render_about_page()
