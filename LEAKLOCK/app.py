"""
LEAKLOCK — AI Data Protection Gateway
Main Streamlit Entrypoint (Home Page)
"""

from __future__ import annotations

import streamlit as st

from services import (
    apply_light_theme,
    get_audit_events,
    get_available_roles,
    get_supported_categories,
    load_sample_prompts,
)

st.set_page_config(
    page_title="LEAKLOCK | AI Data Protection Gateway",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def render_home() -> None:
    apply_light_theme(st)

    st.title("🛡️ LEAKLOCK — AI Data Protection Gateway")
    st.markdown(
        "**Inspect, score, sanitize, or block sensitive prompts before they reach an external AI service.**"
    )

    st.markdown(
        "<div class='ll-security-notice'>"
        "<strong>Prototype Security Notice:</strong> LEAKLOCK is an application-layer security gateway prototype. "
        "While it enforces deterministic policy rules, overlap-safe redaction, and fail-closed error handling, "
        "pattern and heuristic detection is not guaranteed to catch every novel prompt injection or data exfiltration attempt."
        "</div>",
        unsafe_allow_html=True,
    )

    st.divider()

    st.subheader("End-to-End 10-Step Security Workflow")
    row1 = st.columns(5)
    row2 = st.columns(5)
    steps = [
        ("1. Prompt Intake", "Receive untrusted prompt & role.", "#90D5FF"),
        ("2. Secret Detection", "Scan for credentials, PII, & keys.", "#FFDBBB"),
        ("3. Threat Detection", "Check injection & exfiltration rules.", "#F1CFE3"),
        ("4. Risk Scoring", "Calculate explainable 0–100 score.", "#F7D8BA"),
        ("5. Policy Evaluation", "Apply role rules (fail-closed).", "#90D5FF"),
        ("6. Gate Decision", "Produce ALLOW, REDACT, or BLOCK.", "#E1F8DC"),
        ("7. Safe Redaction", "Mask spans right-to-left.", "#FFDBBB"),
        ("8. Provider Forwarding", "Send ONLY safe/redacted payload.", "#E1F8DC"),
        ("9. Privacy Audit", "Log metadata & SHA-256 fingerprint.", "#F7D8BA"),
        ("10. UI Telemetry", "Render decision & provider outcome.", "#F1CFE3"),
    ]
    for col, (title, desc, accent_hex) in zip(row1 + row2, steps):
        with col:
            st.markdown(
                f"<div style='background-color:#FFFFFF;border:1px solid #E2D9C5;"
                f"border-top:5px solid {accent_hex};border-radius:10px;padding:12px 14px;"
                f"margin-bottom:10px;color:#30343B;'>"
                f"<strong>{title}</strong><br/>"
                f"<span style='font-size:0.86rem;color:#30343B;'>{desc}</span>"
                f"</div>",
                unsafe_allow_html=True,
            )

    st.divider()

    st.subheader("Live Gateway Telemetry")
    events, is_in_memory = get_audit_events()
    roles = get_available_roles()
    categories = get_supported_categories()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Configured Agent Roles", len(roles))
    c2.metric("Supported Detection Categories", len(categories))
    c3.metric("Total Prompts Analyzed", len(events))

    if events:
        blocked_count = sum(1 for e in events if e.get("decision") == "BLOCK")
        redacted_count = sum(1 for e in events if e.get("decision") == "REDACT")
        allowed_count = sum(1 for e in events if e.get("decision") == "ALLOW")
        avg_risk = round(sum(e.get("risk_score", 0) for e in events) / len(events), 1)
        c4.metric("Average Risk Score", f"{avg_risk} / 100")

        m1, m2, m3 = st.columns(3)
        m1.metric("Allowed Requests (ALLOW)", allowed_count)
        m2.metric("Sanitized Requests (REDACT)", redacted_count)
        m3.metric("Blocked Requests (BLOCK)", blocked_count)
    else:
        c4.metric("Average Risk Score", "N/A")
        st.markdown(
            "<div class='ll-card-sand'>"
            "No prompts have been analyzed in this session yet. "
            "Open the <strong>Security Scanner</strong> to run Datathon Scenarios A–D or inspect a custom prompt."
            "</div>",
            unsafe_allow_html=True,
        )

    if is_in_memory:
        st.caption("ℹ️ Audit events are held in memory during the current process lifecycle and reset upon restart.")

    st.divider()

    st.subheader("Gateway Modules")
    nav1, nav2, nav3, nav4 = st.columns(4)
    with nav1:
        with st.container(border=True):
            st.markdown("### 🔍 Security Scanner")
            st.write("Run interactive inspections, test Datathon Scenarios A–D, and inspect downstream provider responses.")
            if hasattr(st, "page_link"):
                st.page_link("pages/1_Security_Scanner.py", label="Open Security Scanner", icon="🔍")
    with nav2:
        with st.container(border=True):
            st.markdown("### 📜 Policy Manager")
            st.write("Inspect role-based redaction and blocking rules for all 4 agent profiles.")
            if hasattr(st, "page_link"):
                st.page_link("pages/2_Policy_Manager.py", label="Open Policy Manager", icon="📜")
    with nav3:
        with st.container(border=True):
            st.markdown("### 📊 Audit Dashboard")
            st.write("Review metadata-only audit logs, filter events, and export JSONL telemetry.")
            if hasattr(st, "page_link"):
                st.page_link("pages/3_Audit_Dashboard.py", label="Open Audit Dashboard", icon="📊")
    with nav4:
        with st.container(border=True):
            st.markdown("### ℹ️ About LEAKLOCK")
            st.write("Read architecture documentation, privacy guarantees, and cross-platform setup commands.")
            if hasattr(st, "page_link"):
                st.page_link("pages/4_About.py", label="Open About Page", icon="ℹ️")


# Expose main for import-based structural testing
main = render_home

if __name__ == "__main__":
    render_home()