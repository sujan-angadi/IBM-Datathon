"""
LEAKLOCK — Page 3: Privacy-Preserving Audit Dashboard
"""

from __future__ import annotations

from collections import Counter
import streamlit as st

from services import (
    apply_light_theme,
    export_audit_jsonl,
    get_audit_events,
    get_available_roles,
)

st.set_page_config(
    page_title="Audit Dashboard | LEAKLOCK",
    page_icon="📊",
    layout="wide",
)


def render_audit_dashboard() -> None:
    apply_light_theme(st)

    st.title("📊 Privacy-Preserving Audit Dashboard")
    st.markdown(
        "Monitor gateway decisions, risk distributions, and detected category frequency. "
        "**Strict Privacy Guarantee:** Raw prompts, credentials, and matched secret values are never stored or displayed."
    )

    events, is_in_memory = get_audit_events()

    if is_in_memory:
        st.markdown(
            "<div class='ll-security-notice'>"
            "<strong>Storage Notice:</strong> The audit logger is operating in in-memory mode. "
            "Recorded telemetry persists for the current process lifecycle and resets when the server restarts. "
            "Use the <strong>Export Audit Log (JSONL)</strong> button below to retain audit records externally."
            "</div>",
            unsafe_allow_html=True,
        )

    if not events:
        st.markdown(
            "<div class='ll-card-peach'>"
            "No audit events have been recorded yet. Analyze one or more prompts in the "
            "<strong>Security Scanner</strong> to populate real gateway telemetry."
            "</div>",
            unsafe_allow_html=True,
        )
        return

    with st.container(border=True):
        st.markdown("#### Filter Audit Events")
        f_col1, f_col2, f_col3, f_col4 = st.columns(4)

        all_decisions = ["ALLOW", "REDACT", "BLOCK"]
        selected_decisions = f_col1.multiselect("Decision", options=all_decisions, default=all_decisions)

        available_roles = sorted(list({e.get("role", "PUBLIC_ASSISTANT") for e in events} | set(get_available_roles())))
        selected_roles = f_col2.multiselect("Agent Role", options=available_roles, default=available_roles)

        all_severities = sorted(list({e.get("severity", "NONE") for e in events}))
        selected_severities = f_col3.multiselect("Risk Severity", options=all_severities, default=all_severities)

        date_prefix = f_col4.text_input("Date / Timestamp Filter (YYYY-MM-DD)", value="", placeholder="e.g. 2026-10-18")

    filtered_events = [
        e
        for e in events
        if e.get("decision") in selected_decisions
        and e.get("role") in selected_roles
        and e.get("severity") in selected_severities
        and (not date_prefix.strip() or date_prefix.strip() in e.get("timestamp", ""))
    ]

    total_count = len(filtered_events)
    allow_count = sum(1 for e in filtered_events if e.get("decision") == "ALLOW")
    redact_count = sum(1 for e in filtered_events if e.get("decision") == "REDACT")
    block_count = sum(1 for e in filtered_events if e.get("decision") == "BLOCK")
    avg_risk = round(sum(e.get("risk_score", 0) for e in filtered_events) / total_count, 1) if total_count else 0.0
    threat_events = sum(1 for e in filtered_events if e.get("threat_count", 0) > 0 or e.get("threats"))

    m1, m2, m3, m4, m5, m6 = st.columns(6)
    m1.metric("Filtered Requests", total_count)
    m2.metric("ALLOW", allow_count)
    m3.metric("REDACT", redact_count)
    m4.metric("BLOCK", block_count)
    m5.metric("Avg Risk Score", f"{avg_risk} / 100")
    m6.metric("Threat Events", threat_events)

    if not filtered_events:
        st.markdown("<div class='ll-card-sand'>No audit events match the active filter criteria.</div>", unsafe_allow_html=True)
        return

    st.divider()

    chart_col1, chart_col2 = st.columns(2)
    with chart_col1:
        with st.container(border=True):
            st.markdown("#### Decisions Breakdown")
            decision_counts = {"ALLOW": allow_count, "REDACT": redact_count, "BLOCK": block_count}
            st.bar_chart(decision_counts, color="#90D5FF")

    with chart_col2:
        with st.container(border=True):
            st.markdown("#### Most Frequently Detected Categories")
            cat_counter: Counter[str] = Counter()
            for e in filtered_events:
                for c in e.get("categories", []):
                    cat_counter[str(c)] += 1
            if cat_counter:
                st.bar_chart(dict(cat_counter.most_common(10)), color="#FFDBBB")
            else:
                st.caption("No sensitive categories recorded in the filtered audit events.")

    st.divider()

    st.subheader("Recent Audit Events (Metadata Only)")
    display_rows = []
    for e in reversed(filtered_events):
        display_rows.append(
            {
                "Timestamp": e.get("timestamp", ""),
                "Agent Role": e.get("role", ""),
                "Decision": e.get("decision", ""),
                "Risk Score": e.get("risk_score", 0),
                "Severity": e.get("severity", ""),
                "Detected Categories": ", ".join(str(c) for c in e.get("categories", [])) or "None",
                "Threat Indicators": ", ".join(str(t) for t in e.get("threats", [])) or "None",
                "Provider Status": e.get("provider_status", "RECORDED"),
                "Prompt Fingerprint": e.get("prompt_fingerprint", ""),
                "Policy Reason": e.get("reason", ""),
            }
        )
    st.dataframe(display_rows, use_container_width=True, hide_index=True)

    st.subheader("Export Audit Telemetry")
    jsonl_payload = export_audit_jsonl()
    st.download_button(
        label="⬇️ Export Audit Log (JSONL)",
        data=jsonl_payload,
        file_name="leaklock_audit_events.jsonl",
        mime="application/x-jsonlines",
    )


if __name__ == "__main__":
    render_audit_dashboard()
