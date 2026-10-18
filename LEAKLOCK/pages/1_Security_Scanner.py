"""
LEAKLOCK — Page 1: Interactive Security Scanner & Downstream Provider Demo
"""

from __future__ import annotations

import streamlit as st

from services import (
    DATATHON_DEMO_SCENARIOS,
    analyze_prompt_pipeline,
    apply_light_theme,
    get_available_roles,
    get_max_prompt_length,
    load_sample_prompts,
)

st.set_page_config(
    page_title="Security Scanner | LEAKLOCK",
    page_icon="🔍",
    layout="wide",
)


def _init_session_state() -> None:
    roles = get_available_roles()
    if "selected_agent_role" not in st.session_state or st.session_state["selected_agent_role"] not in roles:
        st.session_state["selected_agent_role"] = roles[0] if roles else "PUBLIC_ASSISTANT"
    if "scanner_prompt_input" not in st.session_state:
        st.session_state["scanner_prompt_input"] = ""
    if "scanner_simulate_provider_error" not in st.session_state:
        st.session_state["scanner_simulate_provider_error"] = False
    if "scanner_last_result" not in st.session_state:
        st.session_state["scanner_last_result"] = None


def _clear_scanner() -> None:
    st.session_state["scanner_prompt_input"] = ""
    st.session_state["scanner_simulate_provider_error"] = False
    st.session_state["scanner_last_result"] = None


def render_scanner_page() -> None:
    apply_light_theme(st)
    _init_session_state()

    roles = get_available_roles()
    samples = load_sample_prompts()
    max_len = get_max_prompt_length()

    st.title("🔍 Interactive Security Scanner & Gateway Inspector")
    st.markdown(
        "Inspect user prompts across agent roles, verify redaction and blocking rules, and observe "
        "exact payloads forwarded to the downstream AI provider."
    )

    with st.container(border=True):
        st.markdown("#### 🎯 Datathon Demonstration Scenarios (One-Click Reproducible Presets)")
        sc_cols = st.columns(4)
        for col, scenario in zip(sc_cols, DATATHON_DEMO_SCENARIOS):
            with col:
                if st.button(scenario["title"], key=f"btn_{scenario['id']}", use_container_width=True):
                    st.session_state["scanner_prompt_input"] = scenario["prompt"]
                    if scenario["role"] in roles:
                        st.session_state["selected_agent_role"] = scenario["role"]
                    st.session_state["scanner_simulate_provider_error"] = bool(scenario["simulate_provider_error"])
                    st.session_state["scanner_last_result"] = analyze_prompt_pipeline(
                        prompt=scenario["prompt"],
                        role=st.session_state["selected_agent_role"],
                        forward_to_provider=True,
                        simulate_provider_error=bool(scenario["simulate_provider_error"]),
                    )
                    st.rerun()
                st.caption(scenario["expected_outcome"])

    with st.container(border=True):
        top_col1, top_col2 = st.columns([1, 2])

        with top_col1:
            selected_role = st.selectbox(
                "Active Agent Role",
                options=roles,
                index=roles.index(st.session_state["selected_agent_role"])
                if st.session_state["selected_agent_role"] in roles
                else 0,
                help="Select the security profile under which the prompt will be evaluated.",
            )
            st.session_state["selected_agent_role"] = selected_role

            sim_err = st.checkbox(
                "Simulate Downstream Provider Failure (Scenario D)",
                value=st.session_state["scanner_simulate_provider_error"],
                help="Test safe gateway error handling when the downstream AI provider times out or fails.",
            )
            st.session_state["scanner_simulate_provider_error"] = sim_err

        with top_col2:
            if samples:
                sample_labels = ["-- Select a synthetic sample from data/sample_prompts.json --"] + [
                    f"[{s.get('category', s.get('type', 'SAMPLE'))}] {s.get('title', s.get('name', s.get('id', f'Sample #{i+1}')))}"
                    for i, s in enumerate(samples)
                ]
                chosen_idx = st.selectbox(
                    "Load Synthetic Dataset Prompt (Optional)",
                    options=range(len(sample_labels)),
                    format_func=lambda idx: sample_labels[idx],
                )
                if chosen_idx > 0:
                    sample_obj = samples[chosen_idx - 1]
                    sample_text = str(sample_obj.get("prompt") or sample_obj.get("text") or "")
                    if st.button("Load Selected Dataset Prompt"):
                        st.session_state["scanner_prompt_input"] = sample_text
                        sample_role = sample_obj.get("role") or sample_obj.get("agent_role")
                        if sample_role in roles:
                            st.session_state["selected_agent_role"] = sample_role
                        st.session_state["scanner_simulate_provider_error"] = False
                        st.rerun()
            else:
                st.caption("Use the Datathon Scenario buttons above or enter any synthetic prompt below.")

        prompt_text = st.text_area(
            f"Prompt to Inspect (Max {max_len:,} characters)",
            value=st.session_state["scanner_prompt_input"],
            height=160,
            placeholder="Paste or type a prompt containing synthetic credentials, PII, or instructions...",
        )
        st.session_state["scanner_prompt_input"] = prompt_text

        btn_col1, btn_col2, _ = st.columns([1, 1, 4])
        analyze_clicked = btn_col1.button("🛡️ Analyze & Process Prompt", type="primary", use_container_width=True)
        btn_col2.button("🧹 Clear / Reset", on_click=_clear_scanner, use_container_width=True)

    if analyze_clicked:
        if not prompt_text or not prompt_text.strip():
            st.markdown(
                "<div class='ll-card-peach'><strong>Validation Notice:</strong> "
                "Please enter a non-empty prompt before running security analysis.</div>",
                unsafe_allow_html=True,
            )
            st.session_state["scanner_last_result"] = None
        else:
            with st.spinner("Executing 10-step security gateway pipeline..."):
                st.session_state["scanner_last_result"] = analyze_prompt_pipeline(
                    prompt=prompt_text,
                    role=selected_role,
                    forward_to_provider=True,
                    simulate_provider_error=st.session_state["scanner_simulate_provider_error"],
                )

    result = st.session_state.get("scanner_last_result")
    if result is None:
        st.markdown(
            "<div class='ll-security-notice'>"
            "Select one of <strong>Scenarios A–D</strong> above or enter a prompt and click "
            "<strong>Analyze &amp; Process Prompt</strong>."
            "</div>",
            unsafe_allow_html=True,
        )
        return

    st.divider()
    st.subheader("1. Security Gate Decision & Risk Assessment")

    decision = result.get("decision", "BLOCK")
    risk_score = result.get("risk_score", 0)
    severity = result.get("severity", "NONE")
    role_used = result.get("role", selected_role)
    categories = result.get("categories", [])
    threat_indicators = result.get("threat_indicators", [])
    provider_result = result.get("provider_result") or {}

    if decision == "ALLOW":
        st.markdown(
            f"<div class='ll-card-peppermint'>"
            f"<h3>✅ GATEWAY DECISION: ALLOW</h3>"
            f"<p><strong>Policy Explanation:</strong> {result.get('explanation')}</p>"
            f"<p>This prompt satisfied the <strong>{role_used}</strong> policy and was approved for downstream transmission.</p>"
            f"</div>",
            unsafe_allow_html=True,
        )
    elif decision == "REDACT":
        st.markdown(
            f"<div class='ll-card-peach'>"
            f"<h3>⚠️ GATEWAY DECISION: REDACT</h3>"
            f"<p><strong>Policy Explanation:</strong> {result.get('explanation')}</p>"
            f"<p>Sensitive content was masked under the <strong>{role_used}</strong> policy. "
            f"<strong>Only the sanitized prompt was forwarded to the downstream provider.</strong></p>"
            f"</div>",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f"<div class='ll-card-blush'>"
            f"<h3>🛑 GATEWAY DECISION: BLOCK</h3>"
            f"<p><strong>Policy Explanation:</strong> {result.get('explanation')}</p>"
            f"<p><strong>CRITICAL: This request was blocked by the {role_used} policy and was NEVER forwarded to the downstream AI provider.</strong></p>"
            f"</div>",
            unsafe_allow_html=True,
        )

    st.write("")
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Gateway Decision", decision)
    m2.metric("Risk Score (0–100)", f"{risk_score} / 100")
    m3.metric("Risk Severity", severity)
    m4.metric("Agent Role", role_used)
    m5.metric("Downstream Provider Called", "Yes" if provider_result.get("called") else "No (Halted)")

    st.progress(min(100, max(0, int(risk_score))) / 100.0, text=f"Explainable Risk Score: {risk_score}/100 ({severity})")

    det_col, thr_col = st.columns(2)
    with det_col:
        with st.container(border=True):
            st.markdown("#### 🔎 Detected Sensitive Categories")
            if categories:
                st.markdown(", ".join(f"`{c}`" for c in categories))
                findings = result.get("findings", [])
                if findings:
                    st.dataframe(findings, use_container_width=True, hide_index=True)
            else:
                st.caption("No sensitive data categories detected.")

    with thr_col:
        with st.container(border=True):
            st.markdown("#### 🚨 Prompt Threat Indicators")
            if threat_indicators:
                st.markdown(", ".join(f"`{t}`" for t in threat_indicators))
                threat_details = result.get("threat_details", [])
                if threat_details:
                    st.dataframe(threat_details, use_container_width=True, hide_index=True)
            else:
                st.caption("No prompt injection, jailbreak, or exfiltration threat indicators detected.")

    st.subheader("2. Prompt Sanitization & Outgoing Request Comparison")
    comp_col1, comp_col2 = st.columns(2)

    with comp_col1:
        with st.container(border=True):
            st.markdown("**Original User Prompt (Session UI Only — Never Logged)**")
            st.caption("Shown only in your current browser session for comparison. Never stored in audit logs.")
            st.code(result.get("original_prompt") or "", language="text")

    with comp_col2:
        with st.container(border=True):
            st.markdown("**Final Outgoing Payload Sent to Downstream Provider**")
            if decision == "BLOCK":
                st.markdown(
                    "<div class='ll-card-blush'>🚫 <strong>NO PAYLOAD SENT (BLOCKED)</strong> — "
                    "Request execution was terminated at the LEAKLOCK gateway. Zero bytes were transmitted downstream.</div>",
                    unsafe_allow_html=True,
                )
            elif decision == "REDACT":
                st.caption("Sanitized payload transmitted downstream (all matched secrets replaced with category markers):")
                st.code(result.get("sanitized_prompt") or "", language="text")
            else:
                st.caption("Approved payload transmitted downstream:")
                st.code(result.get("sanitized_prompt") or "", language="text")

    st.subheader("3. Downstream AI Provider Outcome & Audit Footprint")
    prov_col, aud_col = st.columns([2, 1])

    with prov_col:
        with st.container(border=True):
            st.markdown(f"**Provider Endpoint:** `{provider_result.get('provider_name', 'N/A')}`")
            p_status = provider_result.get("status", "UNKNOWN")
            if p_status == "SUCCESS":
                st.markdown(
                    "<div class='ll-card-peppermint'>Downstream provider processed the approved/sanitized request successfully.</div>",
                    unsafe_allow_html=True,
                )
                st.code(provider_result.get("response_text") or "", language="text")
            elif p_status == "PROVIDER_ERROR":
                st.markdown(
                    f"<div class='ll-card-blush'><strong>Downstream Provider Failure Handled Safely:</strong> "
                    f"{provider_result.get('error')}</div>",
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    "<div class='ll-card-sand'>Downstream provider was not invoked because the request was halted at the security gate.</div>",
                    unsafe_allow_html=True,
                )

    with aud_col:
        with st.container(border=True):
            st.markdown("**Recorded Audit Metadata**")
            st.json({
                "decision": decision,
                "role": role_used,
                "risk_score": risk_score,
                "severity": severity,
                "categories": categories,
                "threats": threat_indicators,
                "provider_status": p_status,
                "prompt_fingerprint": result.get("prompt_fingerprint", ""),
            })


if __name__ == "__main__":
    render_scanner_page()