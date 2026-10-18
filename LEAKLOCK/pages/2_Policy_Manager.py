"""
LEAKLOCK — Page 2: Policy Manager
"""

from __future__ import annotations

import streamlit as st

from services import (
    apply_light_theme,
    get_available_roles,
    get_role_policies,
    get_supported_categories,
)

st.set_page_config(
    page_title="Policy Manager | LEAKLOCK",
    page_icon="📜",
    layout="wide",
)


def render_policy_manager() -> None:
    apply_light_theme(st)

    st.title("📜 Role-Based Security Policy Manager")
    st.markdown(
        "Review how LEAKLOCK evaluates prompts for each agent role. "
        "Policies are enforced deterministically by `core/policy_engine.py` and cannot be weakened from the UI."
    )

    roles = get_available_roles()
    policies = get_role_policies()
    all_categories = get_supported_categories()

    if "selected_agent_role" not in st.session_state or st.session_state["selected_agent_role"] not in roles:
        st.session_state["selected_agent_role"] = roles[0] if roles else "PUBLIC_ASSISTANT"

    with st.container(border=True):
        col_select, col_info = st.columns([1, 2])
        with col_select:
            chosen_role = st.selectbox(
                "Active Role for Security Scanner",
                options=roles,
                index=roles.index(st.session_state["selected_agent_role"]),
                help="Selecting a role here sets the default evaluation profile in the Security Scanner.",
            )
            st.session_state["selected_agent_role"] = chosen_role
        with col_info:
            st.markdown(
                f"<div class='ll-security-notice'>"
                f"<strong>Current Scanner Role:</strong> <code>{chosen_role}</code><br/>"
                f"All policies enforce <strong>fail-closed</strong> security: if any detector or policy check encounters "
                f"an unexpected error, the request is automatically blocked."
                f"</div>",
                unsafe_allow_html=True,
            )

    st.divider()

    st.subheader("Agent Role Policy Matrix")
    matrix_rows = []
    for r in roles:
        p = policies.get(r, {})
        redact_cats = p.get("redact_categories", [])
        block_cats = p.get("block_categories", [])
        matrix_rows.append(
            {
                "Agent Role": r,
                "Blocked Categories": ", ".join(str(c) for c in block_cats) if block_cats else "None (Role Default)",
                "Redacted Categories": ", ".join(str(c) for c in redact_cats) if redact_cats else "None (Role Default)",
                "Threat Handling": p.get("threat_action", "BLOCK"),
                "Risk Block Threshold": p.get("risk_threshold_block") if p.get("risk_threshold_block") is not None else "Policy Default",
                "Fail-Closed": "Yes (Enforced)" if p.get("fail_closed", True) else "No",
            }
        )
    st.dataframe(matrix_rows, use_container_width=True, hide_index=True)

    st.divider()

    st.subheader("Detailed Role Configurations")
    tabs = st.tabs(roles)
    for tab, role_name in zip(tabs, roles):
        p = policies.get(role_name, {})
        with tab:
            st.markdown(f"### `{role_name}`")
            st.write(p.get("description", ""))

            c1, c2, c3 = st.columns(3)
            with c1:
                st.markdown("<div class='ll-card-blush'><h4>🛑 Blocked Categories</h4></div>", unsafe_allow_html=True)
                with st.container(border=True):
                    st.caption("If any of these categories are detected, the entire request is halted immediately.")
                    block_list = p.get("block_categories", [])
                    if block_list:
                        for item in block_list:
                            st.markdown(f"- `{item}`")
                    else:
                        st.caption("Governed by risk score and threat rules.")

            with c2:
                st.markdown("<div class='ll-card-peach'><h4>⚠️ Redacted Categories</h4></div>", unsafe_allow_html=True)
                with st.container(border=True):
                    st.caption("Matched values are replaced with safe placeholders before forwarding.")
                    redact_list = p.get("redact_categories", [])
                    if redact_list:
                        for item in redact_list:
                            st.markdown(f"- `{item}`")
                    else:
                        st.caption("No automatic redaction categories configured for this role.")

            with c3:
                st.markdown("<div class='ll-card-peppermint'><h4>🚨 Threat &amp; Fail-Closed Behavior</h4></div>", unsafe_allow_html=True)
                with st.container(border=True):
                    st.markdown(f"- **Threat Response:** {p.get('threat_action', 'BLOCK')}")
                    if p.get("risk_threshold_block") is not None:
                        st.markdown(f"- **Risk Block Threshold:** `{p['risk_threshold_block']} / 100`")
                    st.markdown(
                        f"- **Fail-Closed Guarantee:** `{'ENABLED' if p.get('fail_closed', True) else 'DISABLED'}`"
                    )

            with st.expander("View Raw Engine Policy Definition"):
                st.json(p.get("raw", {}))

    if all_categories:
        st.divider()
        st.subheader("Engine Sensitive-Data Categories")
        st.markdown(", ".join(f"`{cat}`" for cat in all_categories))


if __name__ == "__main__":
    render_policy_manager()
