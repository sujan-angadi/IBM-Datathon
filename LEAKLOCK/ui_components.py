import streamlit as st

def init_ui():
    """Initializes session state for theme and injects official pastel Light CSS."""
    st.session_state.theme = "light"

    # Define Official LEAKLOCK Pastel Light Palette
    theme_vars = {
        "--bg-app": "#FEF8DD",
        "--bg-sidebar": "#FAF3D4",
        "--bg-card": "#FFFFFF",
        "--bg-input": "#FFFFFF",
        "--text-primary": "#30343B",
        "--text-secondary": "#5A5D64",
        "--border-color": "#E8DFC0",
        "--accent": "#90D5FF",
        "--peach": "#FFDBBB",
        "--peppermint": "#E1F8DC",
        "--blush": "#F1CFE3",
        "--soft-peach": "#F7D8BA",
        "--shadow": "0 2px 8px rgba(90, 70, 40, 0.05)",
    }

    css_vars = "\n".join([f"{k}: {v};" for k, v in theme_vars.items()])

    st.markdown(
        f"""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@500;700&display=swap');

        :root {{
            {css_vars}
        }}

        /* Global App Overrides */
        html, body, .stApp, [data-testid="stAppViewContainer"] {{
            background-color: var(--bg-app) !important;
            color: var(--text-primary) !important;
            font-family: 'Inter', sans-serif !important;
        }}

        /* Sidebar Polish */
        section[data-testid="stSidebar"],
        [data-testid="stSidebar"] > div:first-child {{
            background-color: var(--bg-sidebar) !important;
            border-right: 1px solid var(--border-color) !important;
        }}
        section[data-testid="stSidebar"] * {{
            color: var(--text-primary) !important;
        }}

        /* Hide default Streamlit chrome for enterprise look */
        #MainMenu {{visibility: hidden;}}
        footer {{visibility: hidden;}}
        header[data-testid="stHeader"] {{background: transparent !important;}}

        /* Enterprise Card Container */
        .ll-card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            box-shadow: var(--shadow);
            margin-bottom: 16px;
            transition: transform 0.15s ease, border-color 0.15s ease;
        }}
        .ll-card:hover {{
            border-color: var(--accent);
        }}

        /* KPI Metric Card */
        .ll-kpi-title {{
            font-size: 0.78rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--text-secondary);
            margin-bottom: 6px;
        }}
        .ll-kpi-value {{
            font-size: 1.85rem;
            font-weight: 700;
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            line-height: 1.2;
        }}
        .ll-kpi-sub {{
            font-size: 0.78rem;
            margin-top: 6px;
            color: var(--text-secondary);
        }}

        /* ALLOW / REDACT / BLOCK Status Badges */
        .ll-badge {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 12px;
            border-radius: 9999px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.05em;
            text-transform: uppercase;
        }}
        .ll-badge-allow {{
            background: rgba(34, 197, 94, 0.15);
            color: #22c55e;
            border: 1px solid rgba(34, 197, 94, 0.35);
        }}
        .ll-badge-redact {{
            background: rgba(245, 158, 11, 0.15);
            color: #f59e0b;
            border: 1px solid rgba(245, 158, 11, 0.35);
        }}
        .ll-badge-block {{
            background: rgba(239, 68, 68, 0.15);
            color: #ef4444;
            border: 1px solid rgba(239, 68, 68, 0.35);
        }}

        /* Risk Score Meter */
        .ll-risk-track {{
            width: 100%;
            height: 10px;
            background: var(--border-color);
            border-radius: 999px;
            overflow: hidden;
            margin: 8px 0;
        }}
        .ll-risk-fill {{
            height: 100%;
            border-radius: 999px;
            transition: width 0.4s ease;
        }}

        /* Responsive Mobile Adjustments */
        @media (max-width: 768px) {{
            .ll-kpi-value {{ font-size: 1.4rem; }}
            .ll-card {{ padding: 14px; }}
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_status_badge(action: str) -> str:
    """Returns HTML for ALLOW, REDACT, or BLOCK badge."""
    action_upper = action.upper()
    if action_upper == "ALLOW":
        return '<span class="ll-badge ll-badge-allow">✔ ALLOW</span>'
    elif action_upper == "REDACT":
        return '<span class="ll-badge ll-badge-redact">⚡ REDACT</span>'
    else:
        return '<span class="ll-badge ll-badge-block">🛑 BLOCK</span>'


def render_kpi_card(title: str, value: str, subtitle: str = "", accent_color: str = ""):
    """Renders a polished enterprise KPI metric card."""
    border_style = f"border-left: 4px solid {accent_color};" if accent_color else ""
    st.markdown(
        f"""
        <div class="ll-card" style="{border_style}">
            <div class="ll-kpi-title">{title}</div>
            <div class="ll-kpi-value">{value}</div>
            <div class="ll-kpi-sub">{subtitle}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_risk_meter(score: int):
    """Renders a visual 0-100 risk score bar with dynamic threat coloring."""
    score = max(0, min(100, int(score)))
    if score < 30:
        color, label = "#22c55e", "Low Risk"
    elif score < 70:
        color, label = "#f59e0b", "Elevated Risk"
    else:
        color, label = "#ef4444", "Critical Risk"

    st.markdown(
        f"""
        <div class="ll-card">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span class="ll-kpi-title" style="margin:0;">THREAT RISK SCORE</span>
                <span style="font-family:'JetBrains Mono',monospace; font-weight:700; color:{color};">
                    {score}/100 ({label})
                </span>
            </div>
            <div class="ll-risk-track">
                <div class="ll-risk-fill" style="width:{score}%; background:{color};"></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )