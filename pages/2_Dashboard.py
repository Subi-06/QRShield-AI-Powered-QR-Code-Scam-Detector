"""
QRShield AI — Analytics Dashboard.

Displays real-time scanning statistics, risk distribution, daily trends,
and content type breakdown sourced from the SQLite scan history database.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from config.settings import (
    APP_NAME, ELECTRIC_BLUE, SUCCESS_GREEN, WARNING_AMBER,
    DANGER_RED, MUTED_GRAY, NAVY, DARK_BLUE,
)
from src.database.db_manager import DatabaseManager

st.set_page_config(
    page_title=f"{APP_NAME} - Dashboard",
    page_icon="🛡️",
    layout="wide",
)

css_path = project_root / "styles" / "main.css"
if css_path.exists():
    st.markdown(f"<style>{css_path.read_text()}</style>", unsafe_allow_html=True)


@st.cache_resource
def get_db() -> DatabaseManager:
    return DatabaseManager()


db = get_db()

RISK_COLORS = {
    "low_risk": SUCCESS_GREEN,
    "suspicious": WARNING_AMBER,
    "high_risk": DANGER_RED,
    "verification_required": ELECTRIC_BLUE,
    "informational": MUTED_GRAY,
}

RISK_LABELS = {
    "low_risk": "Low Risk",
    "suspicious": "Suspicious",
    "high_risk": "High Risk",
    "verification_required": "Verification Required",
    "informational": "Informational",
}


# ── Metric card helper ───────────────────────────────────────────
def metric_card(title: str, value: Any, icon: str, color: str) -> str:
    return f"""
    <div style="background: #ffffff; border-radius: 12px; padding: 1.5rem;
                box-shadow: 0 2px 12px rgba(0,0,0,0.06); text-align: center;
                border-top: 3px solid {color}; border: 1px solid #e8edf2;
                border-top-width: 3px;">
        <div style="font-size: 2rem; margin-bottom: 0.25rem;">{icon}</div>
        <div style="font-size: 2.5rem; font-weight: 700; color: {color};">{value}</div>
        <div style="color: #64748b; font-size: 0.9rem; margin-top: 0.25rem;">{title}</div>
    </div>
    """


def empty_state() -> None:
    st.markdown("""
    <div style="text-align: center; padding: 4rem 2rem; background: #ffffff;
                border-radius: 12px; border: 1px dashed #cbd5e1; margin: 2rem 0;">
        <div style="font-size: 4rem; margin-bottom: 1rem;">📊</div>
        <h2 style="color: #475569; font-weight: 600; margin-bottom: 0.5rem;">No Scan Data Yet</h2>
        <p style="color: #94a3b8; font-size: 1rem;">
            Start scanning QR codes to see your analytics here.
        </p>
        <p style="color: #94a3b8; font-size: 0.9rem;">
            Navigate to the <strong>Scanner</strong> page to begin.
        </p>
    </div>
    """, unsafe_allow_html=True)


def main() -> None:
    st.markdown("""
    <div style="margin-bottom: 1.5rem;">
        <h1 style="font-size: 2.2rem; font-weight: 700; color: #0a1628; margin-bottom: 0.25rem;">
            📊 Analytics Dashboard
        </h1>
        <p style="color: #64748b; font-size: 1rem; margin: 0;">
            Real-time overview of your QR code scanning activity
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Refresh button
    if st.button("🔄 Refresh Data", type="secondary"):
        st.cache_resource.clear()
        st.rerun()

    # ── Load stats ───────────────────────────────────────────────
    try:
        stats = db.get_statistics()
    except Exception as e:
        st.error(f"Database error: {e}")
        return

    total = stats.get("total_scans", 0)

    if total == 0:
        empty_state()
        return

    risk_counts = stats.get("scans_by_risk_level", {})
    type_counts = stats.get("scans_by_content_type", {})

    low = risk_counts.get("low_risk", 0)
    suspicious = risk_counts.get("suspicious", 0)
    high = risk_counts.get("high_risk", 0)
    verification = risk_counts.get("verification_required", 0)

    # ── Summary cards ────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(metric_card("Total Scans", total, "📊", ELECTRIC_BLUE), unsafe_allow_html=True)
    with c2:
        st.markdown(metric_card("Low Risk", low, "✅", SUCCESS_GREEN), unsafe_allow_html=True)
    with c3:
        st.markdown(metric_card("Suspicious", suspicious, "⚠️", WARNING_AMBER), unsafe_allow_html=True)
    with c4:
        st.markdown(metric_card("High Risk", high, "🚨", DANGER_RED), unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Charts row 1 ─────────────────────────────────────────────
    chart1, chart2 = st.columns(2)

    with chart1:
        st.markdown("#### Scan Result Distribution")
        dist_data = {RISK_LABELS.get(k, k): v for k, v in risk_counts.items() if v > 0}
        if dist_data:
            fig = go.Figure(go.Pie(
                labels=list(dist_data.keys()),
                values=list(dist_data.values()),
                hole=0.45,
                marker_colors=[RISK_COLORS.get(k, MUTED_GRAY) for k in risk_counts if risk_counts[k] > 0],
                textinfo="label+percent",
                textfont_size=13,
            ))
            fig.update_layout(
                template="plotly_white",
                height=350,
                margin=dict(l=20, r=20, t=20, b=20),
                showlegend=True,
                legend=dict(orientation="h", yanchor="bottom", y=-0.15),
            )
            st.plotly_chart(fig, use_container_width=True, config={"displaylogo": False})

    with chart2:
        st.markdown("#### Daily Scan Trend")
        try:
            daily_counts = db.get_daily_scan_counts(30)
            if daily_counts:
                df_daily = pd.DataFrame(daily_counts)
                fig2 = go.Figure(go.Scatter(
                    x=df_daily["date"],
                    y=df_daily["count"],
                    mode="lines+markers",
                    fill="tozeroy",
                    line=dict(color=ELECTRIC_BLUE, width=2.5),
                    marker=dict(size=6, color=ELECTRIC_BLUE),
                    fillcolor=f"{ELECTRIC_BLUE}18",
                ))
                fig2.update_layout(
                    template="plotly_white",
                    height=350,
                    margin=dict(l=20, r=20, t=20, b=20),
                    xaxis_title="Date",
                    yaxis_title="Scans",
                    yaxis=dict(rangemode="tozero"),
                )
                st.plotly_chart(fig2, use_container_width=True, config={"displaylogo": False})
            else:
                st.info("No daily data available yet.")
        except Exception:
            st.info("Daily trend data unavailable.")

    # ── Charts row 2 ─────────────────────────────────────────────
    chart3, chart4 = st.columns(2)

    with chart3:
        st.markdown("#### Content Type Distribution")
        if type_counts:
            types_sorted = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
            type_names = [t[0].upper() for t in types_sorted]
            type_values = [t[1] for t in types_sorted]
            fig3 = go.Figure(go.Bar(
                y=type_names,
                x=type_values,
                orientation="h",
                marker_color=ELECTRIC_BLUE,
                text=type_values,
                textposition="outside",
            ))
            fig3.update_layout(
                template="plotly_white",
                height=300,
                margin=dict(l=20, r=40, t=10, b=10),
                xaxis_title="Count",
                yaxis=dict(autorange="reversed"),
            )
            st.plotly_chart(fig3, use_container_width=True, config={"displaylogo": False})

    with chart4:
        st.markdown("#### Risk Breakdown")
        if verification > 0:
            st.markdown(
                metric_card("Verification Required", verification, "🔍", ELECTRIC_BLUE),
                unsafe_allow_html=True,
            )
        other_risk = {k: v for k, v in risk_counts.items()
                      if k not in ("low_risk", "suspicious", "high_risk", "verification_required") and v > 0}
        if other_risk:
            for k, v in other_risk.items():
                st.metric(RISK_LABELS.get(k, k), v)

        # Detection rate
        threats = suspicious + high
        if total > 0:
            rate = threats / total * 100
            st.markdown(f"""
            <div style="background: #f8fafc; border-radius: 8px; padding: 1rem;
                        border: 1px solid #e2e8f0; margin-top: 1rem; text-align: center;">
                <div style="font-size: 0.85rem; color: #64748b;">Threat Detection Rate</div>
                <div style="font-size: 2rem; font-weight: 700; color: {NAVY};">{rate:.1f}%</div>
                <div style="font-size: 0.8rem; color: #94a3b8;">{threats} of {total} scans flagged</div>
            </div>
            """, unsafe_allow_html=True)

    # ── Recent scans table ───────────────────────────────────────
    st.markdown("---")
    st.markdown("#### Recent Scans")

    recent = stats.get("recent_scans", [])
    if recent:
        table_data = []
        for scan in recent[:10]:
            risk = scan.get("risk_level", "unknown")
            table_data.append({
                "Time": scan.get("timestamp", "")[:19],
                "Type": (scan.get("content_type") or "unknown").upper(),
                "Content": (scan.get("content_preview") or "N/A")[:60],
                "Risk Level": RISK_LABELS.get(risk, risk),
                "Probability": f"{scan.get('model_probability', 0) or 0:.1%}"
                               if scan.get("model_probability") else "—",
            })
        st.dataframe(
            pd.DataFrame(table_data),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No recent scans to display.")


if __name__ == "__main__":
    main()
