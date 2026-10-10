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


def metric_card(title: str, value: Any, color: str) -> str:
    return f"""
    <div style="background: #ffffff; border-radius: 10px; padding: 1.5rem;
                box-shadow: 0 2px 8px rgba(0,0,0,0.05); text-align: center;
                border: 1px solid #e2e8f0; border-top: 3px solid {color};">
        <div style="font-size: 2.2rem; font-weight: 700; color: {color}; line-height: 1.2;">{value}</div>
        <div style="color: #64748b; font-size: 0.85rem; margin-top: 0.4rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;">{title}</div>
    </div>
    """


def empty_state() -> None:
    st.markdown("""
    <div style="text-align: center; padding: 4rem 2rem; background: #ffffff;
                border-radius: 10px; border: 1px dashed #cbd5e1; margin: 2rem 0;">
        <h3 style="color: #334155; font-weight: 700; margin-bottom: 0.5rem;">No Scan Telemetry Available</h3>
        <p style="color: #64748b; font-size: 0.95rem;">
            Telemetry charts and metrics will populate once QR codes are processed via the Scanner page.
        </p>
    </div>
    """, unsafe_allow_html=True)


def main() -> None:
    st.markdown("""
    <div style="margin-bottom: 1.5rem;">
        <h1 style="font-size: 2.2rem; font-weight: 700; color: #0a1628; margin-bottom: 0.25rem;">
            Security Analytics Dashboard
        </h1>
        <p style="color: #64748b; font-size: 1rem; margin: 0;">
            Overview of scanned payload classifications and risk telemetry
        </p>
    </div>
    """, unsafe_allow_html=True)

    if st.button("Refresh Telemetry", type="secondary"):
        st.cache_resource.clear()
        st.rerun()

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

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(metric_card("Total Scans", total, ELECTRIC_BLUE), unsafe_allow_html=True)
    with c2:
        st.markdown(metric_card("Low Risk", low, SUCCESS_GREEN), unsafe_allow_html=True)
    with c3:
        st.markdown(metric_card("Suspicious", suspicious, WARNING_AMBER), unsafe_allow_html=True)
    with c4:
        st.markdown(metric_card("High Risk", high, DANGER_RED), unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    chart1, chart2 = st.columns(2)

    with chart1:
        st.markdown("#### Risk Level Distribution")
        dist_data = {RISK_LABELS.get(k, k): v for k, v in risk_counts.items() if v > 0}
        if dist_data:
            fig = go.Figure(go.Pie(
                labels=list(dist_data.keys()),
                values=list(dist_data.values()),
                hole=0.45,
                marker_colors=[RISK_COLORS.get(k, MUTED_GRAY) for k in risk_counts if risk_counts[k] > 0],
                textinfo="label+percent",
                textfont_size=12,
            ))
            fig.update_layout(
                template="plotly_white",
                height=340,
                margin=dict(l=20, r=20, t=20, b=20),
                showlegend=True,
                legend=dict(orientation="h", yanchor="bottom", y=-0.15),
            )
            st.plotly_chart(fig, use_container_width=True, config={"displaylogo": False})

    with chart2:
        st.markdown("#### 30-Day Activity Trend")
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
                    fillcolor=f"{ELECTRIC_BLUE}14",
                ))
                fig2.update_layout(
                    template="plotly_white",
                    height=340,
                    margin=dict(l=20, r=20, t=20, b=20),
                    xaxis_title="Date",
                    yaxis_title="Total Scans",
                    yaxis=dict(rangemode="tozero"),
                )
                st.plotly_chart(fig2, use_container_width=True, config={"displaylogo": False})
            else:
                st.info("Insufficient daily telemetry data available.")
        except Exception:
            st.info("Daily trend telemetry unavailable.")

    chart3, chart4 = st.columns(2)

    with chart3:
        st.markdown("#### Scanned Content Classifications")
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
                height=280,
                margin=dict(l=20, r=40, t=10, b=10),
                xaxis_title="Count",
                yaxis=dict(autorange="reversed"),
            )
            st.plotly_chart(fig3, use_container_width=True, config={"displaylogo": False})

    with chart4:
        st.markdown("#### Threat Detection Summary")
        threats = suspicious + high
        rate = (threats / total * 100) if total > 0 else 0
        st.markdown(f"""
        <div style="background: #ffffff; border-radius: 10px; padding: 1.5rem;
                    border: 1px solid #e2e8f0; text-align: center;">
            <div style="font-size: 0.85rem; color: #64748b; font-weight: 600; text-transform: uppercase;">
                Threat Flag Rate
            </div>
            <div style="font-size: 2.5rem; font-weight: 700; color: {NAVY}; margin: 0.35rem 0;">
                {rate:.1f}%
            </div>
            <div style="font-size: 0.85rem; color: #64748b;">
                {threats} flagged threats out of {total} total scans
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("#### Recent Activity Records")

    recent = stats.get("recent_scans", [])
    if recent:
        table_data = []
        for scan in recent[:10]:
            risk = scan.get("risk_level", "unknown")
            table_data.append({
                "Timestamp": scan.get("timestamp", "")[:19],
                "Type": (scan.get("content_type") or "unknown").upper(),
                "Preview": (scan.get("content_preview") or "N/A")[:60],
                "Risk Classification": RISK_LABELS.get(risk, risk),
                "Probability": f"{scan.get('model_probability', 0) or 0:.1%}"
                               if scan.get("model_probability") else "N/A",
            })
        st.dataframe(
            pd.DataFrame(table_data),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No recent scans recorded.")


if __name__ == "__main__":
    main()
