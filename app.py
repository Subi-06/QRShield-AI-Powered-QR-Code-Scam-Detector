"""
QRShieldAI — AI-Powered QR Code Scam Detector
Main application entry point.
"""

import streamlit as st
import sys
from pathlib import Path
from datetime import datetime

project_root = Path(__file__).parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from config.settings import (
    APP_NAME, APP_VERSION, APP_DESCRIPTION,
    ELECTRIC_BLUE, SUCCESS_GREEN, WARNING_AMBER, DANGER_RED,
)

st.set_page_config(
    page_title=f"{APP_NAME} - Scan Smart. Stay Safe.",
    layout="wide",
    initial_sidebar_state="collapsed",
)

css_path = project_root / "styles" / "main.css"
if css_path.exists():
    st.markdown(f"<style>{css_path.read_text()}</style>", unsafe_allow_html=True)

# ── Top Navigation Bar (Matches Reference Screenshot) ────────────
nav_col1, nav_col2 = st.columns([6, 4])
with nav_col1:
    st.markdown("""
    <div class="brand-container">
        <div class="brand-icon">QR</div>
        <div>
            <div class="brand-title">QRShieldAI</div>
            <div class="brand-subtitle">AI-Powered QR Code Scam Detector</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

with nav_col2:
    st.markdown("""
    <div style="display: flex; justify-content: flex-end; gap: 0.5rem; align-items: center; padding-top: 0.5rem;">
        <a href="/" target="_self" style="text-decoration: none; padding: 0.45rem 1rem; background: #eff6ff; color: #2563eb; border-radius: 8px; font-weight: 600; font-size: 0.9rem;">Home</a>
        <a href="/Scanner" target="_self" style="text-decoration: none; padding: 0.45rem 1rem; color: #475569; font-weight: 600; font-size: 0.9rem;">Scan QR</a>
        <a href="/Dashboard" target="_self" style="text-decoration: none; padding: 0.45rem 1rem; color: #475569; font-weight: 600; font-size: 0.9rem;">Dashboard</a>
        <a href="/About" target="_self" style="text-decoration: none; padding: 0.45rem 1rem; color: #475569; font-weight: 600; font-size: 0.9rem;">About</a>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ── Light Blue Hero Banner (Exact Match to Reference Screenshot) ─
st.markdown("""
<div class="hero-banner">
    <div class="hero-text-content">
        <div class="hero-heading">Scan Smart. Stay Safe.</div>
        <div class="hero-subtext">Upload a QR code and detect whether it is safe or a potential scam.</div>
    </div>
    <div class="hero-graphic">
        <div class="phone-mockup">
            <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="3" y="3" width="7" height="7"></rect>
                <rect x="14" y="3" width="7" height="7"></rect>
                <rect x="14" y="14" width="7" height="7"></rect>
                <rect x="3" y="14" width="7" height="7"></rect>
            </svg>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ── Navigation Cards Row ─────────────────────────────────────────
c1, c2, c3 = st.columns(3)

with c1:
    st.markdown("""
    <div class="main-card" style="text-align: center;">
        <div style="font-size: 1.15rem; font-weight: 700; color: #0f172a; margin-bottom: 0.4rem;">QR Scanner</div>
        <div style="font-size: 0.9rem; color: #64748b; line-height: 1.5; margin-bottom: 1.25rem;">Upload or scan any QR code to analyze URL threat parameters and verify UPI payments.</div>
        <a href="/Scanner" target="_self" style="display: inline-block; background: #2563eb; color: #ffffff; text-decoration: none; padding: 0.6rem 1.5rem; border-radius: 8px; font-weight: 600; font-size: 0.9rem;">Open Scanner</a>
    </div>
    """, unsafe_allow_html=True)

with c2:
    st.markdown("""
    <div class="main-card" style="text-align: center;">
        <div style="font-size: 1.15rem; font-weight: 700; color: #0f172a; margin-bottom: 0.4rem;">Security Dashboard</div>
        <div style="font-size: 0.9rem; color: #64748b; line-height: 1.5; margin-bottom: 1.25rem;">Real-time overview of your scanning records, threat distribution, and detection rate.</div>
        <a href="/Dashboard" target="_self" style="display: inline-block; background: #f1f5f9; color: #0f172a; text-decoration: none; padding: 0.6rem 1.5rem; border-radius: 8px; font-weight: 600; font-size: 0.9rem; border: 1px solid #e2e8f0;">View Dashboard</a>
    </div>
    """, unsafe_allow_html=True)

with c3:
    st.markdown("""
    <div class="main-card" style="text-align: center;">
        <div style="font-size: 1.15rem; font-weight: 700; color: #0f172a; margin-bottom: 0.4rem;">Model Evaluation</div>
        <div style="font-size: 0.9rem; color: #64748b; line-height: 1.5; margin-bottom: 1.25rem;">Benchmark metrics, confusion matrix, and performance reports across candidate models.</div>
        <a href="/Model_Report" target="_self" style="display: inline-block; background: #f1f5f9; color: #0f172a; text-decoration: none; padding: 0.6rem 1.5rem; border-radius: 8px; font-weight: 600; font-size: 0.9rem; border: 1px solid #e2e8f0;">View Model Metrics</a>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br><hr style='border: none; border-top: 1px solid #e2e8f0;'><br>", unsafe_allow_html=True)

# ── Activity & Statistics Summary ────────────────────────────────
try:
    from src.database.db_manager import DatabaseManager
    db = DatabaseManager()
    stats = db.get_statistics()
    total = stats.get("total_scans", 0)
    risk_counts = stats.get("scans_by_risk_level", {})
    low = risk_counts.get("low_risk", 0)
    suspicious = risk_counts.get("suspicious", 0)
    high = risk_counts.get("high_risk", 0)
except Exception:
    total, low, suspicious, high = 0, 0, 0, 0

s1, s2, s3, s4 = st.columns(4)
with s1:
    st.markdown(f"""
    <div style="background: white; border-radius: 12px; padding: 1.25rem; border: 1px solid #e2e8f0; text-align: center;">
        <div style="font-size: 2rem; font-weight: 800; color: #2563eb;">{total}</div>
        <div style="font-size: 0.8rem; color: #64748b; font-weight: 600; text-transform: uppercase;">Total Scans</div>
    </div>
    """, unsafe_allow_html=True)
with s2:
    st.markdown(f"""
    <div style="background: white; border-radius: 12px; padding: 1.25rem; border: 1px solid #e2e8f0; text-align: center;">
        <div style="font-size: 2rem; font-weight: 800; color: #10b981;">{low}</div>
        <div style="font-size: 0.8rem; color: #64748b; font-weight: 600; text-transform: uppercase;">Low Risk</div>
    </div>
    """, unsafe_allow_html=True)
with s3:
    st.markdown(f"""
    <div style="background: white; border-radius: 12px; padding: 1.25rem; border: 1px solid #e2e8f0; text-align: center;">
        <div style="font-size: 2rem; font-weight: 800; color: #f59e0b;">{suspicious}</div>
        <div style="font-size: 0.8rem; color: #64748b; font-weight: 600; text-transform: uppercase;">Suspicious</div>
    </div>
    """, unsafe_allow_html=True)
with s4:
    st.markdown(f"""
    <div style="background: white; border-radius: 12px; padding: 1.25rem; border: 1px solid #e2e8f0; text-align: center;">
        <div style="font-size: 2rem; font-weight: 800; color: #ef4444;">{high}</div>
        <div style="font-size: 0.8rem; color: #64748b; font-weight: 600; text-transform: uppercase;">High Risk</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown(
    f"<div style='text-align: center; color: #94a3b8; font-size: 0.85rem; padding: 2.5rem 1rem 1rem 1rem;'>"
    f"{APP_NAME} v{APP_VERSION} | AI-Powered QR Scam Detection Platform"
    f"</div>",
    unsafe_allow_html=True,
)
