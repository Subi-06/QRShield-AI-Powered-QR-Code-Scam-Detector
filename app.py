"""
QRShield AI — AI-Powered QR Code Scam Detector
Main application entry point and landing page.
"""

import streamlit as st
import sys
from pathlib import Path

# Ensure project root is on path
project_root = Path(__file__).parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from config.settings import (
    APP_NAME, APP_VERSION, APP_DESCRIPTION,
    NAVY, DARK_BLUE, LIGHT_BG, ELECTRIC_BLUE,
    SUCCESS_GREEN, WARNING_AMBER, DANGER_RED, MUTED_GRAY,
)

st.set_page_config(
    page_title=f"{APP_NAME} — AI-Powered QR Code Scam Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Load custom CSS ──────────────────────────────────────────────
css_path = project_root / "styles" / "main.css"
if css_path.exists():
    st.markdown(f"<style>{css_path.read_text()}</style>", unsafe_allow_html=True)

# ── Inline CSS for hero & cards ──────────────────────────────────
st.markdown("""
<style>
.hero-section {
    background: linear-gradient(135deg, #0a1628 0%, #1a2742 50%, #0d2137 100%);
    padding: 3.5rem 2.5rem;
    border-radius: 16px;
    text-align: center;
    margin-bottom: 2rem;
    position: relative;
    overflow: hidden;
}
.hero-section::before {
    content: '';
    position: absolute;
    top: -50%; left: -50%;
    width: 200%; height: 200%;
    background: radial-gradient(circle at 30% 50%, rgba(33,150,243,0.08) 0%, transparent 50%);
    pointer-events: none;
}
.hero-title {
    font-size: 3rem;
    font-weight: 800;
    color: #ffffff;
    margin-bottom: 0.5rem;
    letter-spacing: -0.5px;
}
.hero-subtitle {
    font-size: 1.3rem;
    color: #90caf9;
    margin-bottom: 1rem;
    font-weight: 500;
}
.hero-description {
    font-size: 1.05rem;
    color: #b0bec5;
    max-width: 700px;
    margin: 0 auto;
    line-height: 1.6;
}
.feature-card {
    background: #ffffff;
    border-radius: 12px;
    padding: 2rem 1.5rem;
    text-align: center;
    box-shadow: 0 2px 12px rgba(0,0,0,0.06);
    border: 1px solid #e8edf2;
    transition: all 0.3s ease;
    height: 100%;
}
.feature-card:hover {
    transform: translateY(-4px);
    box-shadow: 0 8px 25px rgba(0,0,0,0.1);
    border-color: #2196F3;
}
.feature-icon { font-size: 2.5rem; margin-bottom: 1rem; }
.feature-title { font-size: 1.15rem; font-weight: 700; color: #0a1628; margin-bottom: 0.5rem; }
.feature-desc { font-size: 0.95rem; color: #64748b; line-height: 1.5; }

.step-card {
    background: #ffffff;
    border-radius: 12px;
    padding: 1.5rem 1rem;
    text-align: center;
    box-shadow: 0 1px 6px rgba(0,0,0,0.04);
    border: 1px solid #e8edf2;
}
.step-number {
    display: inline-flex; align-items: center; justify-content: center;
    width: 36px; height: 36px; border-radius: 50%;
    background: #2196F3; color: white; font-weight: 700;
    font-size: 1rem; margin-bottom: 0.75rem;
}
.step-title { font-size: 1rem; font-weight: 600; color: #0a1628; margin-bottom: 0.25rem; }
.step-desc { font-size: 0.85rem; color: #64748b; }

.stat-card {
    background: #ffffff;
    border-radius: 12px;
    padding: 1.5rem;
    text-align: center;
    box-shadow: 0 2px 10px rgba(0,0,0,0.06);
    border-top: 3px solid;
}
.stat-value { font-size: 2.2rem; font-weight: 700; }
.stat-label { font-size: 0.85rem; color: #64748b; margin-top: 0.25rem; }

.notice-box {
    background: #fff8e1;
    border-left: 4px solid #FFB300;
    border-radius: 8px;
    padding: 1.25rem 1.5rem;
    margin: 1.5rem 0;
}
.notice-box p { margin: 0; color: #5d4037; font-size: 0.95rem; line-height: 1.5; }
</style>
""", unsafe_allow_html=True)


# ── Sidebar ──────────────────────────────────────────────────────
with st.sidebar:
    st.markdown(f"""
    <div style="text-align: center; padding: 1rem 0;">
        <div style="font-size: 2.5rem;">🛡️</div>
        <h2 style="margin: 0.25rem 0 0 0; color: #ffffff; font-size: 1.4rem;">{APP_NAME}</h2>
        <p style="color: #90caf9; font-size: 0.8rem; margin: 0;">v{APP_VERSION}</p>
    </div>
    """, unsafe_allow_html=True)
    st.divider()
    st.caption("Navigate using the sidebar pages above.")
    st.divider()

    with st.expander("ℹ️ About", expanded=False):
        st.markdown(f"""
**{APP_NAME}** is an AI-powered QR code security analyzer.

**Tech Stack:**
- Streamlit · Python 3.11+
- XGBoost · Scikit-learn
- OpenCV · pyzbar
- SHAP · Plotly · SQLite

**Security:** All QR content is treated as untrusted.
No URLs are opened automatically.
        """)

    st.divider()
    st.caption(
        "⚠️ QRShield AI provides risk assessment, "
        "not guaranteed protection. Always verify independently."
    )


# ── Hero Section ─────────────────────────────────────────────────
st.markdown("""
<div class="hero-section">
    <h1 class="hero-title">🛡️ QRShield AI</h1>
    <p class="hero-subtitle">AI-Powered QR Code Scam Detector</p>
    <p class="hero-description">
        Protect yourself from malicious QR codes. Upload or scan a QR code to
        analyze its content using advanced machine learning and security heuristics.
    </p>
</div>
""", unsafe_allow_html=True)


# ── Feature Cards ────────────────────────────────────────────────
col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("""
    <div class="feature-card">
        <div class="feature-icon">📷</div>
        <div class="feature-title">QR Scanner</div>
        <div class="feature-desc">Upload or scan QR codes for instant security analysis and content decoding</div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown("""
    <div class="feature-card">
        <div class="feature-icon">🤖</div>
        <div class="feature-title">AI Analysis</div>
        <div class="feature-desc">Machine learning powered phishing URL detection with explainable results</div>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown("""
    <div class="feature-card">
        <div class="feature-icon">💳</div>
        <div class="feature-title">Payment Verification</div>
        <div class="feature-desc">Verify UPI payment QR codes before transacting with rule-based checks</div>
    </div>
    """, unsafe_allow_html=True)


# ── How It Works ─────────────────────────────────────────────────
st.markdown("---")
st.markdown("### How It Works")

steps = st.columns(4)
step_data = [
    ("1", "Upload / Scan", "Provide a QR code image or use your camera"),
    ("2", "Decode", "QR content is extracted and classified"),
    ("3", "Analyze", "ML model and heuristics assess risk"),
    ("4", "Results", "Get risk level, indicators, and recommendations"),
]
for col, (num, title, desc) in zip(steps, step_data):
    with col:
        st.markdown(f"""
        <div class="step-card">
            <div class="step-number">{num}</div>
            <div class="step-title">{title}</div>
            <div class="step-desc">{desc}</div>
        </div>
        """, unsafe_allow_html=True)


# ── Quick Stats ──────────────────────────────────────────────────
st.markdown("---")
st.markdown("### Your Scanning Activity")

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

if total == 0:
    st.info("📊 Start scanning QR codes to see your statistics here. Navigate to the **Scanner** page to begin.")
else:
    s1, s2, s3, s4 = st.columns(4)
    with s1:
        st.markdown(f"""
        <div class="stat-card" style="border-top-color: {ELECTRIC_BLUE};">
            <div style="font-size: 1.5rem;">📊</div>
            <div class="stat-value" style="color: {ELECTRIC_BLUE};">{total}</div>
            <div class="stat-label">Total Scans</div>
        </div>
        """, unsafe_allow_html=True)
    with s2:
        st.markdown(f"""
        <div class="stat-card" style="border-top-color: {SUCCESS_GREEN};">
            <div style="font-size: 1.5rem;">✅</div>
            <div class="stat-value" style="color: {SUCCESS_GREEN};">{low}</div>
            <div class="stat-label">Low Risk</div>
        </div>
        """, unsafe_allow_html=True)
    with s3:
        st.markdown(f"""
        <div class="stat-card" style="border-top-color: {WARNING_AMBER};">
            <div style="font-size: 1.5rem;">⚠️</div>
            <div class="stat-value" style="color: {WARNING_AMBER};">{suspicious}</div>
            <div class="stat-label">Suspicious</div>
        </div>
        """, unsafe_allow_html=True)
    with s4:
        st.markdown(f"""
        <div class="stat-card" style="border-top-color: {DANGER_RED};">
            <div style="font-size: 1.5rem;">🚨</div>
            <div class="stat-value" style="color: {DANGER_RED};">{high}</div>
            <div class="stat-label">High Risk</div>
        </div>
        """, unsafe_allow_html=True)


# ── Model Status ─────────────────────────────────────────────────
st.markdown("---")
st.markdown("### Model Status")

try:
    from src.ml.predict import PhishingPredictor
    predictor = PhishingPredictor()
    if predictor.model_loaded:
        info = predictor.get_model_info()
        model_name = info.get("model_type", info.get("best_model", "Unknown"))
        trained_date = info.get("training_date", "Unknown")
        dataset_note = info.get("dataset_source", info.get("dataset_note", ""))
        st.success(f"✅ Model loaded: **{model_name}** | Trained: {trained_date}")
        if "synthetic" in str(dataset_note).lower():
            st.warning(
                "⚠️ Current model was trained on **synthetic data** for demonstration. "
                "Train with real phishing datasets for production accuracy."
            )
    else:
        st.warning(
            "⚠️ No trained model found. Go to **Model Report** page and click "
            "**Train Model** to create one. Heuristic fallback will be used in the meantime."
        )
except Exception:
    st.warning(
        "⚠️ Model not yet available. Navigate to the **Model Report** page to train."
    )


# ── Security Notice ──────────────────────────────────────────────
st.markdown("""
<div class="notice-box">
    <p>
        <strong>⚠️ Important:</strong> QRShield AI provides automated risk assessment
        based on URL pattern analysis and machine learning. It does <strong>not</strong>
        guarantee the safety of any website or payment. Always verify sensitive
        transactions independently through official channels.
    </p>
</div>
""", unsafe_allow_html=True)

st.markdown(
    f"<div style='text-align: center; color: #94a3b8; font-size: 0.8rem; padding: 1rem;'>"
    f"{APP_NAME} v{APP_VERSION} · Built with Streamlit & XGBoost"
    f"</div>",
    unsafe_allow_html=True,
)
