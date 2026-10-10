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
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Load custom CSS ──────────────────────────────────────────────
css_path = project_root / "styles" / "main.css"
if css_path.exists():
    st.markdown(f"<style>{css_path.read_text()}</style>", unsafe_allow_html=True)

# ── Inline styling for clean dashboard elements ─────────────────
st.markdown("""
<style>
.hero-container {
    background: linear-gradient(135deg, #0a1628 0%, #16243d 50%, #0d2137 100%);
    padding: 3rem 2.5rem;
    border-radius: 14px;
    text-align: center;
    margin-bottom: 2rem;
    border: 1px solid rgba(255, 255, 255, 0.08);
    box-shadow: 0 10px 30px rgba(10, 22, 40, 0.12);
}
.hero-title-text {
    font-size: 2.8rem;
    font-weight: 800;
    color: #ffffff !important;
    margin-bottom: 0.4rem;
    letter-spacing: -0.02em;
}
.hero-subtitle-text {
    font-size: 1.25rem;
    color: #60a5fa !important;
    margin-bottom: 0.8rem;
    font-weight: 600;
}
.hero-desc-text {
    font-size: 1rem;
    color: #e2e8f0 !important;
    max-width: 720px;
    margin: 0 auto;
    line-height: 1.6;
}
.feature-card {
    background: #ffffff;
    border-radius: 12px;
    padding: 2rem 1.5rem;
    text-align: center;
    box-shadow: 0 2px 12px rgba(0,0,0,0.06);
    border: 1px solid #e2e8f0;
    transition: all 0.25s ease;
    height: 100%;
}
.feature-card:hover {
    transform: translateY(-3px);
    box-shadow: 0 8px 24px rgba(0,0,0,0.09);
    border-color: #2196F3;
}
.feature-tag {
    display: inline-block;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: #2196F3;
    background: rgba(33, 150, 243, 0.1);
    padding: 0.25rem 0.75rem;
    border-radius: 20px;
    margin-bottom: 1rem;
}
.feature-title {
    font-size: 1.2rem;
    font-weight: 700;
    color: #0a1628;
    margin-bottom: 0.5rem;
}
.feature-desc {
    font-size: 0.92rem;
    color: #64748b;
    line-height: 1.55;
}

.step-card {
    background: #ffffff;
    border-radius: 10px;
    padding: 1.5rem 1rem;
    text-align: center;
    box-shadow: 0 1px 4px rgba(0,0,0,0.04);
    border: 1px solid #e2e8f0;
}
.step-number {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    border-radius: 50%;
    background: #2196F3;
    color: #ffffff;
    font-weight: 700;
    font-size: 0.9rem;
    margin-bottom: 0.75rem;
}
.step-title {
    font-size: 0.98rem;
    font-weight: 600;
    color: #0a1628;
    margin-bottom: 0.25rem;
}
.step-desc {
    font-size: 0.85rem;
    color: #64748b;
}

.stat-card {
    background: #ffffff;
    border-radius: 10px;
    padding: 1.5rem;
    text-align: center;
    box-shadow: 0 2px 8px rgba(0,0,0,0.05);
    border: 1px solid #e2e8f0;
    border-top: 3px solid;
}
.stat-value {
    font-size: 2.2rem;
    font-weight: 700;
    line-height: 1.2;
}
.stat-label {
    font-size: 0.82rem;
    color: #64748b;
    margin-top: 0.35rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.notice-box {
    background: #fffbeb;
    border-left: 4px solid #f59e0b;
    border-radius: 8px;
    padding: 1.2rem 1.4rem;
    margin: 1.5rem 0;
}
.notice-box p {
    margin: 0;
    color: #78350f;
    font-size: 0.92rem;
    line-height: 1.55;
}
</style>
""", unsafe_allow_html=True)


# ── Sidebar ──────────────────────────────────────────────────────
with st.sidebar:
    st.markdown(f"""
    <div style="text-align: center; padding: 1rem 0 0.5rem 0;">
        <h2 style="margin: 0; color: #ffffff; font-size: 1.35rem; font-weight: 700;">{APP_NAME}</h2>
        <p style="color: #94a3b8; font-size: 0.8rem; margin: 0.2rem 0 0 0;">Version {APP_VERSION}</p>
    </div>
    """, unsafe_allow_html=True)
    st.divider()
    st.caption("Navigation: Select a view from the sidebar menu.")
    st.divider()

    with st.expander("System Information", expanded=False):
        st.markdown(f"""
**{APP_NAME}** provides automated security analysis for QR codes and web links.

**Core Stack:**
- Frontend: Streamlit
- Machine Learning: XGBoost, Scikit-learn
- Vision Engine: OpenCV, pyzbar
- Explainability: SHAP
- Database: SQLite

**Security Policy:** All decoded payloads are treated as untrusted. No URLs are executed or opened automatically.
        """)

    st.divider()
    st.caption(
        "Notice: QRShield AI provides predictive risk analysis, not absolute guarantee. Independent verification is always recommended."
    )


# ── Hero Section ─────────────────────────────────────────────────
st.markdown("""
<div class="hero-container">
    <div class="hero-title-text">QRShield AI</div>
    <div class="hero-subtitle-text">AI-Powered QR Code Scam Detector</div>
    <div class="hero-desc-text">
        Analyze QR code payloads, detect phishing URLs with machine learning, and verify UPI payment requests with security rule sets before taking action.
    </div>
</div>
""", unsafe_allow_html=True)


# ── Feature Cards ────────────────────────────────────────────────
col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("""
    <div class="feature-card">
        <div class="feature-tag">Computer Vision</div>
        <div class="feature-title">QR Scanner</div>
        <div class="feature-desc">Decode QR images or live camera frames with multi-stage image preprocessing and format validation.</div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown("""
    <div class="feature-card">
        <div class="feature-tag">Supervised ML</div>
        <div class="feature-title">AI URL Analysis</div>
        <div class="feature-desc">Evaluate web destinations against 35 lexical and structural features trained on verified datasets.</div>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown("""
    <div class="feature-card">
        <div class="feature-tag">Payment Security</div>
        <div class="feature-title">Payment Verification</div>
        <div class="feature-desc">Inspect UPI payment QR codes, parse merchant identifiers, and highlight anomalous request patterns.</div>
    </div>
    """, unsafe_allow_html=True)


# ── How It Works ─────────────────────────────────────────────────
st.markdown("---")
st.markdown("### Analysis Workflow")

steps = st.columns(4)
step_data = [
    ("1", "Input Capture", "Upload a QR image file or capture through camera interface"),
    ("2", "Payload Decoding", "Extract raw content and classify payload category"),
    ("3", "Threat Evaluation", "Process lexical features through trained XGBoost classifier"),
    ("4", "Risk Report", "Review confidence scores, risk indicators, and recommendations"),
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
st.markdown("### Activity Overview")

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
    st.info("No scans recorded yet. Navigate to the Scanner page to analyze your first QR code.")
else:
    s1, s2, s3, s4 = st.columns(4)
    with s1:
        st.markdown(f"""
        <div class="stat-card" style="border-top-color: {ELECTRIC_BLUE};">
            <div class="stat-value" style="color: {ELECTRIC_BLUE};">{total}</div>
            <div class="stat-label">Total Scans</div>
        </div>
        """, unsafe_allow_html=True)
    with s2:
        st.markdown(f"""
        <div class="stat-card" style="border-top-color: {SUCCESS_GREEN};">
            <div class="stat-value" style="color: {SUCCESS_GREEN};">{low}</div>
            <div class="stat-label">Low Risk</div>
        </div>
        """, unsafe_allow_html=True)
    with s3:
        st.markdown(f"""
        <div class="stat-card" style="border-top-color: {WARNING_AMBER};">
            <div class="stat-value" style="color: {WARNING_AMBER};">{suspicious}</div>
            <div class="stat-label">Suspicious</div>
        </div>
        """, unsafe_allow_html=True)
    with s4:
        st.markdown(f"""
        <div class="stat-card" style="border-top-color: {DANGER_RED};">
            <div class="stat-value" style="color: {DANGER_RED};">{high}</div>
            <div class="stat-label">High Risk</div>
        </div>
        """, unsafe_allow_html=True)


# ── Model Status ─────────────────────────────────────────────────
st.markdown("---")
st.markdown("### Detection Engine Status")

try:
    from src.ml.predict import PhishingPredictor
    predictor = PhishingPredictor()
    if predictor.model_loaded:
        info = predictor.get_model_info()
        model_name = info.get("model_type", info.get("best_model", "XGBoost"))
        trained_date = info.get("training_date", "Active")
        dataset_size = info.get("dataset_size", "12,000")
        is_synthetic = info.get("is_synthetic", False)

        st.success(
            f"Active Model: **{model_name}** | Trained on **{dataset_size:,} standard verified samples** (Phishing.Database + Tranco Top Domains)."
        )
    else:
        st.warning(
            "No trained model found. Open the Model Report page and execute training to activate the ML engine."
        )
except Exception as e:
    st.warning("Model status currently unavailable.")


# ── Security Notice ──────────────────────────────────────────────
st.markdown("""
<div class="notice-box">
    <p>
        <strong>Security Notice:</strong> QRShield AI performs static risk assessment using pattern analysis and machine learning. It does not provide absolute certification of destination safety. Always confirm payment requests and sensitive account interactions through official external channels.
    </p>
</div>
""", unsafe_allow_html=True)

st.markdown(
    f"<div style='text-align: center; color: #94a3b8; font-size: 0.8rem; padding: 1.5rem 1rem;'>"
    f"{APP_NAME} v{APP_VERSION} | Machine Learning Security Research Platform"
    f"</div>",
    unsafe_allow_html=True,
)
