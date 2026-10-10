"""
QRShield AI — About Page.

Project information, technology stack, architecture, security practices,
privacy policy, and disclaimers.
"""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from config.settings import APP_NAME, APP_VERSION, APP_DESCRIPTION

st.set_page_config(
    page_title=f"{APP_NAME} - About",
    page_icon="🛡️",
    layout="wide",
)

css_path = project_root / "styles" / "main.css"
if css_path.exists():
    st.markdown(f"<style>{css_path.read_text()}</style>", unsafe_allow_html=True)


def card(title: str, content: str) -> str:
    return f"""
    <div style="background: #ffffff; border-radius: 12px; padding: 2rem;
                box-shadow: 0 2px 10px rgba(0,0,0,0.05); border: 1px solid #e8edf2;
                margin-bottom: 1.5rem;">
        <h3 style="color: #0a1628; margin-top: 0; font-size: 1.3rem;">{title}</h3>
        <div style="color: #475569; line-height: 1.7; font-size: 0.95rem;">
            {content}
        </div>
    </div>
    """


def main() -> None:
    st.markdown(f"""
    <div style="margin-bottom: 2rem;">
        <h1 style="font-size: 2.2rem; font-weight: 700; color: #0a1628; margin-bottom: 0.25rem;">
            ℹ️ About {APP_NAME}
        </h1>
        <p style="color: #64748b; font-size: 1rem; margin: 0;">
            Version {APP_VERSION}
        </p>
    </div>
    """, unsafe_allow_html=True)

    # ── Project Description ──────────────────────────────────────
    st.markdown(card("🛡️ Project Overview", f"""
        <p><strong>{APP_NAME}</strong> is an AI-powered QR code security analysis tool that
        helps users inspect QR codes before visiting websites or making payments.</p>
        <p>Users can upload a QR image or scan one using a camera. The application decodes
        the content, classifies the content type, extracts security-related features, and
        estimates whether a URL is potentially associated with phishing.</p>
        <p>For UPI payment QR codes, a separate rule-based verification module identifies
        available payment information and flags verification concerns.</p>
    """), unsafe_allow_html=True)

    # ── How It Works ─────────────────────────────────────────────
    st.markdown(card("⚙️ How It Works", """
        <ol style="padding-left: 1.2rem;">
            <li><strong>Upload / Scan:</strong> Provide a QR code image (PNG, JPG, JPEG)
                or capture one using your camera.</li>
            <li><strong>Decode:</strong> The QR content is extracted using OpenCV and
                pyzbar with multi-pass image preprocessing for robust decoding.</li>
            <li><strong>Classify:</strong> Content is classified as URL, UPI payment,
                email, phone, vCard, WiFi config, or plain text.</li>
            <li><strong>Analyze:</strong>
                <ul>
                    <li>URLs are processed by the ML phishing detection pipeline (35 lexical features,
                        XGBoost / Random Forest / Logistic Regression comparison).</li>
                    <li>UPI payment payloads are analyzed by a rule-based verification module.</li>
                </ul>
            </li>
            <li><strong>Results:</strong> Risk level, indicators, feature explanations (SHAP),
                and actionable recommendations are displayed.</li>
            <li><strong>History:</strong> All scans are stored locally for review and analytics.</li>
        </ol>
    """), unsafe_allow_html=True)

    # ── Tech Stack ───────────────────────────────────────────────
    col1, col2 = st.columns(2)

    with col1:
        st.markdown(card("🛠️ Technology Stack", """
            <table style="width: 100%; border-collapse: collapse;">
                <tr style="border-bottom: 1px solid #e2e8f0;">
                    <td style="padding: 0.5rem 0; font-weight: 600;">Frontend</td>
                    <td>Streamlit + Custom CSS</td>
                </tr>
                <tr style="border-bottom: 1px solid #e2e8f0;">
                    <td style="padding: 0.5rem 0; font-weight: 600;">Language</td>
                    <td>Python 3.11+</td>
                </tr>
                <tr style="border-bottom: 1px solid #e2e8f0;">
                    <td style="padding: 0.5rem 0; font-weight: 600;">ML / AI</td>
                    <td>XGBoost, Scikit-learn, SHAP</td>
                </tr>
                <tr style="border-bottom: 1px solid #e2e8f0;">
                    <td style="padding: 0.5rem 0; font-weight: 600;">QR Decoding</td>
                    <td>OpenCV, pyzbar</td>
                </tr>
                <tr style="border-bottom: 1px solid #e2e8f0;">
                    <td style="padding: 0.5rem 0; font-weight: 600;">Visualization</td>
                    <td>Plotly</td>
                </tr>
                <tr style="border-bottom: 1px solid #e2e8f0;">
                    <td style="padding: 0.5rem 0; font-weight: 600;">Database</td>
                    <td>SQLite</td>
                </tr>
                <tr style="border-bottom: 1px solid #e2e8f0;">
                    <td style="padding: 0.5rem 0; font-weight: 600;">Testing</td>
                    <td>Pytest</td>
                </tr>
                <tr>
                    <td style="padding: 0.5rem 0; font-weight: 600;">Data</td>
                    <td>Pandas, NumPy</td>
                </tr>
            </table>
        """), unsafe_allow_html=True)

    with col2:
        st.markdown(card("🏗️ Architecture", """
            <pre style="background: #f8fafc; padding: 1rem; border-radius: 8px;
                        font-size: 0.8rem; overflow-x: auto; border: 1px solid #e2e8f0;">
QRShield/
├── app.py              ← Main entry point
├── pages/              ← Streamlit pages
│   ├── 1_Scanner.py
│   ├── 2_Dashboard.py
│   ├── 3_History.py
│   ├── 4_Model_Report.py
│   └── 5_About.py
├── src/
│   ├── ml/             ← ML pipeline
│   │   ├── feature_engineering.py
│   │   ├── train.py
│   │   ├── predict.py
│   │   └── explainer.py
│   ├── qr_processor/   ← QR decoding
│   ├── upi/            ← Payment verification
│   ├── database/       ← SQLite manager
│   └── security/       ← Input sanitization
├── config/             ← Settings
├── models/             ← Saved ML models
├── styles/             ← Custom CSS
└── tests/              ← Pytest suite
            </pre>
        """), unsafe_allow_html=True)

    # ── Security Practices ───────────────────────────────────────
    st.markdown(card("🔒 Security Practices", """
        <ul style="padding-left: 1.2rem;">
            <li>All QR content is treated as <strong>untrusted input</strong>.</li>
            <li>Decoded content is <strong>never automatically executed or opened</strong>.</li>
            <li>URLs are <strong>not fetched</strong> from the server — analysis is purely lexical.</li>
            <li>HTML escaping is applied before displaying any decoded content.</li>
            <li>File uploads are validated for size, format, and magic bytes.</li>
            <li>SSRF protection blocks requests to private/internal IP ranges.</li>
            <li>No API keys or secrets are stored in source code.</li>
            <li>UPI module <strong>never initiates payments</strong> or requests banking credentials.</li>
            <li>Database stores sanitized content; sensitive UPI fields are redacted.</li>
        </ul>
    """), unsafe_allow_html=True)

    # ── Privacy ──────────────────────────────────────────────────
    st.markdown(card("🔐 Privacy Policy", """
        <ul style="padding-left: 1.2rem;">
            <li>All data is stored <strong>locally</strong> in an SQLite database on your machine.</li>
            <li>No scan data is transmitted to external servers unless you explicitly configure
                an optional API integration.</li>
            <li>Sensitive UPI payment fields (PIN, OTP, account numbers) are automatically
                redacted before storage.</li>
            <li>Scan history can be searched, reviewed, and permanently deleted at any time.</li>
            <li>The "Clear All History" function removes all records with a confirmation step.</li>
        </ul>
    """), unsafe_allow_html=True)

    # ── Disclaimer ───────────────────────────────────────────────
    st.markdown("""
    <div style="background: #fff8e1; border-left: 4px solid #FFB300; border-radius: 8px;
                padding: 1.5rem 2rem; margin: 1.5rem 0;">
        <h3 style="color: #e65100; margin-top: 0;">⚠️ Important Disclaimer</h3>
        <p style="color: #5d4037; margin: 0; line-height: 1.7; font-size: 0.95rem;">
            <strong>QRShield AI provides automated risk assessment based on URL pattern analysis
            and machine learning.</strong> It does <strong>not guarantee</strong> the safety of
            any website, payment, or QR code content.<br><br>
            The ML model uses lexical URL features only and does not visit or load web pages.
            It cannot detect all types of phishing, especially those using legitimate-looking
            domains or recently compromised websites.<br><br>
            Always verify sensitive transactions and links independently through official channels.
            Do not rely solely on this tool for security decisions.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # ── Footer ───────────────────────────────────────────────────
    st.markdown(f"""
    <div style="text-align: center; color: #94a3b8; font-size: 0.8rem; padding: 2rem 1rem;">
        {APP_NAME} v{APP_VERSION} · Built with Python, Streamlit & XGBoost<br>
        Open-source project for educational and demonstration purposes
    </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
