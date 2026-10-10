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
    layout="wide",
)

css_path = project_root / "styles" / "main.css"
if css_path.exists():
    st.markdown(f"<style>{css_path.read_text()}</style>", unsafe_allow_html=True)


def card(title: str, content: str) -> str:
    return f"""
    <div style="background: #ffffff; border-radius: 10px; padding: 1.75rem;
                box-shadow: 0 1px 4px rgba(0,0,0,0.05); border: 1px solid #e2e8f0;
                margin-bottom: 1.5rem;">
        <h3 style="color: #0a1628; margin-top: 0; font-size: 1.25rem; font-weight: 700;">{title}</h3>
        <div style="color: #475569; line-height: 1.7; font-size: 0.95rem;">
            {content}
        </div>
    </div>
    """


def main() -> None:
    st.markdown(f"""
    <div style="margin-bottom: 2rem;">
        <h1 style="font-size: 2.2rem; font-weight: 700; color: #0a1628; margin-bottom: 0.25rem;">
            About {APP_NAME}
        </h1>
        <p style="color: #64748b; font-size: 1rem; margin: 0;">
            Platform Version {APP_VERSION}
        </p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown(card("Platform Overview", f"""
        <p><strong>{APP_NAME}</strong> is an AI-driven security inspection tool designed to examine QR code payloads before users visit external websites or authorize UPI transactions.</p>
        <p>Users can submit QR image files or utilize direct camera capture. The system decodes the payload, classifies its functional category, extracts 35 security-relevant lexical features, and runs supervised machine learning models to detect phishing attempts.</p>
        <p>For UPI payment strings, a dedicated rule-verification module parses transaction parameters and highlights structural anomalies or verification concerns.</p>
    """), unsafe_allow_html=True)

    st.markdown(card("Architecture & Workflow", """
        <ol style="padding-left: 1.2rem;">
            <li><strong>Capture:</strong> Accept PNG, JPG, or JPEG images with size and dimension validation.</li>
            <li><strong>Decoding:</strong> Extract content through OpenCV and pyzbar with adaptive preprocessing.</li>
            <li><strong>Payload Classification:</strong> Identify URL, UPI payment, contact card, or plain text schemes.</li>
            <li><strong>Risk Analysis:</strong>
                <ul>
                    <li>URLs are evaluated via trained XGBoost, Random Forest, and Logistic Regression pipelines using 35 lexical features.</li>
                    <li>UPI payments are checked for missing payees, abnormal amounts, or unrecognized parameters.</li>
                </ul>
            </li>
            <li><strong>Telemetry & History:</strong> Log sanitized results to local SQLite storage for auditability.</li>
        </ol>
    """), unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown(card("Technology Stack", """
            <table style="width: 100%; border-collapse: collapse;">
                <tr style="border-bottom: 1px solid #e2e8f0;">
                    <td style="padding: 0.5rem 0; font-weight: 600;">Frontend</td>
                    <td>Streamlit</td>
                </tr>
                <tr style="border-bottom: 1px solid #e2e8f0;">
                    <td style="padding: 0.5rem 0; font-weight: 600;">Programming Language</td>
                    <td>Python 3.11+</td>
                </tr>
                <tr style="border-bottom: 1px solid #e2e8f0;">
                    <td style="padding: 0.5rem 0; font-weight: 600;">Machine Learning</td>
                    <td>XGBoost, Scikit-learn, SHAP</td>
                </tr>
                <tr style="border-bottom: 1px solid #e2e8f0;">
                    <td style="padding: 0.5rem 0; font-weight: 600;">QR Computer Vision</td>
                    <td>OpenCV, pyzbar</td>
                </tr>
                <tr style="border-bottom: 1px solid #e2e8f0;">
                    <td style="padding: 0.5rem 0; font-weight: 600;">Data Visualization</td>
                    <td>Plotly</td>
                </tr>
                <tr style="border-bottom: 1px solid #e2e8f0;">
                    <td style="padding: 0.5rem 0; font-weight: 600;">Database Engine</td>
                    <td>SQLite</td>
                </tr>
                <tr>
                    <td style="padding: 0.5rem 0; font-weight: 600;">Quality Assurance</td>
                    <td>Pytest</td>
                </tr>
            </table>
        """), unsafe_allow_html=True)

    with col2:
        st.markdown(card("Directory Layout", """
            <pre style="background: #f8fafc; padding: 1rem; border-radius: 8px;
                        font-size: 0.82rem; overflow-x: auto; border: 1px solid #e2e8f0;">
QRShield/
|-- app.py              - Main Application
|-- pages/              - Application Views
|   |-- 1_Scanner.py
|   |-- 2_Dashboard.py
|   |-- 3_History.py
|   |-- 4_Model_Report.py
|   `-- 5_About.py
|-- src/
|   |-- ml/             - Model Training & Inference
|   |-- qr_processor/   - Multi-stage QR Decoder
|   |-- upi/            - UPI Rule Verifier
|   |-- database/       - SQLite Manager
|   `-- security/       - Sanitizer & SSRF Guards
|-- models/             - Model Artifacts
`-- tests/              - Pytest Suite
            </pre>
        """), unsafe_allow_html=True)

    st.markdown(card("Security Policies & Data Privacy", """
        <ul style="padding-left: 1.2rem;">
            <li>All decoded payloads are treated as <strong>untrusted input</strong>.</li>
            <li>No external URLs are executed, navigated, or fetched automatically.</li>
            <li>HTML escaping and string sanitization are applied across all views.</li>
            <li>SSRF defenses restrict resolution against RFC 1918 private IP ranges.</li>
            <li>All telemetry is stored locally on the client system; no third-party tracking is utilized.</li>
        </ul>
    """), unsafe_allow_html=True)

    st.markdown("""
    <div style="background: #fffbeb; border-left: 4px solid #f59e0b; border-radius: 8px;
                padding: 1.25rem 1.5rem; margin: 1.5rem 0;">
        <h4 style="color: #92400e; margin-top: 0;">Operational Advisory</h4>
        <p style="color: #78350f; margin: 0; line-height: 1.6; font-size: 0.92rem;">
            QRShield AI provides automated static pattern analysis and probabilistic classification. It does not provide absolute certification of destination security or payment authenticity. Always confirm sensitive transactions independently through established external communication channels.
        </p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown(f"""
    <div style="text-align: center; color: #94a3b8; font-size: 0.8rem; padding: 1.5rem 1rem;">
        {APP_NAME} v{APP_VERSION} | Python Machine Learning & Cybersecurity Research
    </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
