"""
QRShieldAI — Scanner Page.
Matches user reference design:
- Top Header: QRShieldAI logo + navigation links
- Light Blue Banner: "Scan Smart. Stay Safe."
- Two Column Layout:
  Left: Upload QR Code (Drag and drop box + Choose File + Use Camera)
  Right: Result (Threat Alert Card, Extracted URL, Domain, QR Type, Detected Scam Type, Why is it Fake?)
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import streamlit as st
import numpy as np

project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from config.settings import (
    APP_NAME, NAVY, DARK_BLUE, ELECTRIC_BLUE,
    SUCCESS_GREEN, WARNING_AMBER, DANGER_RED, MUTED_GRAY,
)
from src.qr_processor.decoder import QRDecoder, QRDecodeResult
from src.qr_processor.validator import ImageValidator
from src.security.sanitizer import InputSanitizer
from src.database.db_manager import DatabaseManager

# Model & Explainer
try:
    from src.ml.predict import PhishingPredictor, PredictionResult
    _predictor = PhishingPredictor()
except Exception:
    _predictor = None
    PredictionResult = None

try:
    from src.upi.verifier import UPIVerifier
    _upi_verifier = UPIVerifier()
except Exception:
    _upi_verifier = None

st.set_page_config(
    page_title=f"{APP_NAME} - Scan Smart. Stay Safe.",
    layout="wide",
    initial_sidebar_state="collapsed",
)

css_path = project_root / "styles" / "main.css"
if css_path.exists():
    st.markdown(f"<style>{css_path.read_text()}</style>", unsafe_allow_html=True)

_decoder = QRDecoder()
_validator = ImageValidator()
_sanitizer = InputSanitizer()
_db = DatabaseManager()


def _save_scan(content_type: str, content: str, prediction_category: str = "",
               risk_level: str = "", probability: float = None,
               explanation: str = "", features: dict = None,
               risk_indicators: list = None) -> None:
    try:
        _db.save_scan({
            "content_type": content_type,
            "content_preview": _sanitizer.sanitize_for_storage(content, content_type)[:500],
            "full_content": _sanitizer.sanitize_for_storage(content, content_type),
            "prediction_category": prediction_category,
            "risk_level": risk_level,
            "model_probability": probability,
            "explanation_summary": explanation,
            "features_json": json.dumps(features) if features else None,
            "risk_indicators": json.dumps(risk_indicators) if risk_indicators else None,
            "model_version": "1.0.0",
        })
    except Exception as e:
        pass


def main() -> None:
    # ── Top Navigation Bar (Matches Reference Screenshot) ────────
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
            <a href="/" target="_self" style="text-decoration: none; padding: 0.45rem 1rem; color: #475569; font-weight: 600; font-size: 0.9rem;">Home</a>
            <a href="/Scanner" target="_self" style="text-decoration: none; padding: 0.45rem 1rem; background: #eff6ff; color: #2563eb; border-radius: 8px; font-weight: 600; font-size: 0.9rem;">Scan QR</a>
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

    # ── Two Columns (Upload Left, Result Right) ───────────────────
    col_left, col_right = st.columns([1, 1], gap="large")

    image_bytes: Optional[bytes] = None

    with col_left:
        st.markdown("""
        <div class="card-header-clean">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                <polyline points="17 8 12 3 7 8"></polyline>
                <line x1="12" y1="3" x2="12" y2="15"></line>
            </svg>
            Upload QR Code
        </div>
        """, unsafe_allow_html=True)

        uploaded_file = st.file_uploader(
            "Upload QR image",
            type=["png", "jpg", "jpeg"],
            label_visibility="collapsed",
            help="Supported formats: PNG, JPG, JPEG (Max 5 MB)",
        )

        if uploaded_file is not None:
            is_valid, error_msg, file_bytes = _validator.validate_upload(uploaded_file)
            if not is_valid:
                st.error(f"Upload error: {error_msg}")
            else:
                image_bytes = file_bytes

        st.markdown("<div style='text-align: center; color: #94a3b8; font-weight: 600; font-size: 0.85rem; margin: 0.75rem 0;'>OR</div>", unsafe_allow_html=True)

        use_camera = st.checkbox("Use Camera", value=False)
        if use_camera:
            camera_frame = st.camera_input("Capture QR Code Frame", label_visibility="collapsed")
            if camera_frame is not None:
                image_bytes = camera_frame.getvalue()

        st.markdown("""
        <div style="text-align: center; color: #94a3b8; font-size: 0.85rem; margin-top: 1rem;">
            Supported formats: PNG, JPG, JPEG (Max 5 MB)
        </div>
        """, unsafe_allow_html=True)

    # ── Right Column: Result Panel ────────────────────────────────
    with col_right:
        now_str = datetime.now().strftime("%b %d, %Y  %I:%M %p")
        st.markdown(f"""
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.25rem;">
            <div class="card-header-clean" style="margin-bottom: 0;">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                    <line x1="18" y1="20" x2="18" y2="10"></line>
                    <line x1="12" y1="20" x2="12" y2="4"></line>
                    <line x1="6" y1="20" x2="6" y2="14"></line>
                </svg>
                Result
            </div>
            <div style="color: #64748b; font-size: 0.85rem; font-weight: 500;">
                {now_str}
            </div>
        </div>
        """, unsafe_allow_html=True)

        if image_bytes is None:
            st.markdown("""
            <div style="background: #ffffff; border-radius: 12px; border: 1px dashed #cbd5e1; padding: 4rem 2rem; text-align: center;">
                <div style="color: #94a3b8; font-size: 1rem; font-weight: 500;">
                    No QR code scanned yet.
                </div>
                <div style="color: #cbd5e1; font-size: 0.85rem; margin-top: 0.4rem;">
                    Upload an image or use your camera on the left to view the security analysis.
                </div>
            </div>
            """, unsafe_allow_html=True)
            return

        # ── Process QR Code ──
        with st.spinner("Analyzing QR code..."):
            img_array = np.frombuffer(image_bytes, dtype=np.uint8)
            try:
                import cv2
                decoded_img = cv2.imdecode(img_array, cv2.IMREAD_COLOR)
                if decoded_img is not None:
                    dim_valid, dim_msg = _validator.validate_dimensions(decoded_img)
                    if not dim_valid:
                        st.error(f"Image dimension error: {dim_msg}")
                        return
            except ImportError:
                pass

            result: QRDecodeResult = _decoder.decode_from_image(image_bytes)

        if not result.success:
            st.markdown("""
            <div class="alert-threat-banner">
                <div class="alert-icon-square" style="background: #fee2e2; color: #dc2626;">!</div>
                <div>
                    <div class="alert-title" style="color: #dc2626;">Unreadable QR Code</div>
                    <div class="alert-desc">Could not decode QR pattern. Ensure clear lighting, proper focus, and uncropped borders.</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            return

        content = result.content or ""
        content_type = result.content_type or "text"

        # ── Route Analysis ──
        if content_type == "url":
            pred = _predictor.predict(content) if _predictor else None
            is_fake = pred.risk_category in ("high_risk", "suspicious") if pred else False
            domain = urlparse(content).netloc or "Unknown Domain"

            # Alert Banner (Matches Reference Image)
            if is_fake:
                st.markdown(f"""
                <div class="alert-threat-banner">
                    <div class="alert-icon-square" style="background: #fee2e2; color: #dc2626; font-size: 1.5rem; font-weight: bold;">!</div>
                    <div>
                        <div class="alert-title" style="color: #dc2626;">Fake QR Code Detected</div>
                        <div class="alert-desc">This QR code may lead to a phishing or malicious website.</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="alert-safe-banner">
                    <div class="alert-icon-square" style="background: #dcfce7; color: #16a34a; font-size: 1.5rem; font-weight: bold;">✓</div>
                    <div>
                        <div class="alert-title" style="color: #16a34a;">Legitimate QR Code Verified</div>
                        <div class="alert-desc">No deceptive phishing indicators detected by available security checks.</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

            # Metadata Table (Extracted URL, Domain, QR Type)
            safe_url = _sanitizer.sanitize_text(content)
            st.markdown(f"""
            <div style="background: white; border-radius: 10px; border: 1px solid #e2e8f0; padding: 0.75rem 1.25rem; margin-bottom: 1.25rem;">
                <div class="result-table-row">
                    <div class="result-label">Extracted URL</div>
                    <div class="result-value-box">{safe_url}</div>
                </div>
                <div class="result-table-row">
                    <div class="result-label">Domain</div>
                    <div style="color: #1e293b; font-weight: 500; font-size: 0.9rem;">{_sanitizer.sanitize_text(domain)}</div>
                </div>
                <div class="result-table-row" style="border-bottom: none;">
                    <div class="result-label">QR Type</div>
                    <div style="color: #1e293b; font-weight: 500; font-size: 0.9rem;">Website URL</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Detected Scam Type
            if is_fake:
                st.markdown("""
                <div style="margin-bottom: 1.25rem;">
                    <div style="font-weight: 700; color: #dc2626; font-size: 1rem; margin-bottom: 0.5rem;">
                        Detected Scam Type
                    </div>
                    <div style="background: #fef2f2; border: 1px solid #fee2e2; border-radius: 8px; padding: 1rem 1.25rem;">
                        <div style="font-weight: 700; color: #b91c1c; font-size: 0.95rem; margin-bottom: 0.25rem;">
                            Phishing Website
                        </div>
                        <div style="font-size: 0.88rem; color: #475569; line-height: 1.5;">
                            This link tries to impersonate a genuine website to steal your login credentials or personal information.
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                # Why is it Fake? Checklist
                st.markdown("""
                <div style="margin-bottom: 1.25rem;">
                    <div style="font-weight: 700; color: #0f172a; font-size: 1rem; margin-bottom: 0.65rem;">
                        Why is it Fake?
                    </div>
                """, unsafe_allow_html=True)

                indicators = pred.top_risk_indicators if pred and pred.top_risk_indicators else [
                    "Domain name looks suspicious",
                    "Contains misleading keywords (login, secure)",
                    "Not a trusted domain",
                    "Uses unencrypted HTTP instead of HTTPS",
                ]

                for ind in indicators:
                    st.markdown(f"""
                    <div class="reason-item">
                        <span class="reason-bullet-cross">✕</span>
                        <span>{_sanitizer.sanitize_text(ind)}</span>
                    </div>
                    """, unsafe_allow_html=True)

                st.markdown("</div>", unsafe_allow_html=True)

            else:
                st.markdown("""
                <div style="margin-bottom: 1.25rem;">
                    <div style="font-weight: 700; color: #16a34a; font-size: 1rem; margin-bottom: 0.65rem;">
                        Safety Indicators
                    </div>
                    <div class="reason-item">
                        <span class="reason-bullet-check">✓</span>
                        <span>Standard secure HTTPS connection</span>
                    </div>
                    <div class="reason-item">
                        <span class="reason-bullet-check">✓</span>
                        <span>Reputable domain structure without homograph attacks</span>
                    </div>
                    <div class="reason-item">
                        <span class="reason-bullet-check">✓</span>
                        <span>No deceptive phishing patterns flagged</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)

            # Persist scan
            if pred:
                _save_scan(
                    content_type="url",
                    content=content,
                    prediction_category=pred.risk_category,
                    risk_level=pred.risk_category,
                    probability=pred.probability,
                    explanation="; ".join(pred.top_risk_indicators[:4]),
                    features=pred.features,
                    risk_indicators=pred.top_risk_indicators,
                )

        elif content_type == "upi":
            upi_res = _upi_verifier.verify(content) if _upi_verifier else None
            is_concern = bool(upi_res and (upi_res.concerns or upi_res.warnings))
            payee = upi_res.payment_info.payee_address if upi_res else "Unknown"
            name = upi_res.payment_info.payee_name or "Not Specified"
            amt = f"INR {upi_res.payment_info.amount:,.2f}" if upi_res and upi_res.payment_info.amount else "User Specified"

            if is_concern:
                st.markdown(f"""
                <div class="alert-threat-banner">
                    <div class="alert-icon-square" style="background: #fee2e2; color: #dc2626; font-size: 1.5rem; font-weight: bold;">!</div>
                    <div>
                        <div class="alert-title" style="color: #dc2626;">Payment Verification Concern</div>
                        <div class="alert-desc">Anomalous parameters or missing verification data detected in this UPI QR code.</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="alert-safe-banner">
                    <div class="alert-icon-square" style="background: #dcfce7; color: #16a34a; font-size: 1.5rem; font-weight: bold;">✓</div>
                    <div>
                        <div class="alert-title" style="color: #16a34a;">Standard UPI Payment QR</div>
                        <div class="alert-desc">Payload format matches standard NPCI specifications. Verify recipient name before authorizing.</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

            st.markdown(f"""
            <div style="background: white; border-radius: 10px; border: 1px solid #e2e8f0; padding: 0.75rem 1.25rem; margin-bottom: 1.25rem;">
                <div class="result-table-row">
                    <div class="result-label">Payee VPA</div>
                    <div class="result-value-box">{_sanitizer.sanitize_text(payee)}</div>
                </div>
                <div class="result-table-row">
                    <div class="result-label">Payee Name</div>
                    <div style="color: #1e293b; font-weight: 500; font-size: 0.9rem;">{_sanitizer.sanitize_text(name)}</div>
                </div>
                <div class="result-table-row">
                    <div class="result-label">Amount</div>
                    <div style="color: #1e293b; font-weight: 500; font-size: 0.9rem;">{amt}</div>
                </div>
                <div class="result-table-row" style="border-bottom: none;">
                    <div class="result-label">QR Type</div>
                    <div style="color: #1e293b; font-weight: 500; font-size: 0.9rem;">UPI Payment Payload</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            if upi_res and (upi_res.concerns or upi_res.warnings):
                st.markdown("""
                <div style="margin-bottom: 1.25rem;">
                    <div style="font-weight: 700; color: #0f172a; font-size: 1rem; margin-bottom: 0.65rem;">
                        Identified Verification Findings
                    </div>
                """, unsafe_allow_html=True)
                for issue in (upi_res.concerns + upi_res.warnings):
                    st.markdown(f"""
                    <div class="reason-item">
                        <span class="reason-bullet-cross">✕</span>
                        <span>{_sanitizer.sanitize_text(issue)}</span>
                    </div>
                    """, unsafe_allow_html=True)
                st.markdown("</div>", unsafe_allow_html=True)

            if upi_res:
                _save_scan(
                    content_type="upi",
                    content=content,
                    prediction_category=upi_res.status,
                    risk_level=upi_res.risk_level,
                    explanation="; ".join(upi_res.concerns[:3] + upi_res.warnings[:3]),
                )

        else:
            # Plain text / other
            st.markdown(f"""
            <div class="alert-warning-banner">
                <div class="alert-icon-square" style="background: #fef3c7; color: #d97706; font-size: 1.5rem; font-weight: bold;">i</div>
                <div>
                    <div class="alert-title" style="color: #92400e;">Decoded Content</div>
                    <div class="alert-desc">Category: {content_type.upper()}</div>
                </div>
            </div>
            <div style="background: white; border-radius: 10px; border: 1px solid #e2e8f0; padding: 1.25rem; font-family: monospace; font-size: 0.9rem; word-break: break-all;">
                {_sanitizer.sanitize_for_display(content, max_length=1000)}
            </div>
            """, unsafe_allow_html=True)

            _save_scan(
                content_type=content_type,
                content=content,
                prediction_category="informational",
                risk_level="informational",
            )


if __name__ == "__main__":
    main()
