"""
QRShield AI — QR Code Scanner Page.

Upload a QR code image or use camera to scan, decode, and analyze content.
Routes URLs to ML phishing detection and UPI payloads to rule-based verification.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import streamlit as st
import numpy as np

project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from config.settings import (
    APP_NAME, NAVY, DARK_BLUE, ELECTRIC_BLUE,
    SUCCESS_GREEN, WARNING_AMBER, DANGER_RED, MUTED_GRAY,
    LOW_RISK_THRESHOLD, HIGH_RISK_THRESHOLD,
)
from src.qr_processor.decoder import QRDecoder, QRDecodeResult
from src.qr_processor.validator import ImageValidator
from src.security.sanitizer import InputSanitizer
from src.database.db_manager import DatabaseManager

# Conditional imports
try:
    from src.ml.predict import PhishingPredictor, PredictionResult
    _predictor = PhishingPredictor()
except Exception:
    _predictor = None
    PredictionResult = None

try:
    from src.ml.explainer import ModelExplainer, ExplanationResult
except Exception:
    ModelExplainer = None
    ExplanationResult = None

try:
    from src.upi.verifier import UPIVerifier
    _upi_verifier = UPIVerifier()
except Exception:
    _upi_verifier = None

try:
    import plotly.graph_objects as go
except ImportError:
    go = None

st.set_page_config(
    page_title=f"{APP_NAME} - Scanner",
    layout="wide",
)

css_path = project_root / "styles" / "main.css"
if css_path.exists():
    st.markdown(f"<style>{css_path.read_text()}</style>", unsafe_allow_html=True)

_decoder = QRDecoder()
_validator = ImageValidator()
_sanitizer = InputSanitizer()
_db = DatabaseManager()

RISK_THEME = {
    "low_risk":    (SUCCESS_GREEN, "LOW RISK"),
    "suspicious":  (WARNING_AMBER, "SUSPICIOUS"),
    "high_risk":   (DANGER_RED,    "HIGH RISK"),
}


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
        st.toast(f"Could not save scan: {e}")


def display_url_result(result) -> None:
    color, label = RISK_THEME.get(
        result.risk_category, (MUTED_GRAY, "UNKNOWN")
    )

    st.markdown(f"""
    <div style="background: {color}14; border-left: 5px solid {color};
                padding: 1.5rem 2rem; border-radius: 8px; margin-bottom: 1.5rem;">
        <h2 style="color: {color}; margin: 0; font-size: 1.6rem; letter-spacing: 0.04em;">{label}</h2>
        <p style="color: #475569; margin: 0.4rem 0 0 0; font-size: 0.95rem;">
            Estimated Phishing Probability:
            <strong>{result.probability:.1%}</strong>
            &nbsp;|&nbsp;
            {"Model Inference (XGBoost)" if result.is_model_prediction else "Heuristic Evaluation"}
        </p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### URL Structural Breakdown")
        from urllib.parse import urlparse
        parsed = urlparse(result.url)
        st.markdown(f"""
| Property | Value |
|:---------|:------|
| **Scheme** | `{_sanitizer.sanitize_text(parsed.scheme)}` |
| **Hostname** | `{_sanitizer.sanitize_text(parsed.hostname or '')}` |
| **Path** | `{_sanitizer.sanitize_text(parsed.path or '/')}` |
| **Query** | `{_sanitizer.sanitize_text(parsed.query[:80] + '...' if len(parsed.query) > 80 else parsed.query) if parsed.query else 'None'}` |
| **Port** | `{parsed.port or 'Default'}` |
        """)

    with col2:
        st.markdown("#### Identified Security Indicators")
        if result.top_risk_indicators:
            for indicator in result.top_risk_indicators:
                severity_color = DANGER_RED if any(
                    w in indicator.lower() for w in ["ip address", "http instead", "suspicious", "@ symbol"]
                ) else WARNING_AMBER
                st.markdown(
                    f'<div style="padding: 0.45rem 0.85rem; margin-bottom: 0.45rem; '
                    f'background: {severity_color}12; border-left: 3px solid {severity_color}; '
                    f'border-radius: 4px; font-size: 0.9rem; color: #1e293b;">'
                    f'{_sanitizer.sanitize_text(indicator)}</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.success("No anomalous lexical risk indicators detected.")

    st.markdown("#### Actionable Guidance")
    for rec in result.recommendations:
        st.info(rec)

    with st.expander("Detailed Feature Inspection", expanded=False):
        if result.features:
            notable = {k: v for k, v in result.features.items() if v != 0}
            if notable and go is not None:
                sorted_feats = sorted(notable.items(), key=lambda x: abs(x[1]), reverse=True)[:15]
                names = [f[0] for f in sorted_feats]
                values = [f[1] for f in sorted_feats]
                fig = go.Figure(go.Bar(
                    x=values, y=names, orientation="h",
                    marker_color=[DANGER_RED if v > 0.5 else ELECTRIC_BLUE for v in values],
                ))
                fig.update_layout(
                    title="Active Extracted Features",
                    template="plotly_white",
                    height=380,
                    yaxis=dict(autorange="reversed"),
                    margin=dict(l=10, r=10, t=40, b=10),
                )
                st.plotly_chart(fig, use_container_width=True)
            elif notable:
                st.json(notable)
            else:
                st.caption("All features returned default values.")

        if _predictor and _predictor.model_loaded and ModelExplainer is not None:
            try:
                explainer = ModelExplainer(
                    _predictor.model, _predictor.feature_names
                )
                explanation = explainer.explain_prediction(result.features)
                if explanation.explanation_available and explanation.human_readable:
                    st.markdown("**Model Explanatory Factors:**")
                    for line in explanation.human_readable[:8]:
                        st.write(f"- {line}")
            except Exception:
                st.caption("SHAP explanation unavailable for this prediction.")

    st.caption(result.disclaimer)

    _save_scan(
        content_type="url",
        content=result.url,
        prediction_category=result.risk_category,
        risk_level=result.risk_category,
        probability=result.probability,
        explanation="; ".join(result.top_risk_indicators[:5]),
        features=result.features,
        risk_indicators=result.top_risk_indicators,
    )


def display_upi_result(result) -> None:
    status_theme = {
        "verification_required": (ELECTRIC_BLUE, "VERIFICATION REQUIRED"),
        "info_incomplete":       (WARNING_AMBER,  "INFORMATION INCOMPLETE"),
        "potential_concern":     (DANGER_RED,     "POTENTIAL CONCERN DETECTED"),
    }
    color, label = status_theme.get(
        result.status, (MUTED_GRAY, result.status.replace("_", " ").upper())
    )

    st.markdown(f"""
    <div style="background: {color}14; border-left: 5px solid {color};
                padding: 1.5rem 2rem; border-radius: 8px; margin-bottom: 1.5rem;">
        <h2 style="color: {color}; margin: 0; font-size: 1.5rem;">{label}</h2>
        <p style="color: #475569; margin: 0.35rem 0 0 0; font-size: 0.9rem;">
            Unified Payments Interface (UPI) Request Verification
        </p>
    </div>
    """, unsafe_allow_html=True)

    info = result.payment_info
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("#### Extracted Payment Details")
        rows = [
            ("Payee Address (VPA)", info.payee_address or "Missing"),
            ("Payee Name", info.payee_name or "Not Specified"),
            ("Amount", f"INR {info.amount:,.2f}" if info.amount is not None else "Unspecified"),
            ("Currency", info.currency or "INR"),
        ]
        if info.transaction_ref:
            rows.append(("Transaction Ref", info.transaction_ref))
        if info.transaction_note:
            rows.append(("Note", _sanitizer.sanitize_text(info.transaction_note[:100])))

        md_table = "| Field | Value |\n|:------|:------|\n"
        for field, val in rows:
            md_table += f"| **{field}** | {_sanitizer.sanitize_text(str(val))} |\n"
        st.markdown(md_table)

    with col2:
        st.markdown("#### Rule Evaluation Findings")
        if result.concerns:
            for c in result.concerns:
                st.error(f"[Concern] {_sanitizer.sanitize_text(c)}")
        if result.warnings:
            for w in result.warnings:
                st.warning(f"[Warning] {_sanitizer.sanitize_text(w)}")
        if result.info_messages:
            for i in result.info_messages:
                st.info(f"[Notice] {_sanitizer.sanitize_text(i)}")
        if not result.concerns and not result.warnings and not result.info_messages:
            st.info("No structural discrepancies identified. Verify payee identity prior to PIN authorization.")

    st.markdown("#### Safe Handling Advice")
    for rec in result.recommendations:
        st.info(rec)

    st.caption(
        "Notice: Evaluation is based solely on static QR payload parameters. Never share banking PIN or OTP."
    )

    _save_scan(
        content_type="upi",
        content=info.raw_uri,
        prediction_category=result.status,
        risk_level=result.risk_level,
        explanation="; ".join(result.concerns[:3] + result.warnings[:3]),
    )


def display_other_content(content: str, content_type: str) -> None:
    st.markdown(f"""
    <div style="background: {ELECTRIC_BLUE}12; border-left: 5px solid {ELECTRIC_BLUE};
                padding: 1.5rem 2rem; border-radius: 8px; margin-bottom: 1.5rem;">
        <h2 style="color: {DARK_BLUE}; margin: 0; font-size: 1.5rem;">Payload Category: {content_type.upper()}</h2>
        <p style="color: #64748b; margin: 0.35rem 0 0 0;">Decoded raw QR content</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("**Decoded Content:**")
    st.code(_sanitizer.sanitize_for_display(content, max_length=2000), language=None)

    if content_type == "text" and (content.lower().startswith("http") or "://" in content):
        st.warning(
            "Notice: Text contains a URL string that did not match standard scheme conventions. Verify destination before navigating."
        )

    st.caption(
        "Content rendered as plain text. QRShield AI does not automatically invoke links or handlers."
    )

    _save_scan(
        content_type=content_type,
        content=content,
        prediction_category="informational",
        risk_level="informational",
    )


def main() -> None:
    st.markdown("""
    <div style="margin-bottom: 1.5rem;">
        <h1 style="font-size: 2.2rem; font-weight: 700; color: #0a1628; margin-bottom: 0.25rem;">
            QR Code Scanner
        </h1>
        <p style="color: #64748b; font-size: 1rem; margin: 0;">
            Upload an image or utilize camera capture to analyze payload security
        </p>
    </div>
    """, unsafe_allow_html=True)

    tab_upload, tab_camera = st.tabs(["Upload Image", "Camera Capture"])

    image_bytes: Optional[bytes] = None
    source_label = ""

    with tab_upload:
        uploaded_file = st.file_uploader(
            "Select QR code image file",
            type=["png", "jpg", "jpeg"],
            help="Supported formats: PNG, JPG, JPEG (maximum size 10 MB).",
        )
        if uploaded_file is not None:
            is_valid, error_msg, file_bytes = _validator.validate_upload(uploaded_file)
            if not is_valid:
                st.error(f"Validation failure: {error_msg}")
            else:
                image_bytes = file_bytes
                source_label = "uploaded image"
                col_img, col_info = st.columns([1, 2])
                with col_img:
                    st.image(image_bytes, caption="Input QR Code", width=250)
                with col_info:
                    st.markdown(f"""
                    | Property | Value |
                    |:---------|:------|
                    | **Filename** | `{_sanitizer.sanitize_text(uploaded_file.name)}` |
                    | **Size** | {len(image_bytes) / 1024:.1f} KB |
                    | **Format** | {_sanitizer.sanitize_text(uploaded_file.type or 'unknown')} |
                    """)

    with tab_camera:
        st.caption(
            "Camera input requires appropriate browser device permissions."
        )
        camera_photo = st.camera_input("Capture QR Code Frame")
        if camera_photo is not None:
            image_bytes = camera_photo.getvalue()
            source_label = "camera capture"

    if image_bytes is not None:
        st.markdown("---")

        with st.spinner("Decoding and processing QR payload..."):
            img_array = np.frombuffer(image_bytes, dtype=np.uint8)
            import cv2
            decoded_img = cv2.imdecode(img_array, cv2.IMREAD_COLOR)

            if decoded_img is not None:
                dim_valid, dim_msg = _validator.validate_dimensions(decoded_img)
                if not dim_valid:
                    st.error(f"Image dimension error: {dim_msg}")
                    return

            result: QRDecodeResult = _decoder.decode_from_image(image_bytes)

        if not result.success:
            st.error(
                f"Decoding unsuccessful: {_sanitizer.sanitize_text(result.error_message or 'No QR pattern identified.')}"
            )
            st.info(
                "Recommendation: Ensure clear lighting and minimal blur. Position the QR code fully within the frame."
            )
            return

        safe_content = _sanitizer.sanitize_for_display(result.content, max_length=500)
        st.markdown(f"""
        <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px;
                    padding: 1.25rem 1.5rem; margin-bottom: 1.5rem;">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
                <span style="background: {ELECTRIC_BLUE}14; color: {ELECTRIC_BLUE};
                             padding: 0.25rem 0.75rem; border-radius: 4px;
                             font-size: 0.82rem; font-weight: 700; letter-spacing: 0.05em;">
                    {result.content_type.upper() if result.content_type else "UNKNOWN"}
                </span>
                <span style="color: #64748b; font-size: 0.8rem;">
                    Decoded via {_sanitizer.sanitize_text(result.decoder_used or 'cv2')} ({source_label})
                </span>
            </div>
            <p style="margin: 0.75rem 0 0 0; font-family: monospace; font-size: 0.9rem;
                      color: #0f172a; word-break: break-all;">
                {safe_content}
            </p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("---")

        content_type = result.content_type or "text"

        if content_type == "url":
            st.markdown("### URL Phishing Analysis")
            if _predictor is not None:
                try:
                    prediction = _predictor.predict(result.content)
                    display_url_result(prediction)
                except Exception as e:
                    st.error(f"Analysis error: {e}")
                    display_other_content(result.content, content_type)
            else:
                st.warning("Detection model unavailable.")
                display_other_content(result.content, content_type)

        elif content_type == "upi":
            st.markdown("### UPI Payment Verification")
            if _upi_verifier is not None:
                try:
                    upi_result = _upi_verifier.verify(result.content)
                    display_upi_result(upi_result)
                except Exception as e:
                    st.error(f"UPI verification error: {e}")
                    display_other_content(result.content, content_type)
            else:
                st.warning("UPI verifier unavailable.")
                display_other_content(result.content, content_type)

        else:
            display_other_content(result.content, content_type)


if __name__ == "__main__":
    main()
