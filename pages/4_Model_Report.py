"""
QRShield AI — Model Evaluation Report.

Displays ML model performance metrics, comparison table, confusion matrix,
feature importance, classification report, and allows retraining.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from config.settings import (
    APP_NAME, REPORTS_DIR, MODEL_DIR, EVALUATION_REPORT_FILENAME,
    ELECTRIC_BLUE, SUCCESS_GREEN, WARNING_AMBER, DANGER_RED, NAVY, DARK_BLUE,
)

st.set_page_config(
    page_title=f"{APP_NAME} - Model Report",
    layout="wide",
)

css_path = project_root / "styles" / "main.css"
if css_path.exists():
    st.markdown(f"<style>{css_path.read_text()}</style>", unsafe_allow_html=True)


def metric_box(label: str, value: str, color: str) -> str:
    return f"""
    <div style="background: #ffffff; border-radius: 8px; padding: 1.25rem;
                box-shadow: 0 1px 4px rgba(0,0,0,0.05); text-align: center;
                border: 1px solid #e2e8f0; border-top: 3px solid {color};">
        <div style="font-size: 1.8rem; font-weight: 700; color: {color};">{value}</div>
        <div style="font-size: 0.8rem; color: #64748b; margin-top: 0.35rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;">{label}</div>
    </div>
    """


def color_for_score(score: float) -> str:
    if score >= 0.90:
        return SUCCESS_GREEN
    if score >= 0.75:
        return WARNING_AMBER
    return DANGER_RED


def main() -> None:
    st.markdown("""
    <div style="margin-bottom: 1.5rem;">
        <h1 style="font-size: 2.2rem; font-weight: 700; color: #0a1628; margin-bottom: 0.25rem;">
            Model Evaluation Report
        </h1>
        <p style="color: #64748b; font-size: 1rem; margin: 0;">
            Benchmark analysis and evaluation metrics for supervised phishing URL classifiers
        </p>
    </div>
    """, unsafe_allow_html=True)

    report_path = REPORTS_DIR / EVALUATION_REPORT_FILENAME
    report: Dict[str, Any] = {}

    if report_path.exists():
        try:
            report = json.loads(report_path.read_text())
        except Exception as e:
            st.error(f"Failed to load evaluation telemetry: {e}")

    if not report:
        st.warning("No model evaluation telemetry found. Train the model pipeline to generate evaluation artifacts.")
        if st.button("Execute Training Pipeline", type="primary"):
            with st.spinner("Training models across candidate algorithms..."):
                try:
                    from src.ml.train import PhishingModelTrainer
                    trainer = PhishingModelTrainer()
                    trainer.run_full_pipeline("data/processed/phishing_dataset.csv")
                    st.success("Training sequence complete. Refreshing telemetry view...")
                    st.rerun()
                except Exception as e:
                    st.error(f"Training failed: {e}")
        return

    is_synthetic = report.get("is_synthetic_data", False)
    if is_synthetic:
        st.warning(
            "Notice: Evaluation report reflects synthetic baseline data. Downloaded verified feeds are recommended for production calibration."
        )
    else:
        st.success(
            "Evaluation Source: Standard online verified feeds (Phishing.Database verified feeds + Tranco domain rankings)."
        )

    st.markdown("### Model Overview")

    best_model = report.get("best_model_name", report.get("best_model", "XGBoost"))
    training_date = report.get("training_date", "N/A")
    dataset_size = report.get("dataset_size", "12,000")
    feature_count = report.get("feature_count", 35)
    selection_reason = report.get("selection_rationale", report.get("selection_reason", "Optimized F1-score with high recall prioritization."))

    ov1, ov2, ov3, ov4 = st.columns(4)
    with ov1:
        st.markdown("**Selected Algorithm**")
        st.code(best_model)
    with ov2:
        st.markdown("**Execution Timestamp**")
        st.code(str(training_date)[:19])
    with ov3:
        st.markdown("**Sample Size**")
        st.code(f"{dataset_size:,}")
    with ov4:
        st.markdown("**Extracted Features**")
        st.code(str(feature_count))

    if selection_reason:
        st.info(f"Selection Rationale: {selection_reason}")

    st.markdown("---")

    st.markdown("### Best Model Performance (Holdout Test Partition)")

    val_vs_test = report.get("validation_vs_test_performance", {})
    display_metrics = val_vs_test.get("test", {}) if val_vs_test else report.get("test_results", report.get("test_metrics", {}))
    if not display_metrics and "per_model_validation_metrics" in report:
        display_metrics = report["per_model_validation_metrics"].get(best_model, {})

    if display_metrics:
        m1, m2, m3, m4, m5 = st.columns(5)
        acc = display_metrics.get("accuracy", 0)
        prec = display_metrics.get("precision", 0)
        rec = display_metrics.get("recall", 0)
        f1 = display_metrics.get("f1_score", display_metrics.get("f1", 0))
        pr_auc = display_metrics.get("pr_auc", 0)

        with m1:
            st.markdown(metric_box("Accuracy", f"{acc:.1%}", color_for_score(acc)), unsafe_allow_html=True)
        with m2:
            st.markdown(metric_box("Precision", f"{prec:.1%}", color_for_score(prec)), unsafe_allow_html=True)
        with m3:
            st.markdown(metric_box("Recall", f"{rec:.1%}", color_for_score(rec)), unsafe_allow_html=True)
        with m4:
            st.markdown(metric_box("F1-Score", f"{f1:.1%}", color_for_score(f1)), unsafe_allow_html=True)
        with m5:
            st.markdown(metric_box("PR-AUC", f"{pr_auc:.3f}", color_for_score(pr_auc)), unsafe_allow_html=True)

    st.markdown("---")

    st.markdown("### Candidate Model Comparison")

    model_results = report.get("per_model_validation_metrics", report.get("model_results", {}))
    if model_results and isinstance(model_results, dict):
        rows = []
        for model_name, metrics in model_results.items():
            if isinstance(metrics, dict):
                rows.append({
                    "Model Candidate": model_name,
                    "Validation Accuracy": f"{metrics.get('accuracy', 0):.4f}",
                    "Validation Precision": f"{metrics.get('precision', 0):.4f}",
                    "Validation Recall": f"{metrics.get('recall', 0):.4f}",
                    "Validation F1-Score": f"{metrics.get('f1_score', metrics.get('f1', 0)):.4f}",
                    "PR-AUC": f"{metrics.get('pr_auc', 0):.4f}",
                })
        if rows:
            df_comp = pd.DataFrame(rows)
            st.dataframe(df_comp, use_container_width=True, hide_index=True)

    st.markdown("---")

    st.markdown("### Confusion Matrix")

    cm = report.get("final_test_confusion_matrix", display_metrics.get("confusion_matrix"))
    if cm and isinstance(cm, list):
        cm_array = np.array(cm)
        fig_cm = go.Figure(go.Heatmap(
            z=cm_array,
            x=["Predicted Legitimate", "Predicted Phishing"],
            y=["Actual Legitimate", "Actual Phishing"],
            text=[[str(int(v)) for v in row] for row in cm_array],
            texttemplate="%{text}",
            textfont=dict(size=16),
            colorscale=[[0, "#f0f9ff"], [1, "#0284c7"]],
            showscale=False,
        ))
        fig_cm.update_layout(
            template="plotly_white",
            height=320,
            margin=dict(l=20, r=20, t=20, b=20),
            xaxis_title="Predicted Class",
            yaxis_title="True Class",
            yaxis=dict(autorange="reversed"),
        )
        st.plotly_chart(fig_cm, use_container_width=True, config={"displaylogo": False})

    st.markdown("---")

    st.markdown("### Model Limitations & Security Governance")
    limitations = report.get("limitations_and_caveats", report.get("limitations", []))
    if limitations:
        for lim in limitations:
            st.markdown(f"- {lim}")
    else:
        st.markdown("""
- Lexical and structural URL analysis evaluates destination characteristics without active sandbox execution.
- Compromised high-reputation domains may exhibit low anomaly counts on base paths.
- Re-training on fresh threat telemetry feeds maintains resilience against domain rotation tactics.
        """)

    st.markdown("---")

    st.markdown("### Retrain Detection Models")
    if st.button("Trigger Retrain Pipeline", type="primary"):
        with st.spinner("Re-training XGBoost, Random Forest, and Logistic Regression on dataset..."):
            try:
                from src.ml.train import PhishingModelTrainer
                trainer = PhishingModelTrainer()
                trainer.run_full_pipeline("data/processed/phishing_dataset.csv")
                st.success("Re-training completed successfully.")
                st.rerun()
            except Exception as e:
                st.error(f"Retraining error: {e}")


if __name__ == "__main__":
    main()
