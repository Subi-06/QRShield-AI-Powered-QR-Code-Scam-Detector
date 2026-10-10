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
    page_icon="🛡️",
    layout="wide",
)

css_path = project_root / "styles" / "main.css"
if css_path.exists():
    st.markdown(f"<style>{css_path.read_text()}</style>", unsafe_allow_html=True)


def metric_box(label: str, value: str, color: str) -> str:
    return f"""
    <div style="background: #fff; border-radius: 10px; padding: 1.25rem;
                box-shadow: 0 1px 6px rgba(0,0,0,0.05); text-align: center;
                border-top: 3px solid {color};">
        <div style="font-size: 1.8rem; font-weight: 700; color: {color};">{value}</div>
        <div style="font-size: 0.85rem; color: #64748b; margin-top: 0.25rem;">{label}</div>
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
            🧠 Model Evaluation Report
        </h1>
        <p style="color: #64748b; font-size: 1rem; margin: 0;">
            Detailed performance metrics and analysis of the phishing detection model
        </p>
    </div>
    """, unsafe_allow_html=True)

    # ── Load report ──────────────────────────────────────────────
    report_path = REPORTS_DIR / EVALUATION_REPORT_FILENAME
    report: Dict[str, Any] = {}

    if report_path.exists():
        try:
            report = json.loads(report_path.read_text())
        except Exception as e:
            st.error(f"Failed to load report: {e}")

    if not report:
        st.warning(
            "⚠️ No model evaluation report found. "
            "Train the model first to see performance metrics."
        )
        st.markdown("""
        ### How to train the model

        Click the **Train Model** button below, or run from the terminal:

        ```bash
        cd d:\\QRShield
        python -m src.ml.train
        ```

        After training, this page will display:
        - Model accuracy, precision, recall, F1-score, and PR-AUC
        - Comparison of XGBoost, Random Forest, and Logistic Regression
        - Confusion matrix visualization
        - Feature importance chart
        - Model limitations and data source documentation
        """)

        if st.button("🚀 Train Model", type="primary"):
            with st.spinner("Training model — this may take 1–3 minutes..."):
                try:
                    from src.ml.train import PhishingModelTrainer
                    trainer = PhishingModelTrainer()
                    results = trainer.run_full_pipeline()
                    st.success("✅ Model trained successfully! Refreshing page...")
                    st.rerun()
                except Exception as e:
                    st.error(f"Training failed: {e}")
                    import traceback
                    st.code(traceback.format_exc())
        return

    # ══════════════════════════════════════════════════════════════
    # Report is available
    # ══════════════════════════════════════════════════════════════

    # ── Synthetic data warning ───────────────────────────────────
    is_synthetic = report.get("is_synthetic", False)
    dataset_source = report.get("dataset_source", report.get("dataset_note", ""))
    if is_synthetic or "synthetic" in str(dataset_source).lower():
        st.warning(
            "⚠️ **Synthetic Data Notice:** This model was trained on "
            "synthetically generated URLs for demonstration purposes. "
            "Performance metrics may not reflect real-world phishing detection accuracy. "
            "For production use, train with verified phishing URL datasets "
            "(e.g. UCI Phishing Websites, PhishTank)."
        )

    # ── Section 1: Model Overview ────────────────────────────────
    st.markdown("### 📋 Model Overview")

    best_model = report.get("best_model", report.get("model_type", "Unknown"))
    training_date = report.get("training_date", "Unknown")
    dataset_size = report.get("dataset_size", report.get("total_samples", "N/A"))
    feature_count = report.get("feature_count", report.get("num_features", "N/A"))
    selection_reason = report.get("selection_reason", "Best F1-score on validation set")

    ov1, ov2, ov3, ov4 = st.columns(4)
    with ov1:
        st.markdown(f"**Selected Model**")
        st.code(best_model)
    with ov2:
        st.markdown(f"**Training Date**")
        st.code(str(training_date)[:19])
    with ov3:
        st.markdown(f"**Dataset Size**")
        st.code(str(dataset_size))
    with ov4:
        st.markdown(f"**Features**")
        st.code(str(feature_count))

    if selection_reason:
        st.info(f"📌 Selection: {selection_reason}")

    st.markdown("---")

    # ── Section 2: Best Model Metrics ────────────────────────────
    st.markdown("### 📊 Best Model Performance")

    # Try to get test metrics first, then validation
    test_metrics = report.get("test_metrics", report.get("best_model_test", {}))
    val_metrics = report.get("validation_metrics", report.get("best_model_validation", {}))
    display_metrics = test_metrics if test_metrics else val_metrics
    metric_source = "Test Set" if test_metrics else "Validation Set"

    if display_metrics:
        st.caption(f"Evaluated on: {metric_source}")
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

    # ── Section 3: Model Comparison Table ────────────────────────
    st.markdown("### 🔄 Model Comparison")

    model_results = report.get("model_results", report.get("all_models", {}))
    if model_results and isinstance(model_results, dict):
        rows = []
        for model_name, metrics in model_results.items():
            if isinstance(metrics, dict):
                rows.append({
                    "Model": model_name,
                    "Accuracy": f"{metrics.get('accuracy', 0):.4f}",
                    "Precision": f"{metrics.get('precision', 0):.4f}",
                    "Recall": f"{metrics.get('recall', 0):.4f}",
                    "F1-Score": f"{metrics.get('f1_score', metrics.get('f1', 0)):.4f}",
                    "PR-AUC": f"{metrics.get('pr_auc', 0):.4f}",
                })
        if rows:
            df_comp = pd.DataFrame(rows)
            st.dataframe(df_comp, use_container_width=True, hide_index=True)
            st.caption(f"📌 Best model: **{best_model}** (highlighted)")

    st.markdown("---")

    # ── Section 4: Confusion Matrix ──────────────────────────────
    st.markdown("### 🔢 Confusion Matrix")

    cm = display_metrics.get("confusion_matrix") if display_metrics else None
    if cm and isinstance(cm, list):
        cm_array = np.array(cm)
        fig_cm = go.Figure(go.Heatmap(
            z=cm_array,
            x=["Predicted Legitimate", "Predicted Phishing"],
            y=["Actual Legitimate", "Actual Phishing"],
            text=[[str(int(v)) for v in row] for row in cm_array],
            texttemplate="%{text}",
            textfont=dict(size=18),
            colorscale=[[0, "#e3f2fd"], [1, "#1565c0"]],
            showscale=False,
        ))
        fig_cm.update_layout(
            template="plotly_white",
            height=350,
            margin=dict(l=20, r=20, t=20, b=20),
            xaxis_title="Predicted",
            yaxis_title="Actual",
            yaxis=dict(autorange="reversed"),
        )
        st.plotly_chart(fig_cm, use_container_width=True, config={"displaylogo": False})

        if len(cm_array) == 2:
            tn, fp = cm_array[0]
            fn, tp = cm_array[1]
            cm1, cm2, cm3, cm4 = st.columns(4)
            with cm1:
                st.metric("True Positives (TP)", int(tp))
            with cm2:
                st.metric("True Negatives (TN)", int(tn))
            with cm3:
                st.metric("False Positives (FP)", int(fp))
            with cm4:
                st.metric("False Negatives (FN)", int(fn))

    st.markdown("---")

    # ── Section 5: Feature Importance ────────────────────────────
    st.markdown("### 📈 Feature Importance")

    feature_importance = report.get("feature_importance", {})
    if feature_importance and isinstance(feature_importance, dict):
        sorted_fi = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)[:15]
        fi_names = [f[0] for f in sorted_fi]
        fi_values = [f[1] for f in sorted_fi]

        fig_fi = go.Figure(go.Bar(
            y=fi_names,
            x=fi_values,
            orientation="h",
            marker=dict(
                color=fi_values,
                colorscale=[[0, ELECTRIC_BLUE], [1, DANGER_RED]],
            ),
            text=[f"{v:.4f}" for v in fi_values],
            textposition="outside",
        ))
        fig_fi.update_layout(
            template="plotly_white",
            height=450,
            margin=dict(l=10, r=60, t=10, b=10),
            xaxis_title="Importance",
            yaxis=dict(autorange="reversed"),
        )
        st.plotly_chart(fig_fi, use_container_width=True, config={"displaylogo": False})

    st.markdown("---")

    # ── Section 6: Classification Report ─────────────────────────
    st.markdown("### 📝 Classification Report")

    class_report = display_metrics.get("classification_report", "")
    if class_report:
        if isinstance(class_report, str):
            st.code(class_report, language=None)
        elif isinstance(class_report, dict):
            st.json(class_report)

    st.markdown("---")

    # ── Section 7: Limitations ───────────────────────────────────
    st.markdown("### ⚠️ Limitations & Caveats")

    limitations = report.get("limitations", [])
    if limitations:
        for lim in limitations:
            st.markdown(f"• {lim}")
    else:
        st.markdown("""
• The model analyzes **URL lexical features only** — it does not visit or load web pages.
• It cannot detect phishing that uses legitimate-looking URLs or compromised real domains.
• Performance depends on training data quality and coverage.
• False positives (flagging legitimate URLs) and false negatives (missing phishing URLs) are both possible.
• The model should be regularly retrained with updated phishing data.
• URL risk prediction is **not a guarantee** of safety — always verify independently.
        """)

    st.markdown("""
    > **Why is high phishing recall important?**
    > Missing a phishing URL (false negative) can lead to credential theft, financial loss,
    > or malware infection. Therefore, the model prioritizes recall for the phishing class.
    > However, excessively high false positive rates erode user trust, so both metrics must
    > be balanced.
    """)

    st.markdown("---")

    # ── Section 8: Retrain ───────────────────────────────────────
    st.markdown("### 🔄 Retrain Model")

    if st.button("🚀 Train / Retrain Model", type="primary"):
        with st.spinner("Training model — this may take 1–3 minutes..."):
            try:
                from src.ml.train import PhishingModelTrainer
                trainer = PhishingModelTrainer()
                results = trainer.run_full_pipeline()
                st.success("✅ Model retrained successfully!")
                st.rerun()
            except Exception as e:
                st.error(f"Training failed: {e}")
                import traceback
                st.code(traceback.format_exc())


if __name__ == "__main__":
    main()
