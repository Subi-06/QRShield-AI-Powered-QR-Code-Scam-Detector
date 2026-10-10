"""ML explainability module for QRShield AI.

Provides model interpretation using SHAP (SHapley Additive exPlanations)
along with robust fallbacks to global feature importance and heuristic
interpretability for phishing detection decisions.
"""

from dataclasses import dataclass
import logging
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    shap = None
    SHAP_AVAILABLE = False

# Ensure imports work from project root or direct invocation
try:
    from src.ml.feature_engineering import FEATURE_NAMES, get_feature_descriptions
except ImportError:
    _project_root = str(Path(__file__).resolve().parent.parent.parent)
    if _project_root not in sys.path:
        sys.path.insert(0, _project_root)
    from src.ml.feature_engineering import FEATURE_NAMES, get_feature_descriptions

logger = logging.getLogger(__name__)


@dataclass
class ExplanationResult:
    """Dataclass encapsulating feature-level explanation details for an inference."""

    shap_values: Optional[np.ndarray]
    feature_importance: List[Tuple[str, float]]  # sorted by abs importance
    top_positive_features: List[Tuple[str, float]]  # pushing toward phishing
    top_negative_features: List[Tuple[str, float]]  # pushing toward legitimate
    explanation_available: bool
    explanation_method: str  # 'shap', 'feature_importance', 'heuristic'
    human_readable: List[str]  # Human-readable explanations


class ModelExplainer:
    """Explainer for ML models providing SHAP values and human-friendly narratives."""

    def __init__(
        self,
        model: Optional[Any],
        feature_names: Optional[List[str]] = None,
    ) -> None:
        """Initialize the model explainer.

        Args:
            model: Trained classifier model (e.g., XGBoost, RandomForest, LightGBM).
            feature_names: List of feature names matching model training columns.
        """
        self.model: Optional[Any] = model
        self.feature_names: List[str] = (
            list(feature_names) if feature_names else list(FEATURE_NAMES)
        )
        self.feature_descriptions: Dict[str, str] = get_feature_descriptions()
        self.explainer: Optional[Any] = None
        self.shap_available: bool = SHAP_AVAILABLE

        self._init_shap_explainer()

    def _init_shap_explainer(self) -> None:
        """Initialize SHAP explainer instance safely handling exceptions."""
        if not self.shap_available or self.model is None or shap is None:
            self.explainer = None
            return

        try:
            # TreeExplainer is ideal for tree-based models (XGBoost, CatBoost, sklearn Trees)
            self.explainer = shap.TreeExplainer(self.model)
            logger.info("Initialized SHAP TreeExplainer successfully.")
        except Exception as exc:
            logger.warning("TreeExplainer initialization failed: %s. Attempting fallback.", exc)
            try:
                # KernelExplainer fallback without background data can fail or require summary
                self.explainer = shap.Explainer(self.model)
                logger.info("Initialized generic SHAP Explainer fallback.")
            except Exception as inner_exc:
                logger.warning("Could not initialize SHAP Explainer fallback: %s", inner_exc)
                self.explainer = None

    def get_global_feature_importance(self) -> List[Tuple[str, float]]:
        """Return global feature importances sorted descending by importance.

        Returns:
            List[Tuple[str, float]]: (feature_name, importance_score) pairs.
        """
        if self.model is None:
            return []

        importances: Optional[np.ndarray] = None

        if hasattr(self.model, "feature_importances_"):
            importances = np.array(self.model.feature_importances_, dtype=float)
        elif hasattr(self.model, "coef_"):
            coef = np.array(self.model.coef_, dtype=float)
            if coef.ndim > 1:
                importances = np.abs(coef[0])
            else:
                importances = np.abs(coef)

        if importances is not None and len(importances) == len(self.feature_names):
            pairs = list(zip(self.feature_names, [float(v) for v in importances]))
            pairs.sort(key=lambda item: item[1], reverse=True)
            return pairs

        return []

    def _generate_human_readable(
        self,
        feature_name: str,
        feature_value: float,
        shap_value: float,
    ) -> str:
        """Convert a technical feature name, value, and SHAP attribution into plain English.

        Args:
            feature_name: Name of the feature.
            feature_value: Numeric value observed in the URL.
            shap_value: Attribution score (positive: phishing, negative: legitimate).

        Returns:
            str: Clear, user-friendly security narrative.
        """
        is_positive = shap_value > 0

        # Lexical & Security Specific Explanations
        if feature_name == "is_https":
            if feature_value == 0:
                return "The URL does not use HTTPS, which is common in phishing sites."
            return "The URL uses secure HTTPS encryption, reducing immediate risk."

        if feature_name == "url_length":
            if feature_value > 75:
                return (
                    f"The unusually long URL length ({int(feature_value)} characters) "
                    "is a suspicious indicator often used to obscure malicious parameters."
                )
            return "The URL length is concise and typical of standard legitimate addresses."

        if feature_name == "has_ip_address":
            if feature_value == 1:
                return (
                    "An IP address is used directly in place of a domain name, "
                    "a common phishing tactic to bypass domain registration checks."
                )
            return "Uses a standard registered domain name rather than a raw IP address."

        if feature_name in ("has_suspicious_keyword", "num_suspicious_keywords"):
            if feature_value > 0:
                return (
                    f"The URL contains {int(feature_value)} keyword(s) commonly associated "
                    "with credential theft, banking lures, or urgent verification."
                )
            return "No deceptive authentication or banking keywords detected in URL."

        if feature_name == "is_url_shortener":
            if feature_value == 1:
                return (
                    "A known URL shortening service was detected, which conceals "
                    "the true destination domain."
                )
            return "Direct destination domain is visible with no URL shortening services used."

        if feature_name == "num_subdomains":
            if feature_value > 2:
                return (
                    f"Multiple subdomain levels ({int(feature_value)}) were detected, "
                    "frequently used to mimic authentic organization domains."
                )
            return "Subdomain hierarchy is standard and low complexity."

        if feature_name in ("has_at_sign", "num_at_signs"):
            if feature_value > 0:
                return (
                    "The URL contains an '@' symbol, which can mislead web browsers "
                    "into ignoring the initial hostname prefix."
                )
            return "No misleading '@' credential delimiters present in URL."

        if feature_name == "special_char_ratio":
            if feature_value > 0.2:
                return (
                    f"High concentration of special characters ({feature_value:.1%}) "
                    "indicates potential parameter obfuscation."
                )
            return "Normal proportion of standard alphanumeric characters in URL."

        if feature_name == "url_entropy":
            if feature_value > 4.5:
                return (
                    f"High character entropy ({feature_value:.2f}) indicates potential "
                    "randomly generated or obfuscated character sequences."
                )
            return "Natural character distribution consistent with authentic domain patterns."

        if feature_name == "path_has_double_slash":
            if feature_value == 1:
                return "The URL path contains '//' which can be exploited for open URL redirects."
            return "Standard URL path formatting without redundant slashes."

        if feature_name == "has_encoded_chars":
            if feature_value == 1:
                return (
                    "The URL contains percent-encoded hex sequences (%xx), commonly "
                    "employed to evade pattern-based security filters."
                )
            return "Standard plain-text URL without obfuscated hex encoding."

        if feature_name == "has_port":
            if feature_value == 1:
                return "The URL connects via a non-standard port rather than default web ports (80/443)."
            return "Uses standard default web communication ports."

        if feature_name in ("digit_ratio_url", "digit_ratio_hostname"):
            if feature_value > 0.25:
                return (
                    f"Unusually high digit ratio ({feature_value:.1%}) suggests "
                    "machine-generated or disposable domains."
                )
            return "Typical balance of alphabetic characters and numbers."

        # Generic Fallback with context
        desc = self.feature_descriptions.get(feature_name, feature_name.replace("_", " "))
        direction = "increased phishing risk" if is_positive else "supported legitimate classification"
        return f"{desc.capitalize()} (value: {feature_value:.2f}) {direction}."

    def _explain_with_shap(
        self,
        features_df: pd.DataFrame,
        features_dict: Dict[str, float],
    ) -> ExplanationResult:
        """Compute SHAP values and assemble the ExplanationResult.

        Args:
            features_df: DataFrame containing a single row with exact training columns.
            features_dict: Original feature values mapped by feature name.

        Returns:
            ExplanationResult: Full SHAP breakdown.
        """
        assert self.explainer is not None

        raw_shap = self.explainer.shap_values(features_df)

        # Handle various SHAP output formats (list for multiclass/binary, 2D array, 3D array)
        if isinstance(raw_shap, list):
            # Binary classification in TreeExplainer often returns [class_0, class_1]
            if len(raw_shap) >= 2:
                values_1d = np.array(raw_shap[1][0], dtype=float)
            else:
                values_1d = np.array(raw_shap[0][0], dtype=float)
        elif hasattr(raw_shap, "values"):
            # SHAP Explanation object
            exp_val = raw_shap.values
            if exp_val.ndim == 3:
                values_1d = np.array(exp_val[0, :, 1], dtype=float)
            elif exp_val.ndim == 2:
                values_1d = np.array(exp_val[0], dtype=float)
            else:
                values_1d = np.array(exp_val, dtype=float).flatten()
        elif isinstance(raw_shap, np.ndarray):
            if raw_shap.ndim == 3:
                # Shape (samples, features, classes)
                values_1d = np.array(raw_shap[0, :, 1], dtype=float)
            elif raw_shap.ndim == 2:
                values_1d = np.array(raw_shap[0], dtype=float)
            else:
                values_1d = np.array(raw_shap, dtype=float).flatten()
        else:
            raise ValueError(f"Unsupported SHAP values type: {type(raw_shap)}")

        col_names = list(features_df.columns)
        all_pairs = list(zip(col_names, [float(v) for v in values_1d]))

        # Sort all by absolute impact
        feature_importance = sorted(all_pairs, key=lambda item: abs(item[1]), reverse=True)

        # Top 5 pushing toward phishing (positive SHAP)
        positive_features = [item for item in all_pairs if item[1] > 0]
        positive_features.sort(key=lambda item: item[1], reverse=True)
        top_positive = positive_features[:5]

        # Top 5 pushing toward legitimate (negative SHAP)
        negative_features = [item for item in all_pairs if item[1] < 0]
        negative_features.sort(key=lambda item: item[1], reverse=False)  # strongest negative first
        top_negative = negative_features[:5]

        # Generate human-readable explanations for the top most influential features
        top_influential = feature_importance[:5]
        human_readable: List[str] = []
        for feat_name, shap_val in top_influential:
            val = float(features_dict.get(feat_name, 0.0))
            human_readable.append(self._generate_human_readable(feat_name, val, shap_val))

        return ExplanationResult(
            shap_values=values_1d,
            feature_importance=feature_importance,
            top_positive_features=top_positive,
            top_negative_features=top_negative,
            explanation_available=True,
            explanation_method="shap",
            human_readable=human_readable,
        )

    def _explain_fallback(self, features_dict: Dict[str, float]) -> ExplanationResult:
        """Provide fallback explanation using global feature importance or heuristics.

        Args:
            features_dict: Original feature values mapped by feature name.

        Returns:
            ExplanationResult: Fallback explanation.
        """
        global_importance = self.get_global_feature_importance()
        human_readable: List[str] = []

        if global_importance:
            explanation_method = "feature_importance"
            # Build pseudo-direction based on feature values
            top_positive: List[Tuple[str, float]] = []
            top_negative: List[Tuple[str, float]] = []

            for feat, imp in global_importance:
                val = float(features_dict.get(feat, 0.0))
                # Check known phishing polarity
                if feat == "is_https":
                    is_suspicious = val == 0
                elif "num_" in feat or "has_" in feat or "is_" in feat or "ratio" in feat or "entropy" in feat:
                    is_suspicious = val > 0
                else:
                    is_suspicious = False

                if is_suspicious:
                    top_positive.append((feat, imp))
                else:
                    top_negative.append((feat, -imp))

            top_positive = top_positive[:5]
            top_negative = top_negative[:5]

            for feat, imp in global_importance[:5]:
                val = float(features_dict.get(feat, 0.0))
                direction = 1.0 if any(feat == item[0] for item in top_positive) else -1.0
                human_readable.append(self._generate_human_readable(feat, val, direction * imp))

            return ExplanationResult(
                shap_values=None,
                feature_importance=global_importance,
                top_positive_features=top_positive,
                top_negative_features=top_negative,
                explanation_available=True,
                explanation_method=explanation_method,
                human_readable=human_readable,
            )

        # Pure heuristic fallback
        explanation_method = "heuristic"
        heuristic_positive: List[Tuple[str, float]] = []
        heuristic_negative: List[Tuple[str, float]] = []

        for feat in self.feature_names:
            val = float(features_dict.get(feat, 0.0))
            if feat == "is_https":
                if val == 0:
                    heuristic_positive.append((feat, 0.5))
                else:
                    heuristic_negative.append((feat, -0.5))
            elif feat in ("has_ip_address", "has_at_sign") and val == 1:
                heuristic_positive.append((feat, 0.8))
            elif feat in ("has_suspicious_keyword", "is_url_shortener") and val == 1:
                heuristic_positive.append((feat, 0.6))
            elif feat == "url_length" and val > 75:
                heuristic_positive.append((feat, 0.4))
            elif feat == "url_entropy" and val > 4.5:
                heuristic_positive.append((feat, 0.4))

        heuristic_positive.sort(key=lambda item: item[1], reverse=True)
        heuristic_negative.sort(key=lambda item: item[1])

        combined = heuristic_positive + [(f, abs(v)) for f, v in heuristic_negative]
        combined.sort(key=lambda item: item[1], reverse=True)

        for feat, score in combined[:5]:
            val = float(features_dict.get(feat, 0.0))
            is_pos = any(feat == item[0] for item in heuristic_positive)
            shap_sign = 1.0 if is_pos else -1.0
            human_readable.append(self._generate_human_readable(feat, val, shap_sign * score))

        if not human_readable:
            human_readable.append("Standard URL structure with no detected risk anomalies.")

        return ExplanationResult(
            shap_values=None,
            feature_importance=combined,
            top_positive_features=heuristic_positive[:5],
            top_negative_features=heuristic_negative[:5],
            explanation_available=True,
            explanation_method=explanation_method,
            human_readable=human_readable,
        )

    def explain_prediction(self, features: Dict[str, float]) -> ExplanationResult:
        """Explain model prediction for a specific feature dictionary.

        Steps:
            1. Convert features dict to DataFrame matching feature names.
            2. Compute SHAP values if SHAP explainer is ready.
            3. Sort features by absolute attribution.
            4. Identify top positive (pushing phishing) and negative (pushing legitimate) features.
            5. Generate human-readable explanations.
            6. Fall back gracefully to global feature importance or heuristics if needed.

        Args:
            features: Dictionary of extracted URL features.

        Returns:
            ExplanationResult: Formatted explanation results.
        """
        features_dict = dict(features)
        feature_order = self.feature_names

        # Convert to DataFrame
        df_row = pd.DataFrame([features_dict])
        for col in feature_order:
            if col not in df_row.columns:
                df_row[col] = 0.0
        df_ordered = df_row[feature_order]

        if self.explainer is not None:
            try:
                return self._explain_with_shap(df_ordered, features_dict)
            except Exception as exc:
                logger.warning("SHAP explanation calculation failed: %s. Reverting to fallback.", exc)

        return self._explain_fallback(features_dict)
