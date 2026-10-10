"""ML prediction module for QRShield AI.

Provides the phishing detection inference pipeline that loads trained models,
extracts URL features, performs classification, evaluates risk thresholds, and
generates contextual security recommendations and risk indicators.
"""

from dataclasses import dataclass, field
import json
import logging
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional
import urllib.parse

import joblib
import numpy as np
import pandas as pd

# Handle imports whether package is installed or run directly
try:
    from config.settings import (
        APP_VERSION,
        EVALUATION_REPORT_FILENAME,
        FEATURE_NAMES_FILENAME,
        HIGH_RISK_THRESHOLD,
        LOW_RISK_THRESHOLD,
        MODEL_DIR,
        MODEL_FILENAME,
        REPORTS_DIR,
        SCALER_FILENAME,
    )
    from src.ml.feature_engineering import FEATURE_NAMES, URLFeatureExtractor
except ImportError:
    _project_root = str(Path(__file__).resolve().parent.parent.parent)
    if _project_root not in sys.path:
        sys.path.insert(0, _project_root)
    from config.settings import (
        APP_VERSION,
        EVALUATION_REPORT_FILENAME,
        FEATURE_NAMES_FILENAME,
        HIGH_RISK_THRESHOLD,
        LOW_RISK_THRESHOLD,
        MODEL_DIR,
        MODEL_FILENAME,
        REPORTS_DIR,
        SCALER_FILENAME,
    )
    from src.ml.feature_engineering import FEATURE_NAMES, URLFeatureExtractor

logger = logging.getLogger(__name__)

DEFAULT_DISCLAIMER: str = (
    "QRShield AI provides automated security assessments based on lexical, "
    "structural, and machine learning analysis. No automated system is 100% "
    "foolproof; always exercise caution before entering credentials or sensitive data."
)


@dataclass
class PredictionResult:
    """Dataclass encapsulating comprehensive URL phishing prediction results."""

    url: str
    prediction: int  # 0=legitimate, 1=phishing
    probability: float  # probability of phishing
    risk_category: str  # 'low_risk', 'suspicious', 'high_risk'
    risk_label: str  # 'Low Risk', 'Suspicious', 'High Risk'
    features: Dict[str, float]
    top_risk_indicators: List[str]
    recommendations: List[str]
    model_version: str
    is_model_prediction: bool  # True if ML model used, False if heuristic fallback
    disclaimer: str = DEFAULT_DISCLAIMER


class PhishingPredictor:
    """Predictor pipeline for evaluating URL phishing risks using ML models."""

    def __init__(
        self,
        model_dir: Optional[Path] = None,
        reports_dir: Optional[Path] = None,
    ) -> None:
        """Initialize the phishing predictor and attempt to load artifacts.

        Args:
            model_dir: Optional custom model directory path.
            reports_dir: Optional custom reports directory path.
        """
        self.model_dir: Path = Path(model_dir) if model_dir else MODEL_DIR
        self.reports_dir: Path = Path(reports_dir) if reports_dir else REPORTS_DIR

        self.extractor: URLFeatureExtractor = URLFeatureExtractor()
        self.model: Optional[Any] = None
        self.scaler: Optional[Any] = None
        self.feature_names: List[str] = list(FEATURE_NAMES)
        self.evaluation_report: Dict[str, Any] = {}
        self.model_loaded: bool = False
        self.model_version: str = APP_VERSION

        self._load_artifacts()

    def _load_artifacts(self) -> None:
        """Load trained model, scaler, feature names, and evaluation reports gracefully."""
        # 1. Load Feature Names
        feature_names_path = self.model_dir / FEATURE_NAMES_FILENAME
        json_feature_names_path = self.model_dir / "feature_names.json"

        loaded_features = False
        for path_candidate in [feature_names_path, json_feature_names_path]:
            if path_candidate.exists():
                try:
                    if path_candidate.suffix.lower() == ".json":
                        with open(path_candidate, "r", encoding="utf-8") as f:
                            self.feature_names = json.load(f)
                    else:
                        self.feature_names = joblib.load(path_candidate)
                    loaded_features = True
                    logger.info("Loaded feature names from %s", path_candidate)
                    break
                except Exception as exc:
                    logger.warning("Failed loading feature names from %s: %s", path_candidate, exc)

        if not loaded_features:
            self.feature_names = self.extractor.get_feature_names()

        # 2. Load Evaluation Report
        eval_report_path = self.reports_dir / EVALUATION_REPORT_FILENAME
        if eval_report_path.exists():
            try:
                with open(eval_report_path, "r", encoding="utf-8") as f:
                    self.evaluation_report = json.load(f)
                if "model_version" in self.evaluation_report:
                    self.model_version = str(self.evaluation_report["model_version"])
                logger.info("Loaded evaluation report from %s", eval_report_path)
            except Exception as exc:
                logger.warning("Failed loading evaluation report: %s", exc)

        # 3. Load Scaler
        scaler_path = self.model_dir / SCALER_FILENAME
        if scaler_path.exists():
            try:
                self.scaler = joblib.load(scaler_path)
                logger.info("Loaded feature scaler from %s", scaler_path)
            except Exception as exc:
                logger.warning("Failed loading scaler from %s: %s", scaler_path, exc)
                self.scaler = None
        else:
            logger.info("Scaler file not found at %s", scaler_path)

        # 4. Load ML Model
        model_path = self.model_dir / MODEL_FILENAME
        if model_path.exists():
            try:
                self.model = joblib.load(model_path)
                self.model_loaded = True
                logger.info("Loaded ML model from %s", model_path)
            except Exception as exc:
                logger.warning("Failed loading ML model from %s: %s", model_path, exc)
                self.model = None
                self.model_loaded = False
        else:
            logger.info("Model file not found at %s. Falling back to heuristic mode.", model_path)
            self.model_loaded = False

    def _validate_url(self, url: str) -> str:
        """Validate and normalize the raw input URL.

        Args:
            url: Input URL string.

        Returns:
            str: Normalized URL string.

        Raises:
            ValueError: If URL is empty, non-string, or invalid.
        """
        if not isinstance(url, str) or not url.strip():
            raise ValueError("URL cannot be empty or non-string.")

        trimmed = url.strip()
        # Basic validation check
        if len(trimmed) < 3:
            raise ValueError(f"URL '{trimmed}' is too short to be valid.")
        return trimmed

    def _map_risk_category(self, probability: float) -> tuple[str, str]:
        """Map phishing probability to risk category and display label.

        Args:
            probability: Predicted phishing probability in [0.0, 1.0].

        Returns:
            tuple[str, str]: (risk_category, risk_label)
        """
        if probability < LOW_RISK_THRESHOLD:
            return "low_risk", "Low Risk"
        if probability < HIGH_RISK_THRESHOLD:
            return "suspicious", "Suspicious"
        return "high_risk", "High Risk"

    def _identify_risk_indicators(self, features: Dict[str, float], url: str) -> List[str]:
        """Identify human-readable security risk indicators from extracted features.

        Args:
            features: Dictionary of extracted URL features.
            url: The evaluated URL string.

        Returns:
            List[str]: List of human-readable risk indicators found.
        """
        indicators: List[str] = []

        is_https = features.get("is_https", 1.0)
        has_ip = features.get("has_ip_address", 0.0)
        has_kw = features.get("has_suspicious_keyword", 0.0)
        num_kw = features.get("num_suspicious_keywords", 0.0)
        is_shortener = features.get("is_url_shortener", 0.0)
        url_len = features.get("url_length", float(len(url)))
        num_subdomains = features.get("num_subdomains", 0.0)
        has_at = features.get("has_at_sign", 0.0) or features.get("num_at_signs", 0.0) > 0
        special_ratio = features.get("special_char_ratio", 0.0)
        url_entropy = features.get("url_entropy", 0.0)
        double_slash = features.get("path_has_double_slash", 0.0)
        encoded_chars = features.get("has_encoded_chars", 0.0)
        has_port = features.get("has_port", 0.0)
        digit_ratio = features.get("digit_ratio_url", 0.0)

        if is_https == 0.0:
            indicators.append("URL uses HTTP instead of HTTPS")

        if has_ip == 1.0:
            indicators.append("IP address used as hostname")

        if has_kw == 1.0 or num_kw > 0.0:
            indicators.append("URL contains suspicious keywords")

        if is_shortener == 1.0:
            indicators.append("Known URL shortener detected")

        if url_len > 75:
            indicators.append(f"Unusually long URL ({int(url_len)} characters)")

        if num_subdomains > 2:
            indicators.append(f"Multiple subdomains detected ({int(num_subdomains)})")

        if has_at:
            indicators.append("URL contains @ symbol")

        if special_ratio > 0.3:
            indicators.append("Excessive special characters")

        if url_entropy > 4.5:
            indicators.append("High URL entropy suggesting random characters")

        if double_slash == 1.0:
            indicators.append("URL path contains redirection pattern (//)")

        if encoded_chars == 1.0:
            indicators.append("URL contains percent-encoded hex characters")

        if has_port == 1.0:
            indicators.append("Non-standard port specified in URL")

        if digit_ratio > 0.3:
            indicators.append("High proportion of numeric digits in URL")

        return indicators

    def _generate_recommendations(
        self,
        risk_category: str,
        indicators: List[str],
    ) -> List[str]:
        """Generate tailored safety recommendations based on risk category and indicators.

        Args:
            risk_category: 'low_risk', 'suspicious', or 'high_risk'.
            indicators: List of identified risk indicators.

        Returns:
            List[str]: Actionable user security guidance.
        """
        recommendations: List[str] = []

        if risk_category == "low_risk":
            recommendations.append(
                "No strong phishing indicators found. Standard browsing precautions still apply."
            )
            recommendations.append(
                "Ensure the destination domain matches the official service you intended to access."
            )
        elif risk_category == "suspicious":
            recommendations.append(
                "Verify the website independently before entering passwords or account credentials."
            )
            recommendations.append(
                "Check for a valid SSL certificate and examine the domain spelling for subtle typos."
            )
            recommendations.append(
                "Avoid downloading unsolicited files or opening unknown attachments from this link."
            )
        else:  # high_risk
            recommendations.append(
                "Do not enter personal information, login credentials, or financial details on this site."
            )
            recommendations.append(
                "Verify through official channels or contact the organization directly using a verified contact number."
            )
            recommendations.append(
                "Close this page immediately and do not trust the source QR code or link."
            )

        # Context-specific additional guidance
        if any("URL shortener" in ind for ind in indicators):
            recommendations.append(
                "Use a URL expander service to inspect the actual destination before navigating."
            )
        if any("HTTP instead of HTTPS" in ind for ind in indicators):
            recommendations.append(
                "Unencrypted HTTP connections transmit data in plain text; never transmit sensitive data."
            )

        return recommendations

    def _heuristic_fallback(self, url: str) -> PredictionResult:
        """Perform heuristic rule-based risk evaluation when ML model is unavailable.

        Args:
            url: Evaluated URL string.

        Returns:
            PredictionResult: Heuristic-based assessment result.
        """
        features = self.extractor.extract_features(url)
        indicators = self._identify_risk_indicators(features, url)

        # Heuristic scoring
        score = 0.05  # Base baseline
        if features.get("is_https", 1.0) == 0.0:
            score += 0.20
        if features.get("has_ip_address", 0.0) == 1.0:
            score += 0.35
        if features.get("has_suspicious_keyword", 0.0) == 1.0:
            score += 0.25
        if features.get("is_url_shortener", 0.0) == 1.0:
            score += 0.20
        if features.get("has_at_sign", 0.0) == 1.0:
            score += 0.30
        if features.get("url_length", 0.0) > 75:
            score += 0.15
        if features.get("num_subdomains", 0.0) > 2:
            score += 0.15
        if features.get("url_entropy", 0.0) > 4.5:
            score += 0.15
        if features.get("special_char_ratio", 0.0) > 0.3:
            score += 0.15

        # Bound probability between 0.01 and 0.99
        probability = float(min(0.99, max(0.01, round(score, 4))))
        prediction = 1 if probability >= 0.50 else 0
        risk_category, risk_label = self._map_risk_category(probability)
        recommendations = self._generate_recommendations(risk_category, indicators)

        return PredictionResult(
            url=url,
            prediction=prediction,
            probability=probability,
            risk_category=risk_category,
            risk_label=risk_label,
            features=features,
            top_risk_indicators=indicators,
            recommendations=recommendations,
            model_version=f"{self.model_version}-heuristic",
            is_model_prediction=False,
            disclaimer=DEFAULT_DISCLAIMER,
        )

    def predict(self, url: str) -> PredictionResult:
        """Predict whether a URL is legitimate or a phishing threat.

        Execution steps:
            1. Validate URL.
            2. Extract features via URLFeatureExtractor.
            3. Form DataFrame with exact feature columns.
            4. Scale features if scaler is present.
            5. Run model prediction and obtain phishing probability.
            6. Map probability to risk category via settings thresholds.
            7. Identify risk indicators.
            8. Generate safety recommendations.
            9. Construct and return PredictionResult.

        Args:
            url: The URL string to evaluate.

        Returns:
            PredictionResult: Structured inference result.
        """
        clean_url = self._validate_url(url)

        if not self.model_loaded or self.model is None:
            return self._heuristic_fallback(clean_url)

        try:
            features_dict = self.extractor.extract_features(clean_url)

            # Build DataFrame matching training feature columns
            feature_order = self.feature_names or self.extractor.get_feature_names()
            df_features = pd.DataFrame([features_dict])

            # Ensure all required columns are present with fallback to 0.0
            for col in feature_order:
                if col not in df_features.columns:
                    df_features[col] = 0.0
            df_ordered = df_features[feature_order]

            # Scale if scaler available
            if self.scaler is not None:
                x_input = self.scaler.transform(df_ordered)
            else:
                x_input = df_ordered.values

            # Model inference
            if hasattr(self.model, "predict_proba"):
                proba_array = self.model.predict_proba(x_input)
                # If binary classification, class 1 is phishing probability
                if proba_array.ndim == 2 and proba_array.shape[1] >= 2:
                    phishing_prob = float(proba_array[0, 1])
                else:
                    phishing_prob = float(proba_array[0, 0])
            elif hasattr(self.model, "decision_function"):
                decision = float(self.model.decision_function(x_input)[0])
                # Sigmoid transform for margin
                phishing_prob = float(1.0 / (1.0 + np.exp(-decision)))
            else:
                pred = int(self.model.predict(x_input)[0])
                phishing_prob = 0.90 if pred == 1 else 0.10

            phishing_prob = float(min(1.0, max(0.0, round(phishing_prob, 4))))
            prediction = 1 if phishing_prob >= 0.50 else 0

            risk_category, risk_label = self._map_risk_category(phishing_prob)
            indicators = self._identify_risk_indicators(features_dict, clean_url)
            recommendations = self._generate_recommendations(risk_category, indicators)

            return PredictionResult(
                url=clean_url,
                prediction=prediction,
                probability=phishing_prob,
                risk_category=risk_category,
                risk_label=risk_label,
                features=features_dict,
                top_risk_indicators=indicators,
                recommendations=recommendations,
                model_version=self.model_version,
                is_model_prediction=True,
                disclaimer=DEFAULT_DISCLAIMER,
            )
        except Exception as exc:
            logger.error("Model prediction failed for '%s': %s. Reverting to heuristic.", clean_url, exc)
            return self._heuristic_fallback(clean_url)

    def get_model_info(self) -> Dict[str, Any]:
        """Return model metadata, operational status, and evaluation metrics.

        Returns:
            Dict[str, Any]: Model details dictionary.
        """
        info: Dict[str, Any] = {
            "model_loaded": self.model_loaded,
            "model_version": self.model_version,
            "feature_count": len(self.feature_names),
            "scaler_loaded": self.scaler is not None,
            "evaluation_report": self.evaluation_report if self.evaluation_report else None,
        }
        if self.model is not None:
            info["model_type"] = type(self.model).__name__
            if hasattr(self.model, "n_features_in_"):
                info["n_features_in"] = int(self.model.n_features_in_)
        return info
