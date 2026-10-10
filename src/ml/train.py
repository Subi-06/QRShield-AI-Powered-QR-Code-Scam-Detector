"""Machine learning model training pipeline for QRShield AI.

Trains, evaluates, and selects phishing URL detection models
using extracted lexical, structural, and security features.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import random
import sys
from typing import Any, Dict, List, Optional, Tuple
import urllib.error
import urllib.request

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    auc,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
)
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

# Handle imports whether package is installed or run directly
try:
    from config.settings import (
        EVALUATION_REPORT_FILENAME,
        FEATURE_NAMES_FILENAME,
        MODEL_DIR,
        MODEL_FILENAME,
        PROCESSED_DATA_DIR,
        REPORTS_DIR,
        SCALER_FILENAME,
    )
    from src.ml.feature_engineering import URLFeatureExtractor
except ImportError:
    _project_root = str(Path(__file__).resolve().parent.parent.parent)
    if _project_root not in sys.path:
        sys.path.insert(0, _project_root)
    from config.settings import (
        EVALUATION_REPORT_FILENAME,
        FEATURE_NAMES_FILENAME,
        MODEL_DIR,
        MODEL_FILENAME,
        PROCESSED_DATA_DIR,
        REPORTS_DIR,
        SCALER_FILENAME,
    )
    from src.ml.feature_engineering import URLFeatureExtractor

logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def _generate_synthetic_urls(
    n_legitimate: int = 5000, n_phishing: int = 5000
) -> Tuple[List[str], List[int]]:
    """Generate realistic-looking synthetic URLs for fallback demonstration purposes.

    Args:
        n_legitimate: Number of legitimate URLs to generate.
        n_phishing: Number of phishing URLs to generate.

    Returns:
        Tuple[List[str], List[int]]: Pair of generated URLs and binary labels (0=legitimate, 1=phishing).
    """
    rng = random.Random(42)

    legitimate_domains = [
        "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
        "twitter.com", "linkedin.com", "reddit.com", "netflix.com", "microsoft.com",
        "github.com", "stackoverflow.com", "apple.com", "instagram.com", "yahoo.com",
        "nytimes.com", "bbc.com", "cnn.com", "medium.com", "cloudflare.com",
        "spotify.com", "dropbox.com", "adobe.com", "salesforce.com", "slack.com",
        "zoom.us", "twitch.tv", "paypal.com", "craigslist.org", "ebay.com",
        "walmart.com", "target.com", "pinterest.com", "tumblr.com", "imdb.com",
        "espn.com", "hulu.com", "quora.com", "vimeo.com", "flickr.com",
        "etsy.com", "booking.com", "tripadvisor.com", "weather.com", "coursera.org",
        "khanacademy.org", "gitlab.com", "bitbucket.org", "mozilla.org", "python.org",
    ]

    legit_paths = [
        "",
        "/",
        "/about",
        "/contact-us",
        "/products",
        "/services",
        "/faq",
        "/help/center",
        "/search?q=technology&category=all",
        "/docs/v1/getting-started",
        "/questions/12345678/how-to-implement-python-code",
        "/en/articles/2026/03/annual-security-overview",
        "/dp/B08N5WRWNW?ref_=ast_sto_dp",
        "/wiki/Machine_learning",
        "/user/profile/settings",
        "/explore/trending?tab=top",
        "/downloads/latest/release.tar.gz",
        "/news/technology/future-of-cybersecurity",
        "/pricing/plans?billing=annual",
        "/support/kb/articles/987654",
    ]

    phishing_brands = [
        "paypal", "chase", "wellsfargo", "bankofamerica", "citibank",
        "appleid", "microsoft-login", "amaz0n", "netflix-verify", "google-security",
        "secure-login", "wallet-connect", "coinbase-support", "metamask-auth", "facebook-verify",
        "dropbox-share", "dhl-tracking", "fedex-delivery", "irs-tax-refund", "usps-package",
    ]

    phishing_tlds = [
        ".top", ".xyz", ".club", ".work", ".site", ".online", ".info",
        ".live", ".support", ".click", ".kim", ".loan", ".racing", ".vip",
    ]

    suspicious_keywords_sample = [
        "verify", "secure", "login", "account", "update", "confirm",
        "banking", "password", "signin", "auth", "wallet", "urgent", "suspend",
    ]

    legitimate_urls: List[str] = []
    for _ in range(n_legitimate):
        domain = rng.choice(legitimate_domains)
        path = rng.choice(legit_paths)
        scheme = "https" if rng.random() < 0.96 else "http"
        prefix = "www." if rng.random() < 0.55 else ""
        legitimate_urls.append(f"{scheme}://{prefix}{domain}{path}")

    phishing_urls: List[str] = []
    for _ in range(n_phishing):
        p_type = rng.random()
        scheme = "http" if rng.random() < 0.70 else "https"

        if p_type < 0.20:
            # IP address based URL
            ip = f"{rng.randint(11, 220)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
            kw = rng.choice(suspicious_keywords_sample)
            phishing_urls.append(f"{scheme}://{ip}/{kw}.php?id={rng.randint(10000, 99999)}")
        elif p_type < 0.45:
            # Suspicious subdomain spoofing brand
            brand = rng.choice(phishing_brands)
            kw = rng.choice(suspicious_keywords_sample)
            tld = rng.choice(phishing_tlds)
            host = f"{brand}-{kw}.service{rng.randint(1, 99)}{tld}"
            phishing_urls.append(f"{scheme}://{host}/account/confirm-identity?token={rng.getrandbits(32)}")
        elif p_type < 0.70:
            # Typosquatting / brand variation with deep deceptive path
            brand = rng.choice(phishing_brands)
            kw1 = rng.choice(suspicious_keywords_sample)
            kw2 = rng.choice(suspicious_keywords_sample)
            phishing_urls.append(
                f"{scheme}://{brand}-security-update.com/{kw1}/{kw2}/session?auth_token={rng.getrandbits(48)}"
            )
        elif p_type < 0.85:
            # Embedded @ sign or double slashes in path
            brand = rng.choice(phishing_brands)
            malicious_host = f"secure-gate-{rng.randint(100, 999)}.xyz"
            phishing_urls.append(
                f"{scheme}://{brand}.com@{malicious_host}//signin/account-verify.html"
            )
        else:
            # Hex-encoded characters and long randomized token strings
            brand = rng.choice(phishing_brands)
            hex_token = "%20%2F%3F" + hex(rng.getrandbits(40))[2:]
            phishing_urls.append(
                f"{scheme}://web-{brand}-portal.top/verification/session/{hex_token}?urgent=true"
            )

    urls = legitimate_urls + phishing_urls
    labels = [0] * len(legitimate_urls) + [1] * len(phishing_urls)

    combined = list(zip(urls, labels))
    rng.shuffle(combined)
    shuffled_urls, shuffled_labels = zip(*combined)

    return list(shuffled_urls), list(shuffled_labels)


class PhishingModelTrainer:
    """Trainer pipeline for phishing URL classification models."""

    def __init__(self, random_state: int = 42) -> None:
        """Initialize the phishing model training pipeline.

        Args:
            random_state: Seed for reproducible data splitting and model training.
        """
        self.random_state: int = random_state
        self.feature_extractor: URLFeatureExtractor = URLFeatureExtractor()
        self.is_synthetic_data: bool = False

        self.model_candidates: Dict[str, Any] = {
            "XGBoost": XGBClassifier(
                n_estimators=200,
                max_depth=6,
                learning_rate=0.1,
                eval_metric="logloss",
                random_state=self.random_state,
            ),
            "RandomForest": RandomForestClassifier(
                n_estimators=200,
                max_depth=10,
                random_state=self.random_state,
            ),
            "LogisticRegression": LogisticRegression(
                max_iter=1000,
                C=1.0,
                random_state=self.random_state,
            ),
        }

    def _try_load_processed_dataset(
        self, file_path: Path
    ) -> Optional[Tuple[pd.DataFrame, pd.Series]]:
        """Attempt loading dataset from processed CSV file.

        Args:
            file_path: Path to CSV dataset file.

        Returns:
            Optional tuple of (X, y) or None if loading fails.
        """
        if not file_path.exists():
            return None

        try:
            logger.info("Loading processed dataset from %s", file_path)
            df = pd.read_csv(file_path)
            if "url" in df.columns and "label" in df.columns:
                df = df.dropna(subset=["url", "label"])
                df = df.drop_duplicates(subset=["url"])
                X = self.feature_extractor.extract_features_dataframe(
                    df["url"].astype(str).tolist()
                )
                y = df["label"].astype(int)
                self.is_synthetic_data = False
                return X, y
            elif "label" in df.columns:
                df = df.dropna()
                y = df["label"].astype(int)
                feature_cols = [c for c in df.columns if c != "label"]
                X = df[feature_cols].copy()
                self.is_synthetic_data = False
                return X, y
        except Exception as e:
            logger.warning("Failed to load processed dataset from %s: %s", file_path, e)

        return None

    def _try_download_uci_dataset(self) -> Optional[Tuple[pd.DataFrame, pd.Series]]:
        """Attempt downloading the UCI Phishing Websites dataset.

        Returns:
            Optional tuple of (X, y) or None if download fails.
        """
        uci_url = (
            "https://archive.ics.uci.edu/ml/machine-learning-databases/"
            "00327/Training%20Dataset.arff"
        )
        try:
            logger.info("Attempting download of UCI Phishing dataset from %s", uci_url)
            req = urllib.request.Request(
                uci_url,
                headers={"User-Agent": "QRShield-AI-Trainer/1.0"},
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                content = response.read().decode("utf-8", errors="ignore")

            lines = content.splitlines()
            data_started = False
            rows = []
            for line in lines:
                line_str = line.strip()
                if not line_str or line_str.startswith("%"):
                    continue
                if line_str.lower().startswith("@data"):
                    data_started = True
                    continue
                if data_started:
                    vals = [v.strip() for v in line_str.split(",")]
                    if len(vals) >= 2:
                        rows.append(vals)

            if rows:
                raw_df = pd.DataFrame(rows).apply(pd.to_numeric, errors="coerce").dropna()
                X = raw_df.iloc[:, :-1]
                # In UCI dataset, 1 is legitimate and -1 is phishing; map -1 -> 1 (phishing), 1 -> 0 (legitimate)
                y_raw = raw_df.iloc[:, -1]
                y = (y_raw == -1).astype(int)
                self.is_synthetic_data = False
                logger.info("Successfully fetched and parsed UCI Phishing dataset (%d samples)", len(X))
                return X, y
        except Exception as e:
            logger.warning("Could not download or parse UCI Phishing dataset: %s", e)

        return None

    def prepare_dataset(
        self, data_path: Optional[str] = None
    ) -> Tuple[pd.DataFrame, pd.Series]:
        """Prepare dataset for training by loading, downloading, or generating synthetic data.

        Dataset acquisition strategy:
        1. Load from provided data_path or PROCESSED_DATA_DIR / 'phishing_dataset.csv'
        2. If not found, attempt to download UCI Phishing Websites dataset
        3. If download fails, generate a clearly labeled synthetic dataset for demonstration

        Args:
            data_path: Optional direct path to CSV dataset file.

        Returns:
            Tuple[pd.DataFrame, pd.Series]: Feature matrix X and target labels y (0=legitimate, 1=phishing).
        """
        target_path = Path(data_path) if data_path else PROCESSED_DATA_DIR / "phishing_dataset.csv"

        # Strategy 1: Local processed dataset
        result = self._try_load_processed_dataset(target_path)
        if result is not None:
            X, y = result
            X = X.fillna(0.0)
            return X, y

        # Strategy 2: Generate realistic representative URL dataset using URLFeatureExtractor
        # Ensures identical feature representation between training and inference pipelines
        logger.info(
            "Generating balanced reference URL dataset using URLFeatureExtractor (35 lexical features)..."
        )
        self.is_synthetic_data = True
        urls, labels = _generate_synthetic_urls(n_legitimate=5000, n_phishing=5000)

        df = pd.DataFrame({"url": urls, "label": labels})
        df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)

        logger.info("Extracting URL features for %d URLs...", len(df))
        X = self.feature_extractor.extract_features_dataframe(df["url"].tolist())
        y = pd.Series(df["label"].values, name="label")
        X = X.fillna(0.0)

        # Save dataset to processed directory for persistence
        PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)
        df.to_csv(PROCESSED_DATA_DIR / "phishing_dataset.csv", index=False)

        synthetic_meta_file = PROCESSED_DATA_DIR / "synthetic_data_metadata.json"
        metadata = {
            "is_synthetic": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "n_samples": int(len(X)),
            "n_features": int(X.shape[1]),
            "n_phishing": int((y == 1).sum()),
            "n_legitimate": int((y == 0).sum()),
            "disclaimer": (
                "CLEARLY LABELED: This dataset was synthetically generated as a reference "
                "for demonstration and testing purposes. Features were extracted using URLFeatureExtractor."
            ),
        }
        with open(synthetic_meta_file, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        return X, y

    def train_and_evaluate(self, X: pd.DataFrame, y: pd.Series) -> Dict[str, Any]:
        """Train candidate models, evaluate on validation set, and test best model.

        Splits data into stratified 70% train, 15% validation, and 15% test partitions.
        Scales features using StandardScaler fit on training data only.

        Args:
            X: Feature matrix DataFrame.
            y: Binary target Series (0=legitimate, 1=phishing).

        Returns:
            Dict[str, Any]: Comprehensive evaluation metrics and trained objects.
        """
        feature_names = list(X.columns)

        # Stratified split: 70% train, 30% temp
        X_train_raw, X_temp_raw, y_train, y_temp = train_test_split(
            X,
            y,
            test_size=0.30,
            stratify=y,
            random_state=self.random_state,
        )

        # Split temp equally into 15% validation and 15% test
        X_val_raw, X_test_raw, y_val, y_test = train_test_split(
            X_temp_raw,
            y_temp,
            test_size=0.50,
            stratify=y_temp,
            random_state=self.random_state,
        )

        logger.info(
            "Dataset partitioned: Train=%d, Validation=%d, Test=%d",
            len(X_train_raw),
            len(X_val_raw),
            len(X_test_raw),
        )

        # Fit scaler on training set ONLY
        scaler = StandardScaler()
        X_train = scaler.fit_transform(X_train_raw)
        X_val = scaler.transform(X_val_raw)
        X_test = scaler.transform(X_test_raw)

        candidate_results: Dict[str, Dict[str, Any]] = {}
        trained_models: Dict[str, Any] = {}

        for model_name, model in self.model_candidates.items():
            logger.info("Training candidate model: %s...", model_name)
            model.fit(X_train, y_train)
            trained_models[model_name] = model

            # Validation predictions
            y_val_pred = model.predict(X_val)
            if hasattr(model, "predict_proba"):
                y_val_proba = model.predict_proba(X_val)[:, 1]
            elif hasattr(model, "decision_function"):
                y_val_proba = model.decision_function(X_val)
            else:
                y_val_proba = y_val_pred.astype(float)

            precision, recall, _ = precision_recall_curve(y_val, y_val_proba)
            val_pr_auc = float(auc(recall, precision))

            val_acc = float(accuracy_score(y_val, y_val_pred))
            val_prec = float(precision_score(y_val, y_val_pred, zero_division=0))
            val_rec = float(recall_score(y_val, y_val_pred, zero_division=0))
            val_f1 = float(f1_score(y_val, y_val_pred, zero_division=0))
            val_cm = confusion_matrix(y_val, y_val_pred).tolist()
            val_report = classification_report(
                y_val, y_val_pred, output_dict=True, zero_division=0
            )

            cv_scores = cross_val_score(
                model, X_train, y_train, cv=3, scoring="f1"
            ).tolist()

            candidate_results[model_name] = {
                "accuracy": val_acc,
                "precision": val_prec,
                "recall": val_rec,
                "f1_score": val_f1,
                "pr_auc": val_pr_auc,
                "confusion_matrix": val_cm,
                "classification_report": val_report,
                "cv_f1_scores": cv_scores,
                "cv_f1_mean": float(np.mean(cv_scores)),
            }

            logger.info(
                "[%s Validation] Acc: %.4f, Prec: %.4f, Rec: %.4f, F1: %.4f, PR-AUC: %.4f",
                model_name,
                val_acc,
                val_prec,
                val_rec,
                val_f1,
                val_pr_auc,
            )

        # Select best model by F1-score (with preference for high recall if F1 within 0.005)
        best_model_name = ""
        best_f1 = -1.0
        best_recall = -1.0
        selection_reason = ""

        for name, metrics in candidate_results.items():
            f1 = metrics["f1_score"]
            rec = metrics["recall"]
            if best_model_name == "":
                best_model_name = name
                best_f1 = f1
                best_recall = rec
            else:
                if f1 > best_f1 + 0.005:
                    best_model_name = name
                    best_f1 = f1
                    best_recall = rec
                elif abs(f1 - best_f1) <= 0.005 and rec > best_recall:
                    best_model_name = name
                    best_f1 = f1
                    best_recall = rec

        selection_reason = (
            f"Selected {best_model_name} with validation F1-score of {best_f1:.4f} "
            f"and recall of {best_recall:.4f} prioritizing high phishing catch rate."
        )
        logger.info("Best candidate selected: %s (%s)", best_model_name, selection_reason)

        best_model = trained_models[best_model_name]

        # Evaluate best model on TEST set (final evaluation, executed only once)
        logger.info("Executing final evaluation of %s on TEST set...", best_model_name)
        y_test_pred = best_model.predict(X_test)
        if hasattr(best_model, "predict_proba"):
            y_test_proba = best_model.predict_proba(X_test)[:, 1]
        elif hasattr(best_model, "decision_function"):
            y_test_proba = best_model.decision_function(X_test)
        else:
            y_test_proba = y_test_pred.astype(float)

        t_precision, t_recall, _ = precision_recall_curve(y_test, y_test_proba)
        test_pr_auc = float(auc(t_recall, t_precision))

        test_results = {
            "accuracy": float(accuracy_score(y_test, y_test_pred)),
            "precision": float(precision_score(y_test, y_test_pred, zero_division=0)),
            "recall": float(recall_score(y_test, y_test_pred, zero_division=0)),
            "f1_score": float(f1_score(y_test, y_test_pred, zero_division=0)),
            "pr_auc": test_pr_auc,
            "confusion_matrix": confusion_matrix(y_test, y_test_pred).tolist(),
            "classification_report": classification_report(
                y_test, y_test_pred, output_dict=True, zero_division=0
            ),
        }

        return {
            "candidate_results": candidate_results,
            "best_model_name": best_model_name,
            "best_model": best_model,
            "best_scaler": scaler,
            "feature_names": feature_names,
            "selection_reason": selection_reason,
            "test_results": test_results,
            "dataset_split": {
                "train_samples": int(len(X_train_raw)),
                "val_samples": int(len(X_val_raw)),
                "test_samples": int(len(X_test_raw)),
                "total_samples": int(len(X)),
            },
        }

    def save_model(
        self,
        model: Any,
        scaler: StandardScaler,
        feature_names: List[str],
        evaluation_report: Dict[str, Any],
    ) -> str:
        """Persist trained model, scaler, feature names, and evaluation report.

        Args:
            model: Trained model instance.
            scaler: Fitted StandardScaler instance.
            feature_names: Ordered list of feature names used during training.
            evaluation_report: Evaluation metrics and metadata report dictionary.

        Returns:
            str: Absolute path string of the saved model artifact.
        """
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

        model_path = MODEL_DIR / MODEL_FILENAME
        scaler_path = MODEL_DIR / SCALER_FILENAME
        feature_names_path = MODEL_DIR / FEATURE_NAMES_FILENAME
        report_path = REPORTS_DIR / EVALUATION_REPORT_FILENAME

        # Save model and scaler using joblib
        joblib.dump(model, model_path)
        logger.info("Saved model artifact to %s", model_path)

        joblib.dump(scaler, scaler_path)
        logger.info("Saved feature scaler to %s", scaler_path)

        # Save feature_names to MODEL_DIR / FEATURE_NAMES_FILENAME
        # If FEATURE_NAMES_FILENAME ends with .json write JSON, if .joblib write joblib
        # To strictly satisfy instructions: save feature_names as JSON
        if str(FEATURE_NAMES_FILENAME).endswith(".json"):
            with open(feature_names_path, "w", encoding="utf-8") as f:
                json.dump(feature_names, f, indent=2)
        else:
            # Also dump joblib as defined in settings, plus JSON version if needed
            joblib.dump(feature_names, feature_names_path)
            json_feature_path = MODEL_DIR / "feature_names.json"
            with open(json_feature_path, "w", encoding="utf-8") as f:
                json.dump(feature_names, f, indent=2)

        logger.info("Saved feature names to %s", feature_names_path)

        # Save evaluation report as JSON
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(evaluation_report, f, indent=2)
        logger.info("Saved evaluation report to %s", report_path)

        return str(model_path)

    def generate_evaluation_report(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Create comprehensive evaluation report dictionary.

        Args:
            results: Results dictionary returned from train_and_evaluate.

        Returns:
            Dict[str, Any]: Formatted evaluation report.
        """
        best_name = results["best_model_name"]
        val_metrics = results["candidate_results"][best_name]
        test_metrics = results["test_results"]
        split_info = results["dataset_split"]

        limitations = [
            "Lexical and structural features may not identify compromised legitimate domains without anomalous paths.",
            "Newly registered zero-day malicious domains with valid SSL certificates may have low heuristic indicators.",
            "Dynamic URL redirection services and JavaScript redirections require second-stage sandbox analysis.",
        ]
        if self.is_synthetic_data:
            limitations.insert(
                0,
                "PROMINENT WARNING: This model was trained on SYNTHETIC demonstrative URL data. "
                "Performance metrics reflect synthetic distribution patterns and are not representative "
                "of production live threat evasion rates.",
            )

        report = {
            "training_date": datetime.now(timezone.utc).isoformat(),
            "dataset_size": split_info["total_samples"],
            "dataset_split": split_info,
            "feature_count": len(results["feature_names"]),
            "feature_names": results["feature_names"],
            "is_synthetic_data": self.is_synthetic_data,
            "candidate_models_evaluated": list(results["candidate_results"].keys()),
            "per_model_validation_metrics": results["candidate_results"],
            "best_model_name": best_name,
            "selection_rationale": results["selection_reason"],
            "validation_vs_test_performance": {
                "validation": {
                    "accuracy": val_metrics["accuracy"],
                    "precision": val_metrics["precision"],
                    "recall": val_metrics["recall"],
                    "f1_score": val_metrics["f1_score"],
                    "pr_auc": val_metrics["pr_auc"],
                },
                "test": {
                    "accuracy": test_metrics["accuracy"],
                    "precision": test_metrics["precision"],
                    "recall": test_metrics["recall"],
                    "f1_score": test_metrics["f1_score"],
                    "pr_auc": test_metrics["pr_auc"],
                },
            },
            "final_test_confusion_matrix": test_metrics["confusion_matrix"],
            "final_test_classification_report": test_metrics["classification_report"],
            "limitations_and_caveats": limitations,
        }

        return report

    def run_full_pipeline(self, data_path: Optional[str] = None) -> Dict[str, Any]:
        """Execute the complete end-to-end training and evaluation pipeline.

        Args:
            data_path: Optional explicit path to CSV dataset.

        Returns:
            Dict[str, Any]: Complete pipeline execution results and artifact paths.
        """
        logger.info("Starting PhishingModelTrainer full pipeline execution...")
        try:
            X, y = self.prepare_dataset(data_path=data_path)
            eval_results = self.train_and_evaluate(X, y)
            report = self.generate_evaluation_report(eval_results)

            model_path = self.save_model(
                model=eval_results["best_model"],
                scaler=eval_results["best_scaler"],
                feature_names=eval_results["feature_names"],
                evaluation_report=report,
            )

            logger.info("PhishingModelTrainer pipeline completed successfully.")
            return {
                "status": "success",
                "model_path": model_path,
                "best_model_name": eval_results["best_model_name"],
                "report": report,
            }
        except Exception as e:
            logger.exception("Error executing phishing model training pipeline: %s", e)
            return {
                "status": "error",
                "error": str(e),
            }


if __name__ == "__main__":
    trainer = PhishingModelTrainer()
    output = trainer.run_full_pipeline()
    print(f"Pipeline status: {output.get('status')}")
    if output.get("status") == "success":
        print(f"Model saved to: {output.get('model_path')}")
        print(f"Selected model: {output.get('best_model_name')}")
