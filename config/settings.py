"""Configuration settings for QRShield AI application."""

from pathlib import Path
from typing import List

# Base Directory
BASE_DIR: Path = Path(__file__).resolve().parent.parent

# Application Metadata
APP_NAME: str = "QRShield AI"
APP_VERSION: str = "1.0.0"
APP_DESCRIPTION: str = (
    "AI-powered QR code threat detection, malicious URL analysis, "
    "and UPI fraud prevention system."
)

# File System Directories & Paths
DATA_DIR: Path = BASE_DIR / "data"
RAW_DATA_DIR: Path = DATA_DIR / "raw"
PROCESSED_DATA_DIR: Path = DATA_DIR / "processed"
MODEL_DIR: Path = BASE_DIR / "models"
REPORTS_DIR: Path = BASE_DIR / "reports"
DATABASE_PATH: Path = BASE_DIR / "qrshield.db"

# Model File Names
MODEL_FILENAME: str = "xgboost_qr_detector.joblib"
FEATURE_NAMES_FILENAME: str = "feature_names.joblib"
SCALER_FILENAME: str = "scaler.joblib"
EVALUATION_REPORT_FILENAME: str = "evaluation_report.json"

# Image Processing Limits
MAX_FILE_SIZE_MB: int = 10
ALLOWED_EXTENSIONS: List[str] = [".png", ".jpg", ".jpeg"]
MAX_IMAGE_DIMENSION: int = 4096

# Risk Thresholds
LOW_RISK_THRESHOLD: float = 0.3
HIGH_RISK_THRESHOLD: float = 0.7

# Security & Suspicious Patterns
SUSPICIOUS_KEYWORDS: List[str] = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "confirm",
    "banking",
    "password",
    "signin",
    "auth",
    "wallet",
    "free",
    "winner",
    "prize",
    "urgent",
    "suspend",
    "expire",
    "click",
    "limited",
    "offer",
]

URL_SHORTENERS: List[str] = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "short.io",
]

# Supported Payment Schemes
UPI_SCHEMES: List[str] = ["upi://"]

# UI Theme & Color Palette
NAVY: str = "#0A192F"
DARK_BLUE: str = "#172A45"
LIGHT_BG: str = "#F8FAFC"
ELECTRIC_BLUE: str = "#007BFF"
MUTED_GRAY: str = "#64748B"
SUCCESS_GREEN: str = "#10B981"
WARNING_AMBER: str = "#F59E0B"
DANGER_RED: str = "#EF4444"
