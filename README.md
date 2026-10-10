# 🛡️ QRShield AI — AI-Powered QR Code Scam Detector

A professional web application that helps users inspect QR codes before visiting websites or making payments. Uses machine learning for phishing URL detection and rule-based verification for UPI payment QR codes.

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-red.svg)
![XGBoost](https://img.shields.io/badge/XGBoost-2.0+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## 🚀 Features

- **QR Code Scanning** — Upload images (PNG/JPG/JPEG) or use camera
- **AI Phishing Detection** — XGBoost-based URL classification with 35 lexical features
- **UPI Payment Verification** — Rule-based analysis of UPI payment QR codes
- **Explainable AI** — SHAP-based model explanations and feature importance
- **Dashboard & Analytics** — Real-time statistics with Plotly visualizations
- **Scan History** — Full history with search, filtering, and management
- **Security-First Design** — All content treated as untrusted, no auto-opening

## 📋 Prerequisites

- Python 3.11 or compatible version
- pip (Python package manager)
- zbar library (for pyzbar QR decoding — optional, OpenCV fallback available)

### Installing zbar (optional but recommended)

**Windows:**
```bash
# pyzbar wheels include zbar for Windows — no extra install needed
```

**macOS:**
```bash
brew install zbar
```

**Ubuntu/Debian:**
```bash
sudo apt-get install libzbar0
```

## 🛠️ Installation

1. **Clone the repository:**
```bash
git clone <repository-url>
cd QRShield
```

2. **Create a virtual environment:**
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

4. **Train the ML model:**
```bash
python -m src.ml.train
```
This trains XGBoost, Random Forest, and Logistic Regression on a phishing URL dataset. If no real dataset is available, a synthetic dataset is generated for demonstration (clearly labeled).

5. **Run the application:**
```bash
streamlit run app.py
```

The app will open at `http://localhost:8501`.

## 📁 Project Structure

```
QRShield/
├── app.py                          # Main Streamlit entry point
├── requirements.txt                # Python dependencies
├── config/
│   └── settings.py                 # Application configuration
├── src/
│   ├── ml/
│   │   ├── feature_engineering.py  # 35 URL feature extractor
│   │   ├── train.py                # ML training pipeline
│   │   ├── predict.py              # Prediction service
│   │   └── explainer.py            # SHAP explainability
│   ├── qr_processor/
│   │   ├── decoder.py              # QR decoding (pyzbar + OpenCV)
│   │   └── validator.py            # Image validation
│   ├── upi/
│   │   └── verifier.py             # UPI payment verification
│   ├── database/
│   │   └── db_manager.py           # SQLite scan history
│   └── security/
│       └── sanitizer.py            # Input sanitization & SSRF protection
├── pages/
│   ├── 1_Scanner.py                # QR scanning & analysis
│   ├── 2_Dashboard.py              # Analytics dashboard
│   ├── 3_History.py                # Scan history management
│   ├── 4_Model_Report.py           # ML model evaluation
│   └── 5_About.py                  # Project information
├── styles/
│   └── main.css                    # Custom CSS (1,100+ lines)
├── models/                         # Saved ML models
├── reports/                        # Evaluation reports
├── data/                           # Datasets
└── tests/                          # Pytest test suite
```

## 🧪 Running Tests

```bash
pytest tests/ -v
```

## 🤖 ML Pipeline

### Models Trained
1. **XGBoost** — Primary candidate (typically best F1-score)
2. **Random Forest** — Comparison model
3. **Logistic Regression** — Baseline model

### Features Extracted (35 total)
- URL structure: length, hostname, path, query, fragment
- Security indicators: HTTPS, IP address, port
- Domain analysis: subdomains, TLD, URL shortener detection
- Character analysis: dots, hyphens, digits, special characters
- Suspicion markers: keywords, entropy, encoded characters

### Evaluation Protocol
- 70/15/15 train/validation/test split (stratified)
- Scaler fitted on training data only
- Best model selected by F1-score on validation set
- Final evaluation on held-out test set (single pass)

## 🔒 Security

- All QR content treated as untrusted input
- URLs never automatically opened or fetched
- HTML escaping on all displayed content
- SSRF protection against private IP ranges
- File upload validation (size, type, magic bytes)
- UPI sensitive fields redacted in storage
- No API keys in source code

## ⚠️ Disclaimer

QRShield AI provides **automated risk assessment** based on URL pattern analysis and machine learning. It does **not guarantee** the safety of any website, payment, or QR code content. Always verify sensitive transactions independently.

## 📄 License

MIT License — see LICENSE file for details.
