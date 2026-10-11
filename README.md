# QRShield AI — AI-Powered QR Code Scam Detector

A web application that enables users to inspect QR codes before visiting websites or executing UPI payments. Uses supervised machine learning for phishing URL detection and rule-based verification for UPI payment QR codes.

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-red.svg)
![XGBoost](https://img.shields.io/badge/XGBoost-2.0+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## Features

- **QR Code Scanning** — Upload image files (PNG/JPG/JPEG) or capture frames using camera
- **AI Phishing Detection** — XGBoost-based URL classification utilizing 35 lexical features
- **UPI Payment Verification** — Rule-based parameter inspection for UPI payment strings
- **Explainable AI** — Model feature weights, indicator detection, and SHAP explainability
- **Security Dashboard** — Real-time telemetry, risk distributions, and detection rates
- **Scan History** — Searchable local audit trail with detailed inspection views
- **Secure Handling** — All payloads treated as untrusted input with zero automatic navigation

## Prerequisites

- Python 3.11 or compatible version
- pip (Python package manager)
- zbar / libzbar0 (optional for native pyzbar decoding; pure OpenCV fallback included)

### Installing zbar (Optional)

**Windows:**
Included via pyzbar wheels.

**macOS:**
```bash
brew install zbar
```

**Ubuntu/Debian:**
```bash
sudo apt-get install libzbar0
```

## Installation & Local Setup

1. **Clone the repository:**
```bash
git clone https://github.com/Subi-06/QRShield-AI-Powered-QR-Code-Scam-Detector.git
cd QRShield-AI-Powered-QR-Code-Scam-Detector
```

2. **Create a virtual environment:**
```bash
python -m venv venv

# Windows:
venv\Scripts\activate

# macOS / Linux:
source venv/bin/activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

4. **Train the ML model (Pre-trained models are already included in `models/`):**
```bash
python -m src.ml.train
```

5. **Run the application:**
```bash
streamlit run app.py
```

Open `http://localhost:8501` in your browser.

## Cloud Deployment (Streamlit Community Cloud)

1. Fork or push this repository to your GitHub account.
2. Sign in to [share.streamlit.io](https://share.streamlit.io).
3. Click **New app**, select this repository, choose branch `main`, and set main file to `app.py`.
4. Click **Deploy**. Streamlit Cloud automatically reads `packages.txt` and `requirements.txt`.

## Project Structure

```
QRShield/
|-- app.py                          # Main Streamlit application entry point
|-- packages.txt                    # System apt packages (libzbar0 for cloud)
|-- requirements.txt                # Python package dependencies
|-- config/
|   `-- settings.py                 # Application configuration & thresholds
|-- src/
|   |-- ml/
|   |   |-- feature_engineering.py  # 35 URL lexical feature extractor
|   |   |-- train.py                # Supervised ML training pipeline
|   |   |-- predict.py              # Risk classification inference engine
|   |   `-- explainer.py            # SHAP & feature importance explanations
|   |-- qr_processor/
|   |   |-- decoder.py              # Multi-stage QR decoder (OpenCV + pyzbar)
|   |   `-- validator.py            # Image file & dimension validator
|   |-- upi/
|   |   `-- verifier.py             # Rule-based UPI payment analyzer
|   |-- database/
|   |   `-- db_manager.py           # SQLite scan history storage
|   `-- security/
|       `-- sanitizer.py            # Input sanitization & SSRF guards
|-- pages/
|   |-- 1_Scanner.py                # 2-column QR scan & result interface
|   |-- 2_Dashboard.py              # Real-time analytics & telemetry
|   |-- 3_History.py                # Queryable scan history records
|   |-- 4_Model_Report.py           # Performance benchmarks & confusion matrix
|   `-- 5_About.py                  # Architecture & system information
|-- styles/
|   `-- main.css                    # Custom CSS stylesheet
|-- models/                         # Pre-trained model & scaler joblib artifacts
|-- reports/                        # Evaluation report JSON metrics
|-- assets/                         # Demo sample QR test images
`-- tests/                          # Pytest test suite (66 tests)
```

## Testing Suite

Run all test cases using pytest:

```bash
pytest tests/ -v
```

## Machine Learning Pipeline

### Models Evaluated
1. **XGBoost** (Primary candidate — selected based on F1-score and phishing recall)
2. **Random Forest** (Comparison baseline)
3. **Logistic Regression** (Linear baseline)

### Dataset Source
Trained on standard verified threat telemetry:
- Phishing feeds: `Phishing.Database` active verified URLs + `OpenPhish`
- Legitimate domains: `Tranco Top 1M` research list

### Features Extracted (35 total)
- URL structural dimensions (length, hostname, path, query, fragment)
- Protocol & host characteristics (HTTPS scheme, IP address as host, custom ports)
- Domain indicators (subdomain counts, TLD lengths, shortener service detection)
- Character frequencies (dots, hyphens, slashes, percent signs, digits)
- Heuristic risk indicators (suspicious keywords, Shannon entropy)

## Security Controls

- Decoded payloads are handled as untrusted string inputs.
- No external links or redirects are followed or executed automatically.
- HTML escaping is enforced across all displayed output.
- Server-side private and loopback IP ranges are protected against SSRF.
- Sensitive payment fields are redacted prior to database persistence.

## Disclaimer

QRShield AI provides automated risk assessment based on pattern recognition and statistical modeling. It does not provide absolute certification of safety for any website or payment transaction. Users must verify sensitive requests through established official channels.

## License

MIT License.
