# AI-Based Phishing Detection System

A lightweight, modern, and production-grade cybersecurity web application built with **Python**, **Flask**, **scikit-learn**, and **Vanilla JavaScript** to detect phishing threats across emails, SMS messages (smishing), general text messages, and URLs.

---

## Table of Contents

- [Overview & Architecture](#overview--architecture)
- [Key Features](#key-features)
- [Project Structure](#project-structure)
- [Windows Installation & Setup](#windows-installation--setup)
- [Model Training](#model-training)
- [Running the Web Application](#running-the-web-application)
- [Example Test Cases](#example-test-cases)
- [REST API Reference](#rest-api-reference)
- [External Datasets Guide](#external-datasets-guide)
- [Security & Ethical Disclaimers](#security--ethical-disclaimers)
- [Troubleshooting](#troubleshooting)

---

## Overview & Architecture

Modern phishing campaigns exploit urgent social engineering psychological triggers alongside deceptive technical indicators (such as brand impersonation, deceptive top-level domains, embedded IP addresses, and shortened links).

This system pairs **statistical machine learning** with **deterministic cybersecurity heuristic rules**:

```
                              ┌────────────────────────────────────────┐
                              │  User Input (Email / SMS / Text / URL) │
                              └───────────────────┬────────────────────┘
                                                  │
                                                  ▼
                         ┌──────────────────────────────────────────────────┐
                         │              Flask Web Application               │
                         └────────┬────────────────────────────────┬────────┘
                                  │                                │
                       Message Mode                                URL Mode
                                  │                                │
                                  ▼                                ▼
                 ┌─────────────────────────────────┐   ┌───────────────────────────────┐
                 │        Message Detector         │   │         URL Detector          │
                 │ ─────────────────────────────── │   │ ───────────────────────────── │
                 │ 1. Text Preprocessing           │   │ 1. Zero-Network Static Parse  │
                 │ 2. TF-IDF Unigrams + Bigrams    │   │ 2. 15+ Lexical Feature Vector │
                 │ 3. Logistic Regression ML Model │   │ 3. Random Forest URL Model    │
                 │ 4. Heuristic Pattern Matching   │   │ 4. Heuristic Risk Rules       │
                 └────────────────┬────────────────┘   └───────────────┬───────────────┘
                                  │                                    │
                                  └─────────────────┬──────────────────┘
                                                    │
                                                    ▼
                                  ┌───────────────────────────────────┐
                                  │        Structured Assessment      │
                                  │ ───────────────────────────────── │
                                  │ • Verdict: Phishing / Safe        │
                                  │ • Risk Level: High / Med / Low    │
                                  │ • Calibrated Confidence %         │
                                  │ • Detected Threat Indicators      │
                                  │ • Actionable Recommendation       │
                                  └─────────────────┬─────────────────┘
                                                    │
                                                    ▼
                                  ┌───────────────────────────────────┐
                                  │ Asynchronous JSON Update to UI    │
                                  │ (No Page Reload, Modern Dashboard)│
                                  └───────────────────────────────────┘
```

---

## Key Features

1. **Four Specialized Detection Modes**:
   - **Email Mode**: Evaluates subject line + email body content.
   - **SMS Mode**: Inspects character-constrained text and smishing lures.
   - **Text Mode**: Evaluates generic messages, social media DMs, and customer chat.
   - **URL Mode**: Dedicated lexical and structural link analyzer.

2. **Dual-Layer Threat Detection**:
   - **Machine Learning Layer**: TF-IDF vectorization with calibrated probability estimates.
   - **Heuristic Pattern Layer**: Pinpoints urgency, credential requests, financial hooks, brand impersonation, and link obfuscation.

3. **Isolated Static URL Analysis**:
   - Inspects URL length, hostnames, IP address usage, excessive subdomains, non-standard ports, dangerous TLDs, and `@` symbol user-info traps.
   - **Strict Zero-Network Execution**: Never contacts, fetches, or runs remote code from submitted URLs.

4. **Modern UI/UX**:
   - Dark navy cybersecurity dashboard with subtle cyan accents.
   - 100% vanilla JavaScript with async `fetch` requests (no page reloads).
   - Real-time status indicators, confidence meters, and categorized threat chips.
   - 1-click sample test buttons for quick demonstrations.
   - Optional local scan history backed by SQLite.

---

## Project Structure

```
phishing_detection/
├── app.py                      # Flask backend and REST API endpoints
├── train_message_model.py      # TF-IDF & Logistic Regression training pipeline
├── train_url_model.py          # Lexical feature extraction & Random Forest pipeline
├── test_app.py                 # Automated unit and integration test suite
├── requirements.txt            # Python dependencies
├── README.md                   # Complete documentation
├── data/
│   ├── message_dataset.csv     # Starter email and SMS labeled dataset
│   ├── url_dataset.csv         # Starter URL labeled dataset
│   └── scan_history.db         # Local SQLite database for recent scans
├── models/
│   ├── message_model.pkl       # Trained message classifier
│   ├── message_vectorizer.pkl  # Trained TF-IDF vectorizer
│   └── url_model.pkl           # Trained URL classifier
├── detector/
│   ├── __init__.py             # Detector package definition
│   ├── message_detector.py     # Message detection logic and heuristics
│   └── url_detector.py         # Static URL lexical analyzer and heuristics
├── templates/
│   └── index.html              # Responsive dashboard template
└── static/
    ├── css/
    │   └── style.css           # Clean cybersecurity theme stylesheet
    └── js/
        └── app.js              # Vanilla JavaScript asynchronous controller
```

---

## Windows Installation & Setup

### Prerequisites

- **Python 3.9+** (Tested on Python 3.10, 3.11, 3.12, 3.13, 3.14)
- **PowerShell** or Command Prompt

### Step 1: Open PowerShell in the Project Directory

```powershell
cd "c:\Users\madhu\OneDrive\Desktop\min project"
```

### Step 2: (Optional but Recommended) Create a Virtual Environment

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

> *If you encounter a PowerShell script execution policy error, run:*
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
> .\venv\Scripts\Activate.ps1
> ```

### Step 3: Install Required Dependencies

```powershell
pip install -r requirements.txt
```

---

## Model Training

The application comes with pre-trained models. However, you can re-train or update models anytime using your own data.

### 1. Train the Message Classification Model

```powershell
python train_message_model.py
```

**Expected Output:**
```
[*] Loading dataset from: data/message_dataset.csv
[*] Class distribution: 0 (Legitimate)=23, 1 (Phishing)=27
[*] Vectorizing text with TF-IDF...
[*] Training Logistic Regression classifier...
=======================================================
           MODEL EVALUATION ON TEST SET
=======================================================
Precision (Phishing class 1): 0.7500
Recall    (Phishing class 1): 0.8571
F1-Score  (Phishing class 1): 0.8000
[+] Model successfully saved to:      models\message_model.pkl
[+] Vectorizer successfully saved to: models\message_vectorizer.pkl
```

### 2. Train the URL Classification Model

```powershell
python train_url_model.py
```

**Expected Output:**
```
[*] Loading URL dataset from: data/url_dataset.csv
[*] Extracting static lexical and structural features from URLs...
[*] Training Random Forest URL classifier...
=======================================================
           URL MODEL EVALUATION ON TEST SET
=======================================================
Precision (Phishing class 1): 1.0000
Recall    (Phishing class 1): 1.0000
F1-Score  (Phishing class 1): 1.0000
[+] URL Model saved to: models\url_model.pkl
```

---

## Running the Web Application

Start the Flask server:

```powershell
python app.py
```

Open your browser and navigate to:

👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## Running Automated Tests

Run the built-in test suite to verify all endpoints and models:

```powershell
python test_app.py
```

---

## Example Test Cases

You can test these using the dashboard or the API:

### 1. Email Phishing (Fake Bank Alert)
- **Subject**: `URGENT: Unauthorized access detected on your PayPal Account`
- **Body**:
  ```text
  Dear Customer,
  We detected suspicious login activity from an unknown IP address. Your account has been temporarily restricted. You must confirm your identity and verify your password within 24 hours to prevent permanent account suspension.
  Click here immediately: http://paypal-security-update.xyz/verify
  ```
- **Expected Result**: **Likely Phishing / Suspicious** | Risk: **High**

### 2. Smishing (SMS Package Scam)
- **Mode**: SMS
- **Message**:
  ```text
  USPS: Package delivery for tracking #940551020088 is on hold due to incomplete address. Confirm your details within 12 hours to avoid return: http://tinyurl.com/usps-address-confirm
  ```
- **Expected Result**: **Likely Phishing / Suspicious** | Risk: **High**

### 3. Deceptive URL (IP Host with Brand Spoofing)
- **Mode**: URL
- **Input**:
  ```text
  http://192.168.1.100/chase-online-login/verify.html
  ```
- **Expected Result**: **Likely Phishing / Suspicious** | Risk: **High** | Flag: *Direct IP Address Host*

### 4. Legitimate Work Email
- **Subject**: `Quarterly Architecture Review Meeting Notes`
- **Body**:
  ```text
  Hi Team, please find attached the meeting notes from yesterday's architecture review. Please review the database migration timeline before our sync on Thursday.
  ```
- **Expected Result**: **No Strong Phishing Indicators Found** | Risk: **Low**

---

## REST API Reference

### 1. Health Check
- **`GET /api/health`**
- **Response**:
  ```json
  {
    "status": "healthy",
    "components": {
      "message_model_loaded": true,
      "url_model_loaded": true,
      "history_db_available": true
    }
  }
  ```

### 2. Analyze Message
- **`POST /api/analyze/message`**
- **Request Body**:
  ```json
  {
    "mode": "email",
    "subject": "Account Alert",
    "text": "Your account has been restricted. Click here to verify your credentials: http://evil.xyz"
  }
  ```
- **Response**:
  ```json
  {
    "status": "Likely Phishing / Suspicious",
    "verdict": "Suspicious indicators found",
    "risk_level": "High",
    "confidence_score": 0.942,
    "confidence_percentage": 94.2,
    "analysis_type": "Hybrid (Machine Learning + Heuristics)",
    "indicators": [
      {
        "category": "Credential / Identity Request",
        "severity": "high",
        "detail": "Prompts for credentials, verification, or login actions."
      }
    ],
    "recommendation": "Do NOT click any links or enter credentials.",
    "word_count": 12
  }
  ```

### 3. Analyze URL
- **`POST /api/analyze/url`**
- **Request Body**:
  ```json
  {
    "url": "http://paypal-verification-center.xyz/signin"
  }
  ```
- **Response**:
  ```json
  {
    "status": "Likely Phishing / Suspicious",
    "risk_level": "High",
    "confidence_score": 0.981,
    "confidence_percentage": 98.1,
    "indicators": [
      {
        "category": "High-Risk Top-Level Domain (TLD)",
        "severity": "medium",
        "detail": "Domain ends with '.xyz'."
      }
    ],
    "features": {
      "hostname": "paypal-verification-center.xyz",
      "protocol": "HTTP",
      "is_ip_host": false
    }
  }
  ```

---

## External Datasets Guide

To scale up beyond the bundled starter datasets:

1. **SMS Spam Collection Dataset (UCI / Kaggle)**:
   - Download `spam.csv`.
   - Rename `v1` to `label` (convert `ham` -> 0, `spam` -> 1) and `v2` to `text`.
   - Run `python train_message_model.py --data path/to/spam.csv`.

2. **Enron / SpamAssassin Email Corpus**:
   - Clean emails into `text,label` CSV format.
   - Run `python train_message_model.py --data path/to/enron.csv`.

3. **PhishTank / ISCX-URL Datasets**:
   - Export active verified online phishing URLs with label `1` and Alexa/Tranco top domains with label `0`.
   - Run `python train_url_model.py --data path/to/phishing_urls.csv`.

---

## Security & Ethical Disclaimers

1. **Static Analysis Only**: This software analyzes lexical features, statistical tokens, and regex patterns. It **never performs outbound network calls** or downloads files from untrusted links.
2. **Preliminary Guidance**: Automated AI and heuristics are decision-support aids. A classification of "No Strong Phishing Indicators Found" is not a warranty of safety. Zero-day exploits, legitimate compromised accounts, or tailored spear-phishing may evade standard patterns.
3. **Privacy**: Inputs are evaluated in-memory on the local server. Scan previews are logged only to the local SQLite database (`data/scan_history.db`) and can be permanently wiped at any time using the "Clear History" button.

---

## Troubleshooting

### 1. `ModuleNotFoundError: No module named 'flask'` (or `sklearn`)
**Solution**: Ensure you are running Python inside your virtual environment or install the dependencies globally:
```powershell
python -m pip install -r requirements.txt
```

### 2. `Address already in use` (Port 5000 busy)
**Solution**: Run the application on a custom port:
```powershell
$env:PORT="5050"
python app.py
```

### 3. Model file not found warning on startup
**Solution**: Train the models once using:
```powershell
python train_message_model.py
python train_url_model.py
```

### 4. PowerShell Execution Policy Restriction
**Solution**:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## License

This project is released under the **MIT License**. Free for educational and research use.
