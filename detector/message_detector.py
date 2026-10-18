"""Message Detector Module.

Analyzes emails, SMS, and general text messages for phishing, smishing,
and social engineering indicators using machine learning (TF-IDF + Classifier)
combined with cybersecurity heuristic pattern detection.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional
import joblib


class MessageDetector:
    """Detects phishing in emails, SMS, and text messages."""

    # Heuristic threat patterns compiled for speed
    URGENCY_PATTERNS = [
        r"\b(?:immediate(?:ly)?|urgent(?:ly)?|action required|suspended?|within 24 hours?|account limited|terminated?|unauthorized access|warning|critical|expire[ds]?)\b",
        r"\b(?:act now|time sensitive|final notice|account will be deleted|security breach|locked out)\b",
    ]

    CREDENTIAL_PATTERNS = [
        r"\b(?:confirm|verify|update|validate|restore|re-?activate)\s+(?:your\s+)?(?:account|identity|password|pin|security code|ssn|credentials|billing|access)\b",
        r"\b(?:click (?:here|below|this link)|log-?in (?:to|at)|sign-?in to keep|enter your (?:password|credentials|code))\b",
        r"\b(?:one-?time code|passcode|otp|2fa|mfa)\b.*(?:share|send|reply|do not share)\b",
    ]

    FINANCIAL_PRIZE_PATTERNS = [
        r"\b(?:won|winner|lottery|claim (?:your )?(?:prize|cash|reward|refund|gift card)|congratulations!|selected for)\b",
        r"\b(?:\$\d+[\d,]*|\d+\s*(?:usd|dollars|eur|gbp))\s*(?:refund|bonus|grant|prize|waiting for you)\b",
        r"\b(?:wire transfer|crypto(?:currency)?|bitcoin|btc|eth|gift card code|western union|cashapp|venmo|zelle)\b",
        r"\b(?:unpaid invoice|payment overdue|tax refund|irs payment|customs duty)\b",
    ]

    IMPERSONATION_PATTERNS = [
        r"\b(?:paypal|apple|microsoft|google|amazon|netflix|chase|wells fargo|bank of america|geek squad|mcafee|norton|dhl|fedex|ups|usps)\b",
        r"\b(?:it (?:desk|support|department)|security department|fraud alert|customer support|helpdesk|system administrator)\b",
    ]

    LINK_REGEX = re.compile(
        r"https?://(?:www\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_+.~#?&/=]*)",
        re.IGNORECASE,
    )
    SHORTENER_DOMAINS = {
        "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
        "cutt.ly", "rb.gy", "rebrand.ly", "adf.ly", "shorturl.at"
    }

    def __init__(self, model_path: Optional[str] = None, vectorizer_path: Optional[str] = None):
        """Initialize the message detector, loading model artifacts if present."""
        self.model = None
        self.vectorizer = None
        self.model_loaded = False
        self.load_error: Optional[str] = None

        default_model = os.path.join(os.path.dirname(__file__), "..", "models", "message_model.pkl")
        default_vect = os.path.join(os.path.dirname(__file__), "..", "models", "message_vectorizer.pkl")

        self.model_path = model_path or default_model
        self.vectorizer_path = vectorizer_path or default_vect

        self._load_model()

    def _load_model(self) -> None:
        """Attempt to load trained artifacts from disk."""
        if os.path.exists(self.model_path) and os.path.exists(self.vectorizer_path):
            try:
                self.model = joblib.load(self.model_path)
                self.vectorizer = joblib.load(self.vectorizer_path)
                self.model_loaded = True
                self.load_error = None
            except Exception as e:
                self.model_loaded = False
                self.load_error = f"Error loading model artifacts: {str(e)}"
        else:
            self.model_loaded = False
            self.load_error = (
                "Model artifacts not found. System is operating in rule-based heuristic mode. "
                "Run 'python train_message_model.py' to enable full ML classification."
            )

    @staticmethod
    def preprocess_text(text: str) -> str:
        """Clean and normalize raw text for analysis and vectorization."""
        if not text or not isinstance(text, str):
            return ""
        # Normalize whitespace
        cleaned = re.sub(r"\s+", " ", text).strip()
        return cleaned

    def extract_heuristic_indicators(self, text: str) -> List[Dict[str, str]]:
        """Identify human-readable security indicators present in the message."""
        indicators = []
        lower_text = text.lower()

        # Check urgency
        for pattern in self.URGENCY_PATTERNS:
            match = re.search(pattern, lower_text, re.IGNORECASE)
            if match:
                indicators.append({
                    "category": "High Urgency & Coercion",
                    "severity": "high",
                    "detail": f"Contains urgent pressure phrase: '{match.group(0)}'. Attackers use urgency to bypass critical thinking."
                })
                break

        # Check credentials harvesting
        for pattern in self.CREDENTIAL_PATTERNS:
            match = re.search(pattern, lower_text, re.IGNORECASE)
            if match:
                indicators.append({
                    "category": "Credential / Identity Request",
                    "severity": "high",
                    "detail": f"Prompts for credentials, verification, or login actions: '{match.group(0)}'."
                })
                break

        # Check financial / prize claims
        for pattern in self.FINANCIAL_PRIZE_PATTERNS:
            match = re.search(pattern, lower_text, re.IGNORECASE)
            if match:
                indicators.append({
                    "category": "Financial / Prize Hook",
                    "severity": "medium",
                    "detail": f"Mentions winnings, refunds, crypto, wire transfers, or prize claims: '{match.group(0)}'."
                })
                break

        # Check brand / authority impersonation
        for pattern in self.IMPERSONATION_PATTERNS:
            match = re.search(pattern, lower_text, re.IGNORECASE)
            if match:
                indicators.append({
                    "category": "Brand / Authority Impersonation",
                    "severity": "medium",
                    "detail": f"References high-profile brand or support desk: '{match.group(0)}'."
                })
                break

        # Check embedded links
        links = self.LINK_REGEX.findall(text)
        if links:
            shorteners_found = []
            ip_links = []
            for link in links:
                for s in self.SHORTENER_DOMAINS:
                    if s in link.lower():
                        shorteners_found.append(s)
                if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", link):
                    ip_links.append(link)

            if shorteners_found:
                indicators.append({
                    "category": "Obfuscated Link",
                    "severity": "high",
                    "detail": f"Contains shortened link domain ({', '.join(set(shorteners_found))}), which conceals the real destination."
                })
            elif ip_links:
                indicators.append({
                    "category": "Direct IP Link",
                    "severity": "high",
                    "detail": "Contains direct numerical IP link instead of a verified domain name."
                })
            else:
                indicators.append({
                    "category": "Embedded Hyperlink",
                    "severity": "low",
                    "detail": f"Contains {len(links)} external hyperlink(s). Always inspect target URLs independently."
                })

        return indicators

    def analyze(self, text: str, mode: str = "text", subject: Optional[str] = None) -> Dict[str, Any]:
        """Analyze message content (Email, SMS, or Text) for phishing characteristics."""
        # Combine subject and body for email mode
        full_text = text or ""
        if mode == "email" and subject and subject.strip():
            full_text = f"Subject: {subject.strip()}\n\n{full_text}"

        cleaned_text = self.preprocess_text(full_text)

        if not cleaned_text or len(cleaned_text.strip()) < 3:
            return {
                "status": "Unable to Analyze",
                "verdict": "Invalid or empty input text.",
                "risk_level": "Unknown",
                "confidence_score": None,
                "confidence_percentage": None,
                "model_available": self.model_loaded,
                "indicators": [],
                "recommendation": "Please provide a valid message or email body with at least a few words to evaluate.",
                "mode": mode,
                "word_count": 0,
            }

        indicators = self.extract_heuristic_indicators(full_text)
        num_high = sum(1 for ind in indicators if ind["severity"] == "high")
        num_med = sum(1 for ind in indicators if ind["severity"] == "medium")

        ml_prediction = None
        ml_confidence = None

        if self.model_loaded and self.model is not None and self.vectorizer is not None:
            try:
                features = self.vectorizer.transform([cleaned_text])
                pred = self.model.predict(features)[0]
                ml_prediction = int(pred)  # 1 = Phishing, 0 = Legitimate

                if hasattr(self.model, "predict_proba"):
                    probs = self.model.predict_proba(features)[0]
                    # Probability of the predicted class
                    ml_confidence = float(probs[ml_prediction])
            except Exception as e:
                ml_prediction = None
                ml_confidence = None
                indicators.append({
                    "category": "ML Processing Error",
                    "severity": "low",
                    "detail": f"Model inference fell back to heuristics: {str(e)}"
                })

        # Synthesize final verdict & risk level
        # If ML is available, use it grounded with heuristic indicators
        if ml_prediction is not None:
            if ml_prediction == 1:
                # Phishing predicted by ML
                if ml_confidence and ml_confidence >= 0.85 or num_high >= 1:
                    risk_level = "High"
                else:
                    risk_level = "Medium"
                status = "Likely Phishing / Suspicious"
            else:
                # Legitimate predicted by ML
                if num_high >= 2:
                    # Model thinks safe, but multiple high red flags found
                    risk_level = "Medium"
                    status = "Likely Phishing / Suspicious"
                    indicators.append({
                        "category": "Heuristic Override",
                        "severity": "medium",
                        "detail": "Multiple high-risk indicators were detected despite standard phrasing patterns."
                    })
                elif num_high == 1 or num_med >= 2:
                    risk_level = "Medium"
                    status = "Likely Phishing / Suspicious"
                else:
                    risk_level = "Low"
                    status = "No Strong Phishing Indicators Found"
        else:
            # Pure heuristic evaluation
            if num_high >= 2 or (num_high == 1 and num_med >= 1):
                risk_level = "High"
                status = "Likely Phishing / Suspicious"
            elif num_high == 1 or num_med >= 1:
                risk_level = "Medium"
                status = "Likely Phishing / Suspicious"
            else:
                risk_level = "Low"
                status = "No Strong Phishing Indicators Found"

        # Actionable recommendations
        if risk_level == "High":
            recommendation = (
                "Do NOT click any links, open attachments, or reply to this message. "
                "Never share passwords, 2FA codes, or financial details. Verify directly with the sender through an official phone number or website."
            )
        elif risk_level == "Medium":
            recommendation = (
                "Exercise caution. This message exhibits common social engineering patterns. "
                "Inspect any links carefully before clicking, and verify the sender's identity using a known, trusted contact channel."
            )
        else:
            recommendation = (
                "No immediate phishing indicators detected. However, always verify unknown senders and unexpected requests. "
                "Preliminary automated analysis is not a guarantee of safety."
            )

        conf_pct = round(ml_confidence * 100, 1) if ml_confidence is not None else None

        return {
            "status": status,
            "verdict": "Suspicious indicators found" if status.startswith("Likely") else "Appears standard and legitimate",
            "risk_level": risk_level,
            "confidence_score": round(ml_confidence, 4) if ml_confidence is not None else None,
            "confidence_percentage": conf_pct,
            "model_available": self.model_loaded,
            "analysis_type": "Hybrid (Machine Learning + Heuristics)" if self.model_loaded else "Heuristic Rule-Based",
            "indicators": indicators,
            "recommendation": recommendation,
            "mode": mode,
            "word_count": len(cleaned_text.split()),
        }
