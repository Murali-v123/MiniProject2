"""URL Detector Module.

Analyzes URLs for phishing, spoofing, and malicious patterns using lexical,
structural, and heuristic analysis, alongside optional machine learning classification.
Strictly performs local static analysis: NEVER contacts or fetches untrusted URLs.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import joblib


class URLDetector:
    """Detects phishing and malicious indicators in URLs using static analysis."""

    SUSPICIOUS_TLDS = {
        "xyz", "top", "club", "work", "buzz", "country", "kim", "icu",
        "cam", "gq", "cf", "ml", "ga", "fit", "tk", "rest", "support",
        "vip", "cfd", "monster", "sbs", "quest", "click"
    }

    URL_SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
        "cutt.ly", "rb.gy", "rebrand.ly", "adf.ly", "shorturl.at",
        "tiny.cc", "goo.gl", "bit.do", "shorte.st"
    }

    SUSPICIOUS_KEYWORDS = [
        "login", "signin", "sign-in", "log-in", "verify", "verification",
        "security", "secure", "account", "update", "banking", "billing",
        "confirm", "wallet", "authenticate", "auth", "recover", "ebayisapi",
        "webscr", "password", "credential", "suspend", "unlock"
    ]

    TARGET_BRANDS = [
        "paypal", "apple", "microsoft", "google", "amazon", "netflix",
        "chase", "wellsfargo", "bankofamerica", "binance", "coinbase",
        "meta", "facebook", "instagram", "irs", "usps", "fedex", "dhl"
    ]

    def __init__(self, model_path: Optional[str] = None):
        """Initialize URL detector and attempt loading ML artifact."""
        self.model = None
        self.model_loaded = False
        self.load_error: Optional[str] = None

        default_model = os.path.join(os.path.dirname(__file__), "..", "models", "url_model.pkl")
        self.model_path = model_path or default_model
        self._load_model()

    def _load_model(self) -> None:
        """Load trained URL model if available."""
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                self.model_loaded = True
                self.load_error = None
            except Exception as e:
                self.model_loaded = False
                self.load_error = f"Error loading URL model: {str(e)}"
        else:
            self.model_loaded = False
            self.load_error = (
                "URL ML model not found. Performing transparent heuristic-based analysis. "
                "Run 'python train_url_model.py' to enable ML URL classification."
            )

    @staticmethod
    def normalize_url(raw_url: str) -> str:
        """Ensure standard scheme and structure for parsing."""
        trimmed = raw_url.strip()
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", trimmed):
            # Prepend https scheme by default if omitted
            trimmed = "http://" + trimmed
        return trimmed

    @classmethod
    def extract_features(cls, url: str) -> Dict[str, Any]:
        """Extract lexical, structural, and character-level features from URL."""
        normalized = cls.normalize_url(url)
        parsed = urlparse(normalized)

        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        port = parsed.port
        scheme = parsed.scheme.lower()

        # IP address detection (IPv4 / IPv6)
        ipv4_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
        is_ip = bool(re.match(ipv4_pattern, hostname)) or (":" in hostname and hostname.startswith("["))

        # Shortener check
        is_shortener = hostname in cls.URL_SHORTENERS

        # Subdomain / Dot analysis
        dots_in_host = hostname.count(".")
        subdomain_count = max(0, dots_in_host - 1) if not is_ip else 0

        # Excessive length
        url_len = len(url)
        host_len = len(hostname)

        # Special characters
        at_symbol_present = "@" in url
        hyphens_in_host = hostname.count("-")
        double_slash_path = "//" in path

        # Non-standard ports
        is_unusual_port = False
        if port is not None and port not in (80, 443):
            is_unusual_port = True

        # TLD check
        tld = hostname.split(".")[-1] if "." in hostname else ""
        has_suspicious_tld = tld in cls.SUSPICIOUS_TLDS

        # Keyword checks in path, query, or hostname
        combined_text = f"{hostname} {path} {query}".lower()
        found_keywords = [kw for kw in cls.SUSPICIOUS_KEYWORDS if kw in combined_text]

        # Brand spoofing checks (e.g., brand in subdomain or hyphenated: paypal-security.com)
        found_brands = []
        for brand in cls.TARGET_BRANDS:
            if brand in hostname:
                # Check if it's the genuine official primary domain
                parts = hostname.split(".")
                if len(parts) >= 2 and parts[-2] == brand:
                    continue  # Likely genuine brand domain
                found_brands.append(brand)

        # Percent-encoded characters
        encoded_chars = len(re.findall(r"%[0-9a-fA-F]{2}", url))

        # Digits in host
        digits_in_host = sum(c.isdigit() for c in hostname)
        digit_ratio_host = round(digits_in_host / max(1, host_len), 3)

        return {
            "normalized_url": normalized,
            "scheme": scheme,
            "hostname": hostname,
            "path": path,
            "query": query,
            "port": port,
            "url_length": url_len,
            "host_length": host_len,
            "is_ip": is_ip,
            "is_shortener": is_shortener,
            "dots_in_host": dots_in_host,
            "subdomain_count": subdomain_count,
            "at_symbol_present": at_symbol_present,
            "hyphens_in_host": hyphens_in_host,
            "double_slash_path": double_slash_path,
            "is_unusual_port": is_unusual_port,
            "tld": tld,
            "has_suspicious_tld": has_suspicious_tld,
            "found_keywords": found_keywords,
            "found_brands": found_brands,
            "encoded_chars": encoded_chars,
            "digits_in_host": digits_in_host,
            "digit_ratio_host": digit_ratio_host,
            "uses_https": scheme == "https",
        }

    @staticmethod
    def feature_vector(features: Dict[str, Any]) -> List[float]:
        """Convert features dictionary to numeric vector for machine learning."""
        return [
            float(features["url_length"]),
            float(features["host_length"]),
            float(features["dots_in_host"]),
            float(features["hyphens_in_host"]),
            float(1 if features["is_ip"] else 0),
            float(1 if features["is_shortener"] else 0),
            float(1 if features["at_symbol_present"] else 0),
            float(1 if features["double_slash_path"] else 0),
            float(1 if features["is_unusual_port"] else 0),
            float(1 if features["has_suspicious_tld"] else 0),
            float(len(features["found_keywords"])),
            float(len(features["found_brands"])),
            float(features["encoded_chars"]),
            float(features["digit_ratio_host"]),
            float(1 if features["uses_https"] else 0),
        ]

    def analyze(self, raw_url: str) -> Dict[str, Any]:
        """Analyze a target URL and generate security indicators and risk assessment."""
        if not raw_url or not isinstance(raw_url, str) or len(raw_url.strip()) < 3:
            return {
                "status": "Unable to Analyze",
                "verdict": "Invalid or empty URL.",
                "risk_level": "Unknown",
                "confidence_score": None,
                "confidence_percentage": None,
                "analysis_type": "Static URL Parser",
                "model_available": self.model_loaded,
                "indicators": [],
                "recommendation": "Please enter a valid web address (e.g. example.com or https://site.org/path).",
                "features": {},
            }

        url = raw_url.strip()
        features = self.extract_features(url)
        indicators: List[Dict[str, str]] = []

        # 1. IP Hostname check
        if features["is_ip"]:
            indicators.append({
                "category": "Direct IP Address Host",
                "severity": "high",
                "detail": f"Host '{features['hostname']}' uses a raw IP address instead of a registered domain name. Highly characteristic of phishing and malware staging."
            })

        # 2. Shortened URL check
        if features["is_shortener"]:
            indicators.append({
                "category": "URL Shortener Service",
                "severity": "medium",
                "detail": f"Hostname '{features['hostname']}' is a known URL shortener. Shortened URLs hide the ultimate landing destination from the visitor."
            })

        # 3. Misleading @ symbol
        if features["at_symbol_present"]:
            indicators.append({
                "category": "Embedded User-Info (@) Symbol",
                "severity": "high",
                "detail": "URL contains an '@' symbol. Browsers interpret text before '@' as authentication credentials, disguising the true destination host."
            })

        # 4. Excessive Subdomains
        if features["subdomain_count"] >= 3:
            indicators.append({
                "category": "Excessive Subdomains",
                "severity": "medium",
                "detail": f"Detected {features['subdomain_count']} subdomain levels. Phishing sites frequently stack subdomains to simulate trusted organizations."
            })

        # 5. Length Analysis
        if features["url_length"] > 75:
            indicators.append({
                "category": "Abnormally Long URL",
                "severity": "medium",
                "detail": f"URL length is {features['url_length']} characters (standard threshold <= 75). Long URLs often conceal malicious query payloads."
            })

        # 6. Unusual Port
        if features["is_unusual_port"]:
            indicators.append({
                "category": "Non-Standard Web Port",
                "severity": "high",
                "detail": f"Target specifies non-standard port :{features['port']}. Legitimate public services almost universally use standard ports 80 or 443."
            })

        # 7. Suspicious TLD
        if features["has_suspicious_tld"]:
            indicators.append({
                "category": "High-Risk Top-Level Domain (TLD)",
                "severity": "medium",
                "detail": f"Domain ends with '.{features['tld']}', a TLD statistically associated with high rates of malicious registration and spam abuse."
            })

        # 8. Brand Impersonation in Host
        if features["found_brands"]:
            brands_str = ", ".join(features["found_brands"])
            indicators.append({
                "category": "Brand Name In Subdomain / Host",
                "severity": "high",
                "detail": f"Target references known brand(s) ({brands_str}) in the hostname outside the primary registered domain. Strongly indicates brand impersonation."
            })

        # 9. Suspicious Keywords
        if features["found_keywords"]:
            kw_str = ", ".join(features["found_keywords"][:4])
            indicators.append({
                "category": "Credential / Phishing Keywords",
                "severity": "medium",
                "detail": f"Contains security-sensitive keywords: {kw_str}. Often used to mimic authentication pages."
            })

        # 10. Hyphens in domain
        if features["hyphens_in_host"] >= 2:
            indicators.append({
                "category": "Multiple Hyphens in Domain",
                "severity": "low",
                "detail": f"Domain contains {features['hyphens_in_host']} hyphens, commonly observed in deceptive domain lookalikes."
            })

        # 11. Double Slash in Path
        if features["double_slash_path"]:
            indicators.append({
                "category": "Open Redirect / Double Slash",
                "severity": "medium",
                "detail": "Path contains '//', frequently used to exploit open redirection vulnerabilities."
            })

        # 12. HTTPS Notice
        if features["uses_https"]:
            indicators.append({
                "category": "HTTPS Transport Protocol",
                "severity": "info",
                "detail": "Connection is encrypted via HTTPS. Note: HTTPS indicates encrypted transit only; malicious actors routinely obtain valid SSL certificates."
            })
        else:
            indicators.append({
                "category": "Insecure HTTP Protocol",
                "severity": "medium",
                "detail": "URL uses unencrypted HTTP. Data sent over this connection can be intercepted in transit."
            })

        # Count severity
        high_count = sum(1 for ind in indicators if ind["severity"] == "high")
        med_count = sum(1 for ind in indicators if ind["severity"] == "medium")

        ml_pred = None
        ml_conf = None

        if self.model_loaded and self.model is not None:
            try:
                vec = [self.feature_vector(features)]
                pred = self.model.predict(vec)[0]
                ml_pred = int(pred)
                if hasattr(self.model, "predict_proba"):
                    probs = self.model.predict_proba(vec)[0]
                    ml_conf = float(probs[ml_pred])
            except Exception as e:
                ml_pred = None
                ml_conf = None
                indicators.append({
                    "category": "ML Inference Error",
                    "severity": "low",
                    "detail": f"URL ML model failed to infer: {str(e)}"
                })

        # Final verdict determination
        if ml_pred is not None:
            if ml_pred == 1:
                status = "Likely Phishing / Suspicious"
                risk_level = "High" if (ml_conf and ml_conf >= 0.8) or high_count >= 1 else "Medium"
            else:
                if high_count >= 1 or med_count >= 3:
                    status = "Likely Phishing / Suspicious"
                    risk_level = "Medium"
                else:
                    status = "No Strong Phishing Indicators Found"
                    risk_level = "Low"
        else:
            # Transparent Heuristic Decision Matrix
            if high_count >= 1 or med_count >= 3:
                status = "Likely Phishing / Suspicious"
                risk_level = "High" if high_count >= 2 or (high_count == 1 and med_count >= 2) else "Medium"
            elif med_count >= 1:
                status = "Likely Phishing / Suspicious"
                risk_level = "Medium"
            else:
                status = "No Strong Phishing Indicators Found"
                risk_level = "Low"

        # Actionable recommendations
        if risk_level == "High":
            recommendation = (
                "Do NOT visit this link or input passwords, tokens, or financial details. "
                "The address displays high-risk phishing or evasion patterns."
            )
        elif risk_level == "Medium":
            recommendation = (
                "Exercise high caution. Check whether this URL matches the organization's official domain name before proceeding. "
                "If received via an unsolicited message, do not open it."
            )
        else:
            recommendation = (
                "No critical red flags observed in static lexical features. "
                "Remember that newly registered domains or legitimate compromised websites can host phishing pages without triggering basic lexical rules."
            )

        conf_pct = round(ml_conf * 100, 1) if ml_conf is not None else None

        return {
            "status": status,
            "verdict": "Deceptive URL characteristics found" if status.startswith("Likely") else "URL structure aligns with standard conventions",
            "risk_level": risk_level,
            "confidence_score": round(ml_conf, 4) if ml_conf is not None else None,
            "confidence_percentage": conf_pct,
            "model_available": self.model_loaded,
            "analysis_type": "Hybrid (URL ML Classifier + Lexical Rules)" if self.model_loaded else "Heuristic Lexical Analysis",
            "indicators": indicators,
            "recommendation": recommendation,
            "features": {
                "hostname": features["hostname"],
                "protocol": features["scheme"].upper(),
                "url_length": features["url_length"],
                "is_ip_host": features["is_ip"],
                "subdomain_depth": features["subdomain_count"],
                "suspicious_tld": features["has_suspicious_tld"],
            },
        }
