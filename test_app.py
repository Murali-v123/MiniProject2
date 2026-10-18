"""Automated Test Suite for AI-Based Phishing Detection System.

Tests message detection, URL detection, Flask endpoints, edge cases,
and error handling.
"""

import json
import unittest
from app import app, message_detector, url_detector


class PhishingDetectionTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.client.testing = True

    def test_01_models_loaded(self):
        """Verify model artifacts are loaded or have fallback."""
        print("\n[*] Testing model status...")
        self.assertTrue(message_detector.model_loaded, "Message ML model should be loaded.")
        self.assertTrue(url_detector.model_loaded, "URL ML model should be loaded.")
        print("  -> Both Message and URL models are loaded and ready.")

    def test_02_health_endpoint(self):
        """Test GET /api/health."""
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data["status"], "healthy")
        self.assertTrue(data["components"]["message_model_loaded"])
        self.assertTrue(data["components"]["url_model_loaded"])
        print("  -> /api/health responded 200 OK.")

    def test_03_email_phishing_detection(self):
        """Test phishing email analysis."""
        payload = {
            "mode": "email",
            "subject": "URGENT: Your account has been suspended",
            "text": "Dear customer, your PayPal account has been limited due to unauthorized activity. Click here immediately to confirm your password and restore access: http://paypal-verify-account.xyz/login"
        }
        res = self.client.post(
            "/api/analyze/message",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertIn("Likely Phishing", data["status"])
        self.assertIn(data["risk_level"], ["High", "Medium"])
        self.assertGreater(len(data["indicators"]), 0)
        print("  -> Phishing email correctly detected as Likely Phishing / Suspicious.")

    def test_04_legitimate_email_detection(self):
        """Test legitimate email analysis."""
        payload = {
            "mode": "email",
            "subject": "Weekly Engineering Team Notes",
            "text": "Hi team, please find attached the meeting notes from yesterday's sync. Safe travel to those attending the conference next week."
        }
        res = self.client.post(
            "/api/analyze/message",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertIn("No Strong Phishing", data["status"])
        self.assertEqual(data["risk_level"], "Low")
        print("  -> Legitimate email correctly classified as No Strong Phishing Indicators Found.")

    def test_05_sms_smishing_detection(self):
        """Test SMS smishing detection."""
        payload = {
            "mode": "sms",
            "text": "USPS: Your package could not be delivered due to unpaid customs fee of $2.99. Pay now to avoid return: http://bit.ly/3x8AbCd"
        }
        res = self.client.post(
            "/api/analyze/message",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertIn("Likely Phishing", data["status"])
        print("  -> SMS smishing correctly identified.")

    def test_06_url_phishing_detection(self):
        """Test phishing URL analysis (IP host & brand spoof)."""
        payload = {
            "url": "http://192.168.1.100/chase-online-login/verify.html"
        }
        res = self.client.post(
            "/api/analyze/url",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertIn("Likely Phishing", data["status"])
        self.assertIn(data["risk_level"], ["High", "Medium"])
        self.assertTrue(any("IP" in ind["category"] for ind in data["indicators"]))
        print("  -> Suspicious IP-based URL detected as Likely Phishing.")

    def test_07_safe_url_detection(self):
        """Test legitimate URL analysis."""
        payload = {
            "url": "https://en.wikipedia.org/wiki/Phishing"
        }
        res = self.client.post(
            "/api/analyze/url",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data["risk_level"], "Low")
        self.assertIn("No Strong Phishing", data["status"])
        print("  -> Wikipedia URL correctly analyzed with Low risk.")

    def test_08_invalid_inputs(self):
        """Test validation and bad requests."""
        # Empty message
        res = self.client.post(
            "/api/analyze/message",
            data=json.dumps({"mode": "sms", "text": "   "}),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 400)

        # Invalid mode
        res = self.client.post(
            "/api/analyze/message",
            data=json.dumps({"mode": "carrier_pigeon", "text": "Hello"}),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 400)

        # Empty URL
        res = self.client.post(
            "/api/analyze/url",
            data=json.dumps({"url": ""}),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 400)
        print("  -> Bad input and edge-case validation tests passed.")

    def test_09_scan_history(self):
        """Test scan history recording and clearing."""
        res = self.client.get("/api/history")
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertIn("history", data)
        self.assertGreater(len(data["history"]), 0)

        # Clear history
        clear_res = self.client.post("/api/history/clear")
        self.assertEqual(clear_res.status_code, 200)

        # Check empty
        res_after = self.client.get("/api/history")
        data_after = json.loads(res_after.data)
        self.assertEqual(len(data_after["history"]), 0)
        print("  -> Scan history retrieval and purge verified.")


if __name__ == "__main__":
    unittest.main()
