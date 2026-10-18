"""AI-Based Phishing Detection System.

Flask Web Application providing an interactive dashboard and REST API
for detecting phishing attacks in emails, SMS, text messages, and URLs.
"""

from __future__ import annotations

from datetime import datetime, timezone
import os
import sqlite3
import sys
from typing import Any, Dict, List
from flask import Flask, jsonify, render_template, request

# Ensure local detector package is discoverable
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from detector.message_detector import MessageDetector
from detector.url_detector import URLDetector

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# Database path for lightweight optional history
DB_PATH = os.path.join(os.path.dirname(__file__), "data", "scan_history.db")


def init_db() -> None:
    """Initialize SQLite database for optional local scan history."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                mode TEXT NOT NULL,
                target_preview TEXT NOT NULL,
                status TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                confidence REAL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def record_scan(mode: str, preview: str, status: str, risk_level: str, confidence: Any) -> None:
    """Safely log scan summary to local history without full raw content."""
    try:
        clean_preview = (preview[:60] + "...") if len(preview) > 60 else preview
        conf_val = float(confidence) if confidence is not None else None
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        conn = sqlite3.connect(DB_PATH)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO scan_history (timestamp, mode, target_preview, status, risk_level, confidence)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (now_utc, mode.upper(), clean_preview, status, risk_level, conf_val),
            )
            # Retain only the last 50 scans to keep storage minimal
            cursor.execute(
                """
                DELETE FROM scan_history WHERE id NOT IN (
                    SELECT id FROM scan_history ORDER BY id DESC LIMIT 50
                )
                """
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        app.logger.warning(f"Could not record scan history: {e}")


# Initialize detectors once on startup
print("[*] Initializing AI Phishing Detection Engines...")
message_detector = MessageDetector()
url_detector = URLDetector()
init_db()
print(f"[*] Message Detector ML Status: {'Loaded' if message_detector.model_loaded else 'Heuristic Only'}")
print(f"[*] URL Detector ML Status:     {'Loaded' if url_detector.model_loaded else 'Heuristic Only'}")


@app.route("/")
def index():
    """Render the primary cybersecurity dashboard."""
    return render_template("index.html")


@app.route("/api/health", methods=["GET"])
def health_check():
    """System health check and component diagnostics."""
    return jsonify({
        "status": "healthy",
        "service": "AI-Based Phishing Detection System",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": {
            "message_model_loaded": message_detector.model_loaded,
            "message_model_status": "Ready" if message_detector.model_loaded else "Heuristic Fallback",
            "message_load_error": message_detector.load_error,
            "url_model_loaded": url_detector.model_loaded,
            "url_model_status": "Ready" if url_detector.model_loaded else "Heuristic Fallback",
            "url_load_error": url_detector.load_error,
            "history_db_available": os.path.exists(DB_PATH),
        },
    }), 200


@app.route("/api/analyze/message", methods=["POST"])
def analyze_message():
    """Analyze email, SMS, or general text message content."""
    if not request.is_json:
        return jsonify({
            "error": "Bad Request",
            "message": "Request payload must be formatted as application/json.",
        }), 400

    data = request.get_json() or {}
    text = data.get("text", "")
    mode = data.get("mode", "text").lower()
    subject = data.get("subject", "")

    if mode not in {"email", "sms", "text"}:
        return jsonify({
            "error": "Invalid Mode",
            "message": f"Unsupported analysis mode '{mode}'. Choose 'email', 'sms', or 'text'.",
        }), 400

    if not isinstance(text, str) or not text.strip():
        return jsonify({
            "error": "Missing Input",
            "message": "Message text cannot be empty.",
        }), 400

    # Limit text length to prevent memory exhaustion
    if len(text) > 20000:
        return jsonify({
            "error": "Payload Too Large",
            "message": "Message text exceeds maximum allowed size (20,000 characters).",
        }), 400

    try:
        result = message_detector.analyze(text=text, mode=mode, subject=subject)

        # Log summary to history if analysis succeeded
        preview_src = f"[{subject}] {text}" if mode == "email" and subject else text
        record_scan(
            mode=mode,
            preview=preview_src,
            status=result["status"],
            risk_level=result["risk_level"],
            confidence=result["confidence_score"],
        )

        return jsonify(result), 200
    except Exception as e:
        app.logger.error(f"Error during message analysis: {e}")
        return jsonify({
            "error": "Analysis Failure",
            "message": "An unexpected error occurred during message inspection.",
        }), 500


@app.route("/api/analyze/url", methods=["POST"])
def analyze_url():
    """Analyze a single URL for phishing patterns."""
    if not request.is_json:
        return jsonify({
            "error": "Bad Request",
            "message": "Request payload must be formatted as application/json.",
        }), 400

    data = request.get_json() or {}
    url = data.get("url", "")

    if not isinstance(url, str) or not url.strip():
        return jsonify({
            "error": "Missing Input",
            "message": "URL cannot be empty.",
        }), 400

    if len(url) > 2000:
        return jsonify({
            "error": "Payload Too Large",
            "message": "URL exceeds maximum allowed length (2,000 characters).",
        }), 400

    try:
        result = url_detector.analyze(url)

        record_scan(
            mode="URL",
            preview=url,
            status=result["status"],
            risk_level=result["risk_level"],
            confidence=result["confidence_score"],
        )

        return jsonify(result), 200
    except Exception as e:
        app.logger.error(f"Error during URL analysis: {e}")
        return jsonify({
            "error": "Analysis Failure",
            "message": "An unexpected error occurred during URL inspection.",
        }), 500


@app.route("/api/history", methods=["GET"])
def get_history():
    """Retrieve recent scan history summaries."""
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp, mode, target_preview, status, risk_level, confidence
            FROM scan_history
            ORDER BY id DESC
            LIMIT 20
            """
        )
        rows = cursor.fetchall()
        history_list = [dict(row) for row in rows]
        return jsonify({"history": history_list}), 200
    except Exception as e:
        app.logger.error(f"Error fetching scan history: {e}")
        return jsonify({"history": [], "error": "Unable to fetch history"}), 500
    finally:
        conn.close()


@app.route("/api/history/clear", methods=["POST"])
def clear_history():
    """Clear recorded scan history."""
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_history")
        conn.commit()
        return jsonify({"message": "Scan history cleared successfully."}), 200
    except Exception as e:
        app.logger.error(f"Error clearing scan history: {e}")
        return jsonify({"error": "Failed to clear history."}), 500
    finally:
        conn.close()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_DEBUG", "False").lower() in ("true", "1")
    print(f"\n[+] Phishing Detection Web Server starting on http://127.0.0.1:{port}")
    print("[+] Press Ctrl+C in terminal to stop server.\n")
    app.run(host="127.0.0.1", port=port, debug=debug_mode)
