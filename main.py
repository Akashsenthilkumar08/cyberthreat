"""
main.py — CyberGuard Agent Entry Point
Starts the autonomous detection agent and serves the live dashboard.
Author: Akash S (Team Leader)
"""

import os
import sys
import time
import threading
import json
from flask import Flask, jsonify, render_template_string, send_from_directory

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from agent.detector import ThreatDetector

# ── Flask App ─────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder="dashboard")
detector = ThreatDetector()


@app.route("/")
def index():
    """Serve the live dashboard."""
    return send_from_directory("dashboard", "index.html")


@app.route("/api/events")
def api_events():
    """Return the 50 most recent events as JSON."""
    events = detector.get_recent_events(n=50)
    # Convert datetime objects to strings if needed
    return jsonify(events)


@app.route("/api/stats")
def api_stats():
    """Return current session statistics."""
    return jsonify(detector.get_stats())


@app.route("/api/report")
def api_report():
    """Generate and return a full incident report."""
    report = detector.logger.generate_report()
    return jsonify(report)


@app.route("/api/blocked")
def api_blocked():
    """Return lists of blocked IPs and isolated hosts."""
    return jsonify({
        "blocked_ips": detector.mitigator.get_blocked_ips(),
        "isolated_hosts": detector.mitigator.get_isolated_hosts(),
        "action_summary": detector.mitigator.get_action_summary(),
    })


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print("\n" + "=" * 60)
    print("  🛡️  CYBERGUARD — AUTONOMOUS CYBER THREAT DETECTION AGENT")
    print("  Team: Akash S | Preethika K R | Ragul M | Deerandaran M")
    print("=" * 60)

    # Start the autonomous detection loop in background
    detector.start(interval=1.5)

    # Give agent a moment to initialize
    time.sleep(1)

    print("\n[Server] Starting dashboard server...")
    print("[Server] Dashboard available at: http://localhost:5000\n")

    # Start Flask in main thread
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False,
    )


if __name__ == "__main__":
    main()
