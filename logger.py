"""
logger.py — Incident Logging & Report Generator
Records all security events and generates incident reports.
Author: Ragul M (Backend Dev)
"""

import os
import json
import logging
from datetime import datetime

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# Configure file logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "cyberguard.log")),
        logging.StreamHandler(),
    ],
)
_file_logger = logging.getLogger("cyberguard")


class IncidentLogger:
    """Logs events and generates incident reports."""

    def __init__(self):
        self.incidents = []
        self.session_start = datetime.now()

    def log_event(self, event: dict):
        """Log a single security event."""
        self.incidents.append(event)
        if event["is_threat"]:
            _file_logger.warning(
                f"THREAT | {event['threat_type']} | {event['severity'].upper()} | "
                f"src={event['src_ip']} | action={event['action_taken']} | "
                f"confidence={event['confidence']}%"
            )

    def generate_report(self) -> dict:
        """Generate a full incident report for the current session."""
        threats = [e for e in self.incidents if e["is_threat"]]
        blocked = [e for e in threats if e.get("blocked")]

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        threat_type_counts = {}

        for e in threats:
            sev = e.get("severity", "low")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            tt = e.get("threat_type", "Unknown")
            threat_type_counts[tt] = threat_type_counts.get(tt, 0) + 1

        report = {
            "report_id": f"RPT-{int(datetime.now().timestamp())}",
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "session_start": self.session_start.strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "total_events": len(self.incidents),
                "total_threats": len(threats),
                "threats_blocked": len(blocked),
                "block_rate": round(len(blocked) / max(len(threats), 1) * 100, 1),
            },
            "severity_breakdown": severity_counts,
            "threat_type_breakdown": threat_type_counts,
            "top_source_ips": self._top_source_ips(threats, n=5),
            "recent_incidents": threats[-10:],
        }

        # Save to disk
        report_path = os.path.join(LOG_DIR, f"report_{report['report_id']}.json")
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        _file_logger.info(f"Incident report saved: {report_path}")

        return report

    def _top_source_ips(self, threats: list, n: int = 5) -> list:
        ip_counts = {}
        for e in threats:
            ip = e.get("src_ip", "unknown")
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def get_incidents(self) -> list:
        return list(self.incidents)

    def clear(self):
        self.incidents.clear()
        self.session_start = datetime.now()
