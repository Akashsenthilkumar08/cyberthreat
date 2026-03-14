"""
mitigator.py — Autonomous Threat Mitigation Engine
Decides and executes response actions for detected threats.
Author: Ragul M (Backend Dev)
"""

import time
from datetime import datetime

# Response action mapping per threat type
MITIGATION_RULES = {
    "SSH-Bruteforce": {
        "action": "block_ip",
        "description": "Source IP added to firewall blocklist",
        "blocked": True,
        "severity_required": "critical",
    },
    "SQL-Injection": {
        "action": "waf_rule",
        "description": "WAF rule applied; request dropped",
        "blocked": True,
        "severity_required": "critical",
    },
    "DDoS": {
        "action": "rate_limit",
        "description": "Rate limiting applied; upstream scrubbing enabled",
        "blocked": True,
        "severity_required": "high",
    },
    "Ransomware": {
        "action": "isolate_host",
        "description": "Host network isolated; SMB session terminated",
        "blocked": True,
        "severity_required": "critical",
    },
    "Malware-C2": {
        "action": "block_domain",
        "description": "C2 domain blocked at DNS; process killed",
        "blocked": True,
        "severity_required": "critical",
    },
    "PortScan": {
        "action": "log_alert",
        "description": "Port scan logged; SOC alerted",
        "blocked": False,
        "severity_required": "medium",
    },
    "DataExfiltration": {
        "action": "block_egress",
        "description": "Outbound traffic blocked; DLP alert raised",
        "blocked": True,
        "severity_required": "critical",
    },
    "PrivilegeEscalation": {
        "action": "kill_session",
        "description": "User session terminated; account locked",
        "blocked": True,
        "severity_required": "high",
    },
    "DNS-Tunneling": {
        "action": "block_dns",
        "description": "Suspicious DNS queries blocked; SOC alerted",
        "blocked": True,
        "severity_required": "high",
    },
    "ARP-Spoofing": {
        "action": "isolate_port",
        "description": "Switch port isolated; DAI inspection enabled",
        "blocked": True,
        "severity_required": "high",
    },
    "XSS": {
        "action": "sanitize_request",
        "description": "Request sanitized; CSP header enforced",
        "blocked": False,
        "severity_required": "medium",
    },
    "GeoAnomaly": {
        "action": "mfa_challenge",
        "description": "MFA challenge triggered; session flagged for review",
        "blocked": False,
        "severity_required": "medium",
    },
}

# Simulated blocklist (in production this would write to iptables/firewall API)
_blocked_ips = set()
_blocked_domains = set()
_isolated_hosts = set()


class Mitigator:
    """
    Autonomous response engine.
    Maps detected threats to mitigation actions and executes them.
    """

    def __init__(self):
        self.action_log = []

    def respond(self, event: dict) -> dict:
        """
        Execute the appropriate mitigation for a detected threat.

        Args:
            event: Threat event dict from the detector.

        Returns:
            dict with action taken and blocked status.
        """
        threat_type = event.get("threat_type", "BENIGN")
        src_ip = event.get("src_ip", "unknown")

        rule = MITIGATION_RULES.get(threat_type)
        if not rule:
            return {"action": "none", "blocked": False, "description": "No rule matched"}

        action = rule["action"]
        blocked = rule["blocked"]
        description = rule["description"]

        # Execute the action
        self._execute_action(action, src_ip, event)

        record = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "threat_type": threat_type,
            "src_ip": src_ip,
            "action": action,
            "blocked": blocked,
            "description": description,
        }
        self.action_log.append(record)

        return {"action": action, "blocked": blocked, "description": description}

    def _execute_action(self, action: str, src_ip: str, event: dict):
        """Simulate executing a mitigation action."""
        if action == "block_ip":
            _blocked_ips.add(src_ip)
        elif action == "isolate_host":
            _isolated_hosts.add(event.get("dst_ip", src_ip))
        elif action == "block_domain":
            _blocked_domains.add(f"c2-{src_ip}.example.com")
        # Other actions (rate_limit, waf_rule, etc.) would call external APIs in production

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        return ip in _blocked_ips

    def get_blocked_ips(self) -> list:
        return list(_blocked_ips)

    def get_isolated_hosts(self) -> list:
        return list(_isolated_hosts)

    def get_action_summary(self) -> dict:
        """Return a count of each action type taken."""
        summary = {}
        for record in self.action_log:
            action = record["action"]
            summary[action] = summary.get(action, 0) + 1
        return summary
