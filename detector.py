"""
detector.py — Autonomous Cyber Threat Detection Engine
The core agentic loop: Perceive → Analyze → Decide → Act → Learn
Author: Akash S (Team Leader / Architecture)
"""

import time
import random
import threading
from datetime import datetime
from collections import deque
from agent.classifier import ThreatClassifier, FEATURE_COLUMNS
from agent.mitigator import Mitigator
from agent.logger import IncidentLogger

# ── Threat event templates for simulation ────────────────────────────────────
THREAT_TEMPLATES = {
    "SSH-Bruteforce": {
        "detail": "Multiple failed SSH login attempts detected",
        "src_port_range": (1024, 65535),
        "dst_port": 22,
        "pkt_count_range": (80, 200),
        "login_attempts_range": (50, 200),
    },
    "SQL-Injection": {
        "detail": "Malicious SQL payload detected in HTTP POST request",
        "src_port_range": (1024, 65535),
        "dst_port": 80,
        "pkt_count_range": (5, 30),
        "login_attempts_range": (0, 2),
    },
    "DDoS": {
        "detail": "UDP flood attack from multiple sources detected",
        "src_port_range": (1, 1024),
        "dst_port": 53,
        "pkt_count_range": (5000, 20000),
        "login_attempts_range": (0, 0),
    },
    "Ransomware": {
        "detail": "Mass file encryption pattern detected (.locked extension)",
        "src_port_range": (445, 445),
        "dst_port": 445,
        "pkt_count_range": (200, 800),
        "login_attempts_range": (0, 1),
    },
    "Malware-C2": {
        "detail": "Periodic outbound beaconing to known C2 server",
        "src_port_range": (1024, 65535),
        "dst_port": 443,
        "pkt_count_range": (10, 50),
        "login_attempts_range": (0, 0),
    },
    "PortScan": {
        "detail": "SYN scan across multiple ports detected",
        "src_port_range": (1024, 65535),
        "dst_port": 0,
        "pkt_count_range": (500, 2000),
        "login_attempts_range": (0, 0),
    },
    "DataExfiltration": {
        "detail": "Abnormally large outbound data transfer detected",
        "src_port_range": (1024, 65535),
        "dst_port": 443,
        "pkt_count_range": (1000, 5000),
        "login_attempts_range": (0, 0),
    },
    "PrivilegeEscalation": {
        "detail": "Sudo exploit attempt detected (CVE-2021-3156)",
        "src_port_range": (0, 0),
        "dst_port": 0,
        "pkt_count_range": (5, 20),
        "login_attempts_range": (1, 5),
    },
    "DNS-Tunneling": {
        "detail": "Encoded data in DNS TXT queries detected",
        "src_port_range": (1024, 65535),
        "dst_port": 53,
        "pkt_count_range": (100, 500),
        "login_attempts_range": (0, 0),
    },
    "ARP-Spoofing": {
        "detail": "Duplicate ARP replies from two MACs for same IP",
        "src_port_range": (0, 0),
        "dst_port": 0,
        "pkt_count_range": (50, 200),
        "login_attempts_range": (0, 0),
    },
    "XSS": {
        "detail": "Cross-site scripting payload in HTTP request",
        "src_port_range": (1024, 65535),
        "dst_port": 80,
        "pkt_count_range": (3, 20),
        "login_attempts_range": (0, 0),
    },
    "GeoAnomaly": {
        "detail": "Login attempt from unexpected geographic location",
        "src_port_range": (1024, 65535),
        "dst_port": 443,
        "pkt_count_range": (5, 30),
        "login_attempts_range": (1, 3),
    },
    "BENIGN": {
        "detail": "Normal network activity",
        "src_port_range": (1024, 65535),
        "dst_port": 443,
        "pkt_count_range": (5, 40),
        "login_attempts_range": (0, 1),
    },
}

# Weighted threat distribution (more benign than threats)
THREAT_WEIGHTS = {
    "BENIGN": 0.40,
    "SSH-Bruteforce": 0.08,
    "SQL-Injection": 0.07,
    "DDoS": 0.07,
    "Ransomware": 0.05,
    "Malware-C2": 0.06,
    "PortScan": 0.06,
    "DataExfiltration": 0.05,
    "PrivilegeEscalation": 0.04,
    "DNS-Tunneling": 0.04,
    "ARP-Spoofing": 0.03,
    "XSS": 0.03,
    "GeoAnomaly": 0.02,
}

PRIVATE_IPS = [
    "10.0.0.{}", "192.168.1.{}", "172.16.0.{}"
]
PUBLIC_IPS = [
    "185.220.101.{}", "91.108.56.{}", "203.0.113.{}",
    "45.142.212.{}", "77.91.124.{}", "104.21.55.{}"
]


def _random_ip(private=True):
    template = random.choice(PRIVATE_IPS if private else PUBLIC_IPS)
    return template.format(random.randint(2, 254))


def _generate_event_features(threat_type: str) -> list:
    """Generate realistic feature vector for a given threat type."""
    t = THREAT_TEMPLATES[threat_type]
    src_port = random.randint(*t["src_port_range"]) if t["src_port_range"][0] > 0 else 0
    dst_port = t["dst_port"] if t["dst_port"] > 0 else random.randint(1, 1024)
    pkt_count = random.randint(*t["pkt_count_range"])
    byte_count = pkt_count * random.randint(64, 1500)
    avg_pkt = byte_count / max(pkt_count, 1)
    login_attempts = random.randint(*t["login_attempts_range"])

    # Flags vary by threat
    syn = 1 if threat_type in ("SSH-Bruteforce", "PortScan", "DDoS") else random.randint(0, 1)
    rst = 1 if threat_type == "PortScan" else random.randint(0, 1)
    ack = random.randint(0, 1)
    fin = random.randint(0, 1)
    psh = 1 if threat_type in ("SQL-Injection", "XSS") else random.randint(0, 1)
    urg = 1 if threat_type == "DDoS" else 0

    protocol = {"SSH-Bruteforce": 6, "DDoS": 17, "DNS-Tunneling": 17}.get(threat_type, random.choice([6, 17]))

    fwd = int(pkt_count * 0.6)
    bwd = pkt_count - fwd
    fwd_bytes = int(byte_count * 0.7)
    bwd_bytes = byte_count - fwd_bytes

    return [
        round(random.uniform(0.001, 60.0), 4),  # duration
        protocol,                                 # protocol_type
        src_port,                                 # src_port
        dst_port,                                 # dst_port
        pkt_count,                                # pkt_count
        byte_count,                               # byte_count
        round(avg_pkt, 2),                        # avg_pkt_size
        round(random.uniform(0.0001, 0.5), 6),   # flow_iat_mean
        round(random.uniform(0.0, 0.3), 6),      # flow_iat_std
        fwd,                                      # fwd_pkt_count
        bwd,                                      # bwd_pkt_count
        fwd_bytes,                                # fwd_byte_count
        bwd_bytes,                                # bwd_byte_count
        syn, ack, rst, fin, psh, urg,             # flags
        login_attempts,                           # login_attempts
    ]


class ThreatDetector:
    """
    Autonomous Cyber Threat Detection Agent.

    Agentic loop:
        1. PERCEIVE  — read incoming network events
        2. ANALYZE   — classify using ML model
        3. DECIDE    — determine response action
        4. ACT       — execute mitigation
        5. LOG       — record incident
    """

    def __init__(self):
        self.classifier = ThreatClassifier()
        self.mitigator = Mitigator()
        self.logger = IncidentLogger()
        self.running = False
        self.events = deque(maxlen=500)   # rolling event buffer
        self.stats = {
            "total_events": 0,
            "threats_detected": 0,
            "threats_blocked": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        self._lock = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self, interval: float = 1.5):
        """Start the autonomous monitoring loop."""
        print("\n" + "="*60)
        print("  CYBERGUARD AGENT — STARTING AUTONOMOUS MONITORING")
        print("="*60)
        self.running = True
        self._ensure_model()
        thread = threading.Thread(target=self._monitoring_loop, args=(interval,), daemon=True)
        thread.start()
        print("[Agent] Monitoring active. Press Ctrl+C to stop.\n")
        return thread

    def stop(self):
        """Stop the monitoring loop."""
        self.running = False
        print("[Agent] Monitoring stopped.")

    def analyze_event(self, features: list, src_ip: str = None, dst_ip: str = None, raw_detail: str = None) -> dict:
        """
        Process a single network event through the full agentic pipeline.

        Returns a fully populated event dict.
        """
        # 1. ANALYZE — classify with ML
        result = self.classifier.predict(features)

        # 2. BUILD event record
        event = {
            "id": f"evt_{int(time.time() * 1000)}_{random.randint(100, 999)}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src_ip or _random_ip(private=result["is_threat"]),
            "dst_ip": dst_ip or _random_ip(private=True),
            "threat_type": result["label"],
            "severity": result["severity"],
            "confidence": result["confidence"],
            "is_threat": result["is_threat"],
            "detail": raw_detail or THREAT_TEMPLATES.get(result["label"], {}).get("detail", ""),
            "action_taken": "none",
            "blocked": False,
        }

        # 3. ACT — mitigate if threat
        if event["is_threat"]:
            mitigation = self.mitigator.respond(event)
            event["action_taken"] = mitigation["action"]
            event["blocked"] = mitigation["blocked"]

        # 4. LOG
        self.logger.log_event(event)

        # 5. UPDATE STATS
        with self._lock:
            self.stats["total_events"] += 1
            if event["is_threat"]:
                self.stats["threats_detected"] += 1
                if event["blocked"]:
                    self.stats["threats_blocked"] += 1
            self.stats[event["severity"]] = self.stats.get(event["severity"], 0) + 1
            self.events.appendleft(event)

        return event

    def get_recent_events(self, n: int = 50) -> list:
        """Return the n most recent events."""
        with self._lock:
            return list(self.events)[:n]

    def get_stats(self) -> dict:
        with self._lock:
            return dict(self.stats)

    # ── Internal ─────────────────────────────────────────────────────────────

    def _monitoring_loop(self, interval: float):
        """Continuously simulate and process network events."""
        while self.running:
            threat_type = random.choices(
                list(THREAT_WEIGHTS.keys()),
                weights=list(THREAT_WEIGHTS.values()),
                k=1,
            )[0]
            features = _generate_event_features(threat_type)
            event = self.analyze_event(features)
            self._print_event(event)
            time.sleep(interval + random.uniform(0, interval * 0.5))

    def _print_event(self, event: dict):
        """Pretty-print event to console."""
        from colorama import Fore, Style, init
        init(autoreset=True)

        SEV_COLOR = {
            "critical": Fore.RED,
            "high": Fore.YELLOW,
            "medium": Fore.CYAN,
            "low": Fore.GREEN,
        }
        color = SEV_COLOR.get(event["severity"], Fore.WHITE)
        status = f"[{event['action_taken'].upper()}]" if event["is_threat"] else "[SAFE]"
        print(
            f"{Fore.WHITE}{event['timestamp']}  "
            f"{color}{event['severity'].upper():<8}  "
            f"{Fore.WHITE}{event['threat_type']:<22}  "
            f"{Fore.LIGHTBLACK_EX}{event['src_ip']:<18}  "
            f"{color}{status}{Style.RESET_ALL}"
        )

    def _ensure_model(self):
        """Make sure the classifier is trained and ready."""
        import os
        model_path = os.path.join(os.path.dirname(__file__), "..", "models", "classifier.pkl")
        if not os.path.exists(model_path):
            print("[Agent] No trained model found. Training on synthetic data...")
            from data.generate_data import generate_dataset
            df = generate_dataset(n_samples=8000)
            self.classifier.train(df)
        else:
            self.classifier._load_or_train()
