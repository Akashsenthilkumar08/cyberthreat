"""
generate_data.py — Synthetic Network Log Dataset Generator
Generates labelled network flow data for training the ML classifier.
Author: Preethika K R (ML Engineer)
"""

import numpy as np
import pandas as pd
import random
import os

THREAT_CONFIGS = {
    "BENIGN": {
        "weight": 0.40,
        "pkt_range": (5, 100),
        "byte_multiplier": (64, 512),
        "duration_range": (0.1, 30.0),
        "login_range": (0, 1),
        "flags": {"syn": 0.3, "ack": 0.8, "rst": 0.05, "fin": 0.4, "psh": 0.5, "urg": 0.0},
    },
    "SSH-Bruteforce": {
        "weight": 0.08,
        "pkt_range": (80, 500),
        "byte_multiplier": (64, 256),
        "duration_range": (0.5, 120.0),
        "login_range": (50, 300),
        "flags": {"syn": 0.9, "ack": 0.5, "rst": 0.7, "fin": 0.3, "psh": 0.2, "urg": 0.0},
    },
    "SQL-Injection": {
        "weight": 0.07,
        "pkt_range": (3, 30),
        "byte_multiplier": (200, 2000),
        "duration_range": (0.001, 2.0),
        "login_range": (0, 2),
        "flags": {"syn": 0.4, "ack": 0.8, "rst": 0.1, "fin": 0.4, "psh": 0.9, "urg": 0.0},
    },
    "DDoS": {
        "weight": 0.07,
        "pkt_range": (5000, 50000),
        "byte_multiplier": (40, 100),
        "duration_range": (10.0, 300.0),
        "login_range": (0, 0),
        "flags": {"syn": 0.95, "ack": 0.1, "rst": 0.05, "fin": 0.0, "psh": 0.1, "urg": 0.8},
    },
    "Ransomware": {
        "weight": 0.05,
        "pkt_range": (200, 1000),
        "byte_multiplier": (512, 4096),
        "duration_range": (5.0, 60.0),
        "login_range": (0, 2),
        "flags": {"syn": 0.5, "ack": 0.8, "rst": 0.1, "fin": 0.3, "psh": 0.6, "urg": 0.0},
    },
    "Malware-C2": {
        "weight": 0.06,
        "pkt_range": (10, 80),
        "byte_multiplier": (64, 512),
        "duration_range": (0.1, 5.0),
        "login_range": (0, 0),
        "flags": {"syn": 0.6, "ack": 0.7, "rst": 0.05, "fin": 0.2, "psh": 0.4, "urg": 0.0},
    },
    "PortScan": {
        "weight": 0.06,
        "pkt_range": (500, 5000),
        "byte_multiplier": (40, 80),
        "duration_range": (0.5, 30.0),
        "login_range": (0, 0),
        "flags": {"syn": 0.98, "ack": 0.02, "rst": 0.8, "fin": 0.0, "psh": 0.0, "urg": 0.0},
    },
    "DataExfiltration": {
        "weight": 0.05,
        "pkt_range": (1000, 10000),
        "byte_multiplier": (1024, 8192),
        "duration_range": (5.0, 300.0),
        "login_range": (0, 0),
        "flags": {"syn": 0.4, "ack": 0.9, "rst": 0.0, "fin": 0.5, "psh": 0.8, "urg": 0.0},
    },
    "PrivilegeEscalation": {
        "weight": 0.04,
        "pkt_range": (5, 30),
        "byte_multiplier": (128, 512),
        "duration_range": (0.1, 5.0),
        "login_range": (1, 10),
        "flags": {"syn": 0.2, "ack": 0.7, "rst": 0.3, "fin": 0.2, "psh": 0.5, "urg": 0.0},
    },
    "DNS-Tunneling": {
        "weight": 0.04,
        "pkt_range": (100, 800),
        "byte_multiplier": (50, 200),
        "duration_range": (1.0, 60.0),
        "login_range": (0, 0),
        "flags": {"syn": 0.3, "ack": 0.6, "rst": 0.05, "fin": 0.3, "psh": 0.2, "urg": 0.0},
    },
    "ARP-Spoofing": {
        "weight": 0.03,
        "pkt_range": (50, 300),
        "byte_multiplier": (28, 42),
        "duration_range": (0.5, 20.0),
        "login_range": (0, 0),
        "flags": {"syn": 0.0, "ack": 0.0, "rst": 0.0, "fin": 0.0, "psh": 0.0, "urg": 0.0},
    },
    "XSS": {
        "weight": 0.03,
        "pkt_range": (3, 20),
        "byte_multiplier": (300, 3000),
        "duration_range": (0.001, 1.0),
        "login_range": (0, 1),
        "flags": {"syn": 0.3, "ack": 0.8, "rst": 0.05, "fin": 0.4, "psh": 0.95, "urg": 0.0},
    },
    "GeoAnomaly": {
        "weight": 0.02,
        "pkt_range": (5, 40),
        "byte_multiplier": (100, 1000),
        "duration_range": (0.1, 10.0),
        "login_range": (1, 5),
        "flags": {"syn": 0.5, "ack": 0.7, "rst": 0.1, "fin": 0.3, "psh": 0.4, "urg": 0.0},
    },
}

COLUMNS = [
    "duration", "protocol_type", "src_port", "dst_port",
    "pkt_count", "byte_count", "avg_pkt_size",
    "flow_iat_mean", "flow_iat_std", "fwd_pkt_count",
    "bwd_pkt_count", "fwd_byte_count", "bwd_byte_count",
    "syn_flag", "ack_flag", "rst_flag", "fin_flag",
    "psh_flag", "urg_flag", "login_attempts", "label",
]


def generate_sample(label: str) -> dict:
    """Generate a single labelled network flow sample."""
    cfg = THREAT_CONFIGS[label]

    pkt_count = random.randint(*cfg["pkt_range"])
    byte_mul = random.randint(*cfg["byte_multiplier"])
    byte_count = pkt_count * byte_mul
    avg_pkt = byte_count / max(pkt_count, 1)
    duration = round(random.uniform(*cfg["duration_range"]), 4)
    login_attempts = random.randint(*cfg["login_range"])
    protocol = random.choice([6, 17, 1])

    fwd = int(pkt_count * random.uniform(0.4, 0.7))
    bwd = pkt_count - fwd
    fwd_bytes = int(byte_count * 0.6)
    bwd_bytes = byte_count - fwd_bytes

    flags = cfg["flags"]
    return {
        "duration": duration,
        "protocol_type": protocol,
        "src_port": random.randint(1024, 65535),
        "dst_port": random.randint(1, 1024),
        "pkt_count": pkt_count,
        "byte_count": byte_count,
        "avg_pkt_size": round(avg_pkt, 2),
        "flow_iat_mean": round(random.uniform(0.00001, 0.5), 6),
        "flow_iat_std": round(random.uniform(0.0, 0.3), 6),
        "fwd_pkt_count": fwd,
        "bwd_pkt_count": bwd,
        "fwd_byte_count": fwd_bytes,
        "bwd_byte_count": bwd_bytes,
        "syn_flag": 1 if random.random() < flags["syn"] else 0,
        "ack_flag": 1 if random.random() < flags["ack"] else 0,
        "rst_flag": 1 if random.random() < flags["rst"] else 0,
        "fin_flag": 1 if random.random() < flags["fin"] else 0,
        "psh_flag": 1 if random.random() < flags["psh"] else 0,
        "urg_flag": 1 if random.random() < flags["urg"] else 0,
        "login_attempts": login_attempts,
        "label": label,
    }


def generate_dataset(n_samples: int = 10000, save: bool = True) -> pd.DataFrame:
    """
    Generate a complete labelled dataset for training.

    Args:
        n_samples: Total number of samples to generate.
        save: Whether to save as CSV.

    Returns:
        pandas DataFrame with features and labels.
    """
    print(f"[DataGen] Generating {n_samples} labelled samples...")

    labels = list(THREAT_CONFIGS.keys())
    weights = [THREAT_CONFIGS[l]["weight"] for l in labels]

    chosen_labels = random.choices(labels, weights=weights, k=n_samples)
    records = [generate_sample(label) for label in chosen_labels]

    df = pd.DataFrame(records, columns=COLUMNS)

    if save:
        out_dir = os.path.join(os.path.dirname(__file__))
        os.makedirs(out_dir, exist_ok=True)
        csv_path = os.path.join(out_dir, "sample_logs.csv")
        df.to_csv(csv_path, index=False)
        print(f"[DataGen] Dataset saved to {csv_path}")
        print(f"[DataGen] Label distribution:\n{df['label'].value_counts().to_string()}")

    return df


if __name__ == "__main__":
    df = generate_dataset(n_samples=10000)
    print(f"\n[DataGen] Generated {len(df)} samples with {df['label'].nunique()} classes.")
