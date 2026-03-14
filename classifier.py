"""
classifier.py — ML Threat Classifier
Trains and uses a Random Forest model to classify network events as threats.
Author: Preethika K R (ML Engineer)
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

# Threat label definitions
THREAT_LABELS = [
    "BENIGN",
    "SSH-Bruteforce",
    "SQL-Injection",
    "DDoS",
    "Ransomware",
    "Malware-C2",
    "PortScan",
    "DataExfiltration",
    "PrivilegeEscalation",
    "DNS-Tunneling",
    "ARP-Spoofing",
    "XSS",
    "GeoAnomaly",
]

SEVERITY_MAP = {
    "BENIGN":              "low",
    "SSH-Bruteforce":      "critical",
    "SQL-Injection":       "critical",
    "DDoS":                "high",
    "Ransomware":          "critical",
    "Malware-C2":          "critical",
    "PortScan":            "medium",
    "DataExfiltration":    "critical",
    "PrivilegeEscalation": "high",
    "DNS-Tunneling":       "high",
    "ARP-Spoofing":        "high",
    "XSS":                 "medium",
    "GeoAnomaly":          "medium",
}

FEATURE_COLUMNS = [
    "duration", "protocol_type", "src_port", "dst_port",
    "pkt_count", "byte_count", "avg_pkt_size",
    "flow_iat_mean", "flow_iat_std", "fwd_pkt_count",
    "bwd_pkt_count", "fwd_byte_count", "bwd_byte_count",
    "syn_flag", "ack_flag", "rst_flag", "fin_flag",
    "psh_flag", "urg_flag", "login_attempts",
]

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "classifier.pkl")
SCALER_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "scaler.pkl")
ENCODER_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "encoder.pkl")


class ThreatClassifier:
    """Random Forest-based network threat classifier."""

    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.label_encoder.fit(THREAT_LABELS)
        self.trained = False

    def train(self, df: pd.DataFrame) -> dict:
        """Train the classifier on labelled network log data."""
        print("[Classifier] Starting model training...")

        X = df[FEATURE_COLUMNS].values
        y = self.label_encoder.transform(df["label"].values)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        X_train = self.scaler.fit_transform(X_train)
        X_test = self.scaler.transform(X_test)

        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            min_samples_split=5,
            random_state=42,
            n_jobs=-1,
            class_weight="balanced",
        )
        self.model.fit(X_train, y_train)
        self.trained = True

        y_pred = self.model.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        present_labels = sorted(set(y_test) | set(y_pred))
        present_names = list(self.label_encoder.inverse_transform(present_labels))
        report = classification_report(
            y_test, y_pred,
            labels=present_labels,
            target_names=present_names,
            output_dict=True,
            zero_division=0,
        )

        print(f"[Classifier] Training complete. Accuracy: {acc:.4f}")
        self._save_model()
        return {"accuracy": acc, "report": report}

    def predict(self, features: list) -> dict:
        """
        Predict threat type for a single network event.

        Args:
            features: List of 20 feature values matching FEATURE_COLUMNS order.

        Returns:
            dict with keys: label, severity, confidence, is_threat
        """
        if not self.trained:
            self._load_or_train()

        X = np.array(features).reshape(1, -1)
        X_scaled = self.scaler.transform(X)

        label_idx = self.model.predict(X_scaled)[0]
        proba = self.model.predict_proba(X_scaled)[0]
        confidence = float(proba[label_idx])
        label = self.label_encoder.inverse_transform([label_idx])[0]

        return {
            "label": label,
            "severity": SEVERITY_MAP.get(label, "low"),
            "confidence": round(confidence * 100, 2),
            "is_threat": label != "BENIGN",
        }

    def predict_batch(self, df: pd.DataFrame) -> pd.DataFrame:
        """Predict threats for a batch of events."""
        if not self.trained:
            self._load_or_train()

        X = df[FEATURE_COLUMNS].values
        X_scaled = self.scaler.transform(X)
        preds = self.model.predict(X_scaled)
        probas = self.model.predict_proba(X_scaled)

        labels = self.label_encoder.inverse_transform(preds)
        confidences = [round(probas[i][preds[i]] * 100, 2) for i in range(len(preds))]

        df = df.copy()
        df["predicted_label"] = labels
        df["severity"] = [SEVERITY_MAP.get(l, "low") for l in labels]
        df["confidence"] = confidences
        df["is_threat"] = labels != "BENIGN"
        return df

    def _save_model(self):
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        joblib.dump(self.model, MODEL_PATH)
        joblib.dump(self.scaler, SCALER_PATH)
        joblib.dump(self.label_encoder, ENCODER_PATH)
        print("[Classifier] Model saved.")

    def _load_or_train(self):
        if os.path.exists(MODEL_PATH):
            self.model = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)
            self.label_encoder = joblib.load(ENCODER_PATH)
            self.trained = True
            print("[Classifier] Loaded saved model.")
        else:
            # Train on synthetic data if no model exists
            from data.generate_data import generate_dataset
            df = generate_dataset(n_samples=5000)
            self.train(df)
