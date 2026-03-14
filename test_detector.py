"""
test_detector.py — Unit Tests for CyberGuard Agent
Run with: pytest tests/
Author: Akash S
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from data.generate_data import generate_dataset, generate_sample, THREAT_CONFIGS
from agent.classifier import ThreatClassifier, THREAT_LABELS, FEATURE_COLUMNS
from agent.mitigator import Mitigator, MITIGATION_RULES
from agent.logger import IncidentLogger
from agent.detector import ThreatDetector, _generate_event_features


# ── Data Generation Tests ─────────────────────────────────────────────────────

class TestDataGeneration:

    def test_generate_sample_returns_dict(self):
        sample = generate_sample("BENIGN")
        assert isinstance(sample, dict)

    def test_generate_sample_has_all_columns(self):
        sample = generate_sample("SSH-Bruteforce")
        for col in FEATURE_COLUMNS:
            assert col in sample, f"Missing column: {col}"

    def test_generate_sample_label_correct(self):
        for label in THREAT_CONFIGS:
            sample = generate_sample(label)
            assert sample["label"] == label

    def test_generate_dataset_shape(self):
        df = generate_dataset(n_samples=100, save=False)
        assert len(df) == 100
        assert "label" in df.columns
        assert len(df.columns) == len(FEATURE_COLUMNS) + 1  # features + label

    def test_generate_dataset_has_all_labels(self):
        df = generate_dataset(n_samples=500, save=False)
        unique_labels = set(df["label"].unique())
        expected = set(THREAT_CONFIGS.keys())
        # Most labels should appear in 500 samples
        assert len(unique_labels) >= 8

    def test_no_negative_values_in_counts(self):
        df = generate_dataset(n_samples=200, save=False)
        assert (df["pkt_count"] > 0).all()
        assert (df["byte_count"] > 0).all()


# ── Classifier Tests ──────────────────────────────────────────────────────────

class TestClassifier:

    @pytest.fixture
    def trained_classifier(self):
        clf = ThreatClassifier()
        df = generate_dataset(n_samples=1000, save=False)
        clf.train(df)
        return clf

    def test_train_returns_accuracy(self, trained_classifier):
        df = generate_dataset(n_samples=200, save=False)
        result = trained_classifier.train(df)
        assert "accuracy" in result
        assert 0.0 <= result["accuracy"] <= 1.0

    def test_predict_returns_expected_keys(self, trained_classifier):
        sample = generate_sample("SSH-Bruteforce")
        features = [sample[col] for col in FEATURE_COLUMNS]
        result = trained_classifier.predict(features)
        assert "label" in result
        assert "severity" in result
        assert "confidence" in result
        assert "is_threat" in result

    def test_predict_confidence_range(self, trained_classifier):
        sample = generate_sample("DDoS")
        features = [sample[col] for col in FEATURE_COLUMNS]
        result = trained_classifier.predict(features)
        assert 0.0 <= result["confidence"] <= 100.0

    def test_benign_prediction_not_threat(self, trained_classifier):
        """BENIGN samples should generally not be flagged as threats."""
        correct = 0
        for _ in range(20):
            sample = generate_sample("BENIGN")
            features = [sample[col] for col in FEATURE_COLUMNS]
            result = trained_classifier.predict(features)
            if not result["is_threat"]:
                correct += 1
        assert correct >= 10  # At least 50% correct for benign

    def test_predict_batch(self, trained_classifier):
        import pandas as pd
        df = generate_dataset(n_samples=50, save=False)
        result_df = trained_classifier.predict_batch(df)
        assert "predicted_label" in result_df.columns
        assert "severity" in result_df.columns
        assert "confidence" in result_df.columns
        assert len(result_df) == 50


# ── Mitigator Tests ───────────────────────────────────────────────────────────

class TestMitigator:

    def test_respond_critical_threat_blocked(self):
        mit = Mitigator()
        event = {
            "threat_type": "SSH-Bruteforce",
            "severity": "critical",
            "src_ip": "1.2.3.4",
            "dst_ip": "10.0.0.1",
            "is_threat": True,
        }
        result = mit.respond(event)
        assert result["blocked"] is True
        assert result["action"] == "block_ip"

    def test_respond_benign_no_action(self):
        mit = Mitigator()
        event = {
            "threat_type": "BENIGN",
            "severity": "low",
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.1",
            "is_threat": False,
        }
        result = mit.respond(event)
        assert result["action"] == "none"

    def test_all_threat_types_have_rules(self):
        for threat in THREAT_LABELS:
            if threat == "BENIGN":
                continue
            assert threat in MITIGATION_RULES, f"No mitigation rule for: {threat}"

    def test_blocked_ip_tracked(self):
        mit = Mitigator()
        event = {
            "threat_type": "SSH-Bruteforce",
            "severity": "critical",
            "src_ip": "9.9.9.9",
            "dst_ip": "10.0.0.1",
            "is_threat": True,
        }
        mit.respond(event)
        assert mit.is_blocked("9.9.9.9")

    def test_action_summary_increments(self):
        mit = Mitigator()
        event = {"threat_type": "PortScan", "severity": "medium", "src_ip": "1.1.1.1", "dst_ip": "10.0.0.1", "is_threat": True}
        mit.respond(event)
        mit.respond(event)
        summary = mit.get_action_summary()
        assert summary.get("log_alert", 0) >= 2


# ── Logger Tests ──────────────────────────────────────────────────────────────

class TestLogger:

    def _make_event(self, is_threat=True, severity="critical", action="block_ip", blocked=True):
        return {
            "id": "test_123",
            "timestamp": "2024-01-01 12:00:00",
            "src_ip": "1.2.3.4",
            "dst_ip": "10.0.0.1",
            "threat_type": "SSH-Bruteforce" if is_threat else "BENIGN",
            "severity": severity,
            "confidence": 95.0,
            "is_threat": is_threat,
            "detail": "Test event",
            "action_taken": action,
            "blocked": blocked,
        }

    def test_log_event_increments_count(self):
        logger = IncidentLogger()
        logger.log_event(self._make_event())
        logger.log_event(self._make_event())
        assert len(logger.get_incidents()) == 2

    def test_report_structure(self):
        logger = IncidentLogger()
        for _ in range(5):
            logger.log_event(self._make_event())
        report = logger.generate_report()
        assert "report_id" in report
        assert "summary" in report
        assert "severity_breakdown" in report
        assert report["summary"]["total_events"] == 5

    def test_clear_resets_incidents(self):
        logger = IncidentLogger()
        logger.log_event(self._make_event())
        logger.clear()
        assert len(logger.get_incidents()) == 0


# ── Detector Integration Test ─────────────────────────────────────────────────

class TestDetector:

    def test_analyze_event_returns_full_record(self):
        detector = ThreatDetector()
        df = generate_dataset(n_samples=500, save=False)
        detector.classifier.train(df)

        sample = generate_sample("DDoS")
        features = [sample[col] for col in FEATURE_COLUMNS]
        event = detector.analyze_event(features)

        assert "id" in event
        assert "threat_type" in event
        assert "severity" in event
        assert "action_taken" in event
        assert "confidence" in event

    def test_stats_increment(self):
        detector = ThreatDetector()
        df = generate_dataset(n_samples=500, save=False)
        detector.classifier.train(df)

        for _ in range(5):
            sample = generate_sample("SSH-Bruteforce")
            features = [sample[col] for col in FEATURE_COLUMNS]
            detector.analyze_event(features)

        stats = detector.get_stats()
        assert stats["total_events"] >= 5

    def test_generate_event_features_length(self):
        features = _generate_event_features("Ransomware")
        assert len(features) == len(FEATURE_COLUMNS)
