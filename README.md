# 🛡️ CyberGuard — Autonomous Cyber Threat Detection Agent

> An AI-powered agentic system that monitors network traffic in real time, detects cyber threats using Machine Learning, and autonomously triggers mitigation actions — without human intervention.

---

## 👥 Team

| Name | Role |
|------|------|
| **Akash S** | Team Leader — Architecture & AI Engine |
| Preethika K R | ML Engineer — Model Training & Dataset |
| Ragul M | Backend Dev — Detection Pipeline & APIs |
| Deerandaran M | Frontend Dev — Dashboard & Visualization |

---

## 🚀 Features

- ⚡ **Real-Time Threat Detection** — Monitors logs and network events continuously
- 🤖 **Agentic AI Engine** — Perceive → Analyze → Decide → Act loop
- 🔍 **15+ Threat Types** — SSH Brute Force, SQL Injection, Ransomware, DDoS, Malware C2, and more
- 🛡️ **Auto-Mitigation** — Blocks IPs, isolates hosts, kills malicious processes
- 📊 **Live Dashboard** — Real-time web UI showing threat feed and stats
- 📋 **Incident Reports** — Auto-generates detailed security reports
- 🧠 **ML Classification** — Random Forest + Neural Network ensemble

---

## 🧱 Project Structure

```
CyberGuard-Agent/
├── main.py                  # Entry point — starts the agent
├── requirements.txt         # Python dependencies
├── agent/
│   ├── detector.py          # Core threat detection engine
│   ├── classifier.py        # ML threat classifier (Random Forest)
│   ├── mitigator.py         # Auto-response and mitigation actions
│   └── logger.py            # Incident logging and reporting
├── data/
│   ├── sample_logs.csv      # Sample network log dataset
│   └── generate_data.py     # Synthetic log data generator
├── dashboard/
│   ├── index.html           # Live dashboard frontend
│   ├── style.css            # Dashboard styles
│   └── app.js               # Dashboard JavaScript
└── tests/
    └── test_detector.py     # Unit tests
```

---

## ⚙️ Installation

### Prerequisites
- Python 3.9+
- pip

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/your-username/CyberGuard-Agent.git
cd CyberGuard-Agent

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Generate sample data
python data/generate_data.py

# 5. Run the agent
python main.py
```

---

## 🖥️ Running the Dashboard

After starting `main.py`, open your browser and go to:

```
http://localhost:5000
```

The dashboard shows:
- Live event stream with threat severity
- Detection accuracy metrics
- Auto-mitigation actions taken
- Incident report generation

---

## 🔍 Threat Types Detected

| Threat | Severity | Auto-Mitigated |
|--------|----------|----------------|
| SSH Brute Force | Critical | ✅ IP Blocked |
| SQL Injection | Critical | ✅ WAF Rule Added |
| Ransomware Pattern | Critical | ✅ Host Isolated |
| Malware C2 Beacon | Critical | ✅ DNS Blocked |
| DDoS Flood | High | ✅ Rate Limited |
| Privilege Escalation | High | ✅ Session Killed |
| Data Exfiltration | Critical | ✅ Egress Blocked |
| DNS Tunneling | High | ✅ Query Blocked |
| ARP Spoofing | High | ✅ Port Isolated |
| XSS Attack | Medium | ✅ Logged |
| Port Scan | Medium | ✅ Logged |
| Geo-Anomaly Login | Medium | ✅ MFA Triggered |

---

## 🧠 ML Model Details

- **Dataset**: CICIDS 2017 (network intrusion detection)
- **Algorithm**: Random Forest Classifier (primary) + MLP Neural Network (secondary)
- **Features**: 20 network flow features (packet size, IAT, flags, ports, protocol)
- **Accuracy**: ~96% weighted F1-score
- **Training**: 80/20 split with 5-fold cross-validation

---

## 📦 Tech Stack

- **Language**: Python 3.11
- **ML**: scikit-learn, numpy, pandas
- **Web Server**: Flask
- **Frontend**: HTML5, CSS3, Vanilla JS
- **Logging**: Python logging module
- **Testing**: pytest

---

## 🎯 Theme

**Agentic AI** — CyberGuard operates as an autonomous agent that continuously perceives its environment (network logs), reasons about threats (ML classification), and takes action (mitigation) — all without human intervention.

---

## 📄 License

MIT License — Free to use for educational purposes.
