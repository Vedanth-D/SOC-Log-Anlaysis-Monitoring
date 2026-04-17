# 🛡️ SOC Log Analysis & Monitoring System

<div align="center">

![SOC Banner](https://img.shields.io/badge/SOC-Security%20Operations%20Center-red?style=for-the-badge&logo=shield&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white)
![React](https://img.shields.io/badge/React-18+-61DAFB?style=for-the-badge&logo=react&logoColor=black)
![Vite](https://img.shields.io/badge/Vite-8.0-646CFF?style=for-the-badge&logo=vite&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**A full-stack Security Operations Center (SOC) project for real-time log analysis, threat detection, and security monitoring.**

* Cybersecurity | MITRE ATT&CK Aligned*

</div>

---

## 📸 Project Screenshots
### 🖥️ Live Dashboard
![Dashboard](https://github.com/user-attachments/assets/a30a4f78-deb5-47a9-af91-3e14d8bcde42)

## 📋 Table of Contents

- [About the Project](#-about-the-project)
- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [How It Works](#-how-it-works)
- [Installation & Setup](#-installation--setup)
- [Usage](#-usage)
- [Threat Detection Rules](#-threat-detection-rules)
- [Dashboard Components](#-dashboard-components)
- [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
- [Sample Output](#-sample-output)
- [Future Improvements](#-future-improvements)
- [Author](#-author)

---

## 🔍 About the Project

This project simulates a **Security Operations Center (SOC)** environment with two core components:

1. **Python Backend** — Parses system/authentication logs, applies threat detection rules, and generates a JSON security report
2. **React Frontend** — A real-time monitoring dashboard with live charts, alert feeds, and log analysis

The system detects common cyberattacks like **brute force**, **port scanning**, **privilege escalation**, and **malicious IP activity** — the same techniques used in enterprise tools like **Splunk**, **IBM QRadar**, and **Elastic SIEM**.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔴 **Real-time Alerts** | Live CRITICAL/HIGH/MEDIUM/LOW alerts as events are processed |
| 📈 **Event Timeline** | 30-minute area chart showing events, threats, and critical incidents |
| 🥧 **Severity Distribution** | Pie chart showing breakdown of alert severity levels |
| 📊 **Top Source IPs** | Bar chart highlighting most active and malicious IPs |
| 🚨 **Threat Detection** | 5 automated detection rules (brute force, port scan, etc.) |
| 📄 **JSON Report** | Full security report exported to `soc_report.json` |
| 🔄 **Live / Pause Mode** | Toggle real-time log simulation on/off |
| 🖥️ **Log Feed** | Scrollable live log entries with timestamp, IP, user, severity |
| 📁 **Real Log Support** | Can analyze actual Linux `auth.log` files |
| ⚡ **Risk Scoring** | Automatic overall risk score: CRITICAL / HIGH / MEDIUM / LOW |

---

## 🛠️ Tech Stack

### Backend (Python)
- **Python 3.10+** — Core language
- **re** — Regex for log parsing
- **json** — Report generation
- **collections** — Counter and defaultdict for analysis
- **argparse** — CLI argument handling
- **datetime** — Timestamp processing

### Frontend (React)
- **React 18** — UI framework
- **Vite 8** — Build tool and dev server
- **Recharts** — Charts (AreaChart, PieChart, BarChart)
- **CSS-in-JS** — Inline styling with dark theme

---

## 📁 Project Structure

```
soc-project/
│
├── 📂 backend/
│   └── soc_log_analyzer.py      # Python threat detection engine
│
├── 📂 frontend/
│   ├── 📂 src/
│   │   └── App.jsx              # React SOC dashboard
│   ├── package.json
│   └── index.html
│
├── soc_report.json              # Auto-generated after running Python
└── README.md                    # This file
```

---

## 🔄 How It Works

```
┌─────────────────────────────────────────────────────────┐
│                    DATA FLOW                            │
└─────────────────────────────────────────────────────────┘

  [Linux Auth Logs / Simulated Logs]
              │
              ▼
  ┌─────────────────────┐
  │   Log Parser        │  ← Extracts: IP, User, Action,
  │   (Python Regex)    │    Timestamp, Service, Port
  └─────────────────────┘
              │
              ▼
  ┌─────────────────────┐
  │  Threat Detection   │  ← Applies 5 detection rules
  │  Engine             │    Generates severity-tagged alerts
  └─────────────────────┘
              │
              ▼
  ┌─────────────────────┐
  │  JSON Report        │  ← soc_report.json with risk score,
  │  Generator          │    top IPs, alert list, stats
  └─────────────────────┘
              │
              ▼
  ┌─────────────────────┐
  │  React Dashboard    │  ← Live charts, alert feed,
  │  (Recharts)         │    log viewer, severity stats
  └─────────────────────┘
```

---

## 🚀 Installation & Setup

### Prerequisites

Make sure you have these installed:

```bash
python --version    # 3.10 or above
node --version      # 16 or above
npm --version       # 8 or above
```

- 🐍 Python → [python.org](https://python.org)
- 🟢 Node.js → [nodejs.org](https://nodejs.org)

---

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/soc-project.git
cd soc-project
```

---

### 2️⃣ Set Up Python Backend

```bash
cd backend
python soc_log_analyzer.py
```

This will:
- Generate 150 simulated log entries
- Run all 5 threat detection rules
- Print a full report in the terminal
- Save `soc_report.json`

**To analyze a real log file:**
```bash
python soc_log_analyzer.py --file /var/log/auth.log
```

**To generate more logs:**
```bash
python soc_log_analyzer.py --generate 500
```

---

### 3️⃣ Set Up React Frontend

```bash
# From the root soc-project/ folder
npm create vite@latest frontend -- --template react
cd frontend
npm install
npm install recharts
```

Now paste the dashboard code into `src/App.jsx`, then:

```bash
npm run dev
```

Open browser → **http://localhost:5173**

---

## 💻 Usage

### Running the Python Analyzer

| Command | Description |
|---------|-------------|
| `python soc_log_analyzer.py` | Run with 150 simulated logs |
| `python soc_log_analyzer.py --generate 500` | Generate 500 fake logs |
| `python soc_log_analyzer.py --file auth.log` | Analyze a real log file |
| `python soc_log_analyzer.py --output report.json` | Custom output filename |

### Using the Dashboard

| Action | How |
|--------|-----|
| **Pause live feed** | Click the LIVE button (top right) |
| **View threat events only** | Click "THREAT EVENTS" tab |
| **See all logs** | Click "LOG FEED" tab |
| **Check active alerts** | Left panel shows CRITICAL/HIGH alerts |

---

## 🚨 Threat Detection Rules

### Rule 1 — Brute Force Detection
```
Trigger : 5+ failed login attempts from the same IP
Severity: HIGH / CRITICAL (if 20+ attempts)
Maps to : MITRE T1110
```

### Rule 2 — Port Scan Detection
```
Trigger : Single IP accessing 10+ unique ports
Severity: HIGH
Maps to : MITRE T1046
```

### Rule 3 — Known Malicious IP
```
Trigger : Any activity from threat intelligence IP list
Severity: CRITICAL
Maps to : MITRE T1133
```

### Rule 4 — Privilege Escalation
```
Trigger : Keywords: sudo, su -, chmod 777, visudo
Severity: HIGH
Maps to : MITRE T1548
```

### Rule 5 — Direct Root Login
```
Trigger : Successful login as root user
Severity: MEDIUM
Maps to : MITRE T1078
```

---

## 📊 Dashboard Components

### Stat Cards (Top Row)

| Card | What It Measures |
|------|-----------------|
| 📡 Total Events | Every log entry received this session |
| 🔴 Critical Alerts | Events from bad IPs or critical-severity actions |
| 🟠 High Severity | Failed logins, sudo failures, invalid users |
| 🚫 IPs Flagged | Events from known malicious IP addresses |
| ⚙️ Services Active | Unique services generating log events |

### Charts

| Chart | Type | Data Shown |
|-------|------|-----------|
| Event Timeline | Area Chart | Events, Threats, Criticals over 30 min |
| Severity Mix | Pie Chart | Distribution of CRITICAL/HIGH/MEDIUM/LOW/INFO |
| Top Source IPs | Bar Chart | Most active IPs (red = malicious) |

---

## 🎯 MITRE ATT&CK Mapping

This project detects the following MITRE ATT&CK techniques:

| Detection | Tactic | Technique | ID |
|-----------|--------|-----------|-----|
| Brute Force Login | Credential Access | Brute Force | T1110 |
| Port Scanning | Discovery | Network Service Discovery | T1046 |
| Privilege Escalation | Privilege Escalation | Abuse Elevation Control | T1548 |
| Malicious IP Activity | Initial Access | External Remote Services | T1133 |
| Root Account Login | Defense Evasion | Valid Accounts | T1078 |

---

## 📄 Sample Output

### Python Terminal Output
```
══════════════════════════════════════════════════════════
       SOC LOG ANALYSIS REPORT
══════════════════════════════════════════════════════════
  Generated : 2025-01-15T14:32:10
  Log Entries: 150  |  Alerts: 12
  Overall Risk Score: 🔴 CRITICAL
────────────────────────────────────────────────────────

📊 SEVERITY DISTRIBUTION
  🔴 CRITICAL     ██████ (6)
  🟠 HIGH         ████ (4)
  🟡 MEDIUM       ██ (2)

🚨 ALERTS

  🔴 [CRITICAL] Brute Force Attack
     47 failed login attempts from 192.168.100.99 targeting: root
     Evidence: Failed password for root from 192.168.100.99

  🔴 [CRITICAL] Known Malicious IP
     Activity from known malicious IP 203.0.113.44
     Evidence: Connection attempt from 203.0.113.44
```

### JSON Report (`soc_report.json`)
```json
{
  "report_metadata": {
    "generated_at": "2025-01-15T14:32:10",
    "tool": "SOC Log Analyzer v1.0",
    "total_logs": 150,
    "total_alerts": 12
  },
  "summary": {
    "severity_distribution": {
      "CRITICAL": 6,
      "HIGH": 4,
      "MEDIUM": 2
    },
    "risk_score": "CRITICAL"
  },
  "top_source_ips": [
    { "ip": "192.168.100.99", "count": 47 },
    { "ip": "10.0.0.1",       "count": 12 }
  ],
  "alerts": [...]
}
```

---

## 🔮 Future Improvements

- [ ] Connect Python backend to React via Flask/FastAPI REST API
- [ ] Add email/SMS notifications for CRITICAL alerts
- [ ] Integrate real threat intelligence feeds (AbuseIPDB, VirusTotal)
- [ ] Add user authentication to the dashboard
- [ ] Support Windows Event Logs (`.evtx` files)
- [ ] Add GeoIP mapping to show attack origin on a world map
- [ ] Machine learning anomaly detection
- [ ] Docker containerization for easy deployment
- [ ] Export reports to PDF

---

## 📚 References & Concepts Used

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Linux auth.log Format](https://www.man7.org/linux/man-pages/man8/pam.8.html)
- [Recharts Documentation](https://recharts.org/)
- [Vite Documentation](https://vitejs.dev/)

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

⭐ **If this project helped you, please give it a star!** ⭐

Made with ❤️ for Cybersecurity Projects

</div>
