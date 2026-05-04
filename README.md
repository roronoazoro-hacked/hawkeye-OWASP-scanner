# 🦅 Hawkeye OWASP Scanner

> Professional web vulnerability scanner covering the OWASP Top 10 with triage workflow, PDF/SARIF reporting and passive/active scan modes.

![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-black?style=flat-square&logo=flask)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

---

## 🔍 What it does

A production-grade web vulnerability scanner that checks targets against the OWASP Top 10 — the globally recognised standard for web application security risks. Built from scratch in Python with a browser-based dashboard, login protection, and professional reporting.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **OWASP Top 10 checks** | All 10 categories covered — A01 through A10 |
| 🛡 **Passive / Active modes** | Passive is safe for any target, Active sends payloads |
| ✅ **Triage workflow** | Mark findings as Confirmed, False Positive, or Accepted Risk |
| 📄 **PDF report** | Executive summary + full technical findings |
| ⚙ **SARIF export** | Compatible with Burp Suite, Jira, GitHub Advanced Security |
| { } **JSON export** | Machine-readable findings for pipeline integration |
| 🔐 **Login protection** | Session-based auth protects the dashboard |
| 📊 **Scan history** | All scans persisted in SQLite with diff comparison |
| ⚡ **Concurrent scans** | Up to 2 scans running in parallel |
| 🔄 **Scan diffing** | Compare findings between scans of the same target |

---

## 🖥 Requirements

Before you start make sure you have:

- **Python 3.10 or higher** — download from https://www.python.org/downloads/
- **Git** — download from https://git-scm.com/downloads
- A terminal (PowerShell on Windows, Terminal on Mac/Linux)

---

## 🚀 Setup — step by step

### Step 1 — Clone the repository

```bash
git clone https://github.com/roronoazoro-hacked/hawkeye-OWASP-scanner.git
cd hawkeye-OWASP-scanner
```

### Step 2 — Create a virtual environment

**Windows:**
```powershell
python -m venv .venv
.venv\Scripts\activate
```

**Mac / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

You'll know it worked when you see `(.venv)` at the start of your terminal line.

### Step 3 — Install dependencies

```bash
pip install -r requirements.txt
```

This installs Flask, BeautifulSoup, requests, reportlab, and all other required libraries automatically.

### Step 4 — Run the scanner

**Windows:**
```powershell
python main.py
```

**Mac / Linux:**
```bash
python3 main.py
```

You should see:
=======================================================
OWASP Web Vulnerability Scanner
Open: http://127.0.0.1:5000

### Step 5 — Open the dashboard

Open your browser and go to:
http://127.0.0.1:5000
### Step 6 — Log in

### First time setup — create your `.env` file

Copy `.env.example` to `.env` and set your own credentials:
SCANNER_USERNAME=yourchoice
SCANNER_PASSWORD=yourpassword
Then run the scanner. Never share your `.env` file.

> ⚠️ Change these in `main.py` before sharing with anyone

---

## 📖 How to use it

### Running a scan

1. Enter a target URL in the input box — e.g. `https://example.com`
2. Choose scan mode:
   - **🛡 Passive** — only reads headers and HTML, safe for any target
   - **⚡ Active** — sends test payloads, only use on targets you own
3. Click **▶ Scan**
4. Watch checks run live — each OWASP category updates in real time

### Reading results

Each finding shows:
- **Severity** — CRITICAL / HIGH / MEDIUM / LOW / INFO
- **OWASP category** — which Top 10 rule triggered
- **Detail** — what exactly was found
- **Fix** — how to remediate it
- **Request/Response** — the exact HTTP evidence (click to expand)

### Triaging findings

Click any finding to expand it, then use the triage buttons:
- **✓ Confirmed** — real vulnerability, needs fixing
- **✗ False Positive** — not a real issue
- **⚠ Accepted Risk** — known issue, accepted by team

### Exporting reports

Once a scan completes, three export buttons appear:
- **📄 PDF Report** — professional report for clients or management
- **{ } JSON** — machine-readable for automation pipelines
- **⚙ SARIF** — import directly into Burp Suite, Jira, or GitHub Advanced Security

---

## 🎯 OWASP checks covered

| ID | Category | What it checks |
|---|---|---|
| A01 | Broken Access Control | Sensitive paths, admin panels, backup files |
| A02 | Cryptographic Failures | HTTPS, HSTS, weak TLS configuration |
| A03 | Injection | SQL injection, XSS payload reflection |
| A05 | Security Misconfiguration | Missing security headers, server version disclosure |
| A06 | Vulnerable Components | Outdated jQuery, deprecated JS libraries |
| A07 | Authentication Failures | Default credentials, missing rate limiting |
| A09 | Logging & Monitoring | Exposed log files, robots.txt sensitive paths |
| A10 | SSRF | URL parameters that accept external addresses |

---

## 🏗 Project structure
hawkeye-OWASP-scanner/
├── main.py         — Flask server, login system, all API routes
├── scanner.py      — Scan engine, threading, SQLite persistence
├── checks.py       — All OWASP detection logic
├── reporter.py     — PDF, JSON, SARIF report generation
├── requirements.txt
├── templates/
│   ├── index.html  — Main scanner dashboard
│   └── login.html  — Login page
└── scans.db        — Auto-created SQLite database (scan history)
---

## ⚙️ Configuration

Open `main.py` and change these at the top:

```python
USERNAME = "admin"   # change this
PASSWORD = "root"    # change this to something strong
```

---

## 🔒 Legal notice

**Only scan targets you own or have explicit written permission to test.**
Unauthorized scanning may be illegal in your jurisdiction.
This tool is for educational and professional security testing purposes only.

---

## 🛠 Troubleshooting

**Port already in use:**
```bash
# Change port in main.py
app.run(host="0.0.0.0", port=5001)
```

**pip install fails:**
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**Blank page after login:**
- Make sure you always use the same address — either `127.0.0.1:5000` or your IP, not both
- Try clearing browser cookies and logging in again

**Scan button not responding:**
- Open browser developer tools (F12) → Console tab — check for red errors
- Make sure you are logged in at `http://127.0.0.1:5000/login`

---

## 👨‍💻 Author

**Dhrumil Chheda**
- GitHub: [@roronoazoro-hacked](https://github.com/roronoazoro-hacked)

---

## 📄 License

MIT License — free to use, modify and distribute with attribution.