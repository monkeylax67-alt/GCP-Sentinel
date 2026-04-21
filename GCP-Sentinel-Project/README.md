# 🛡️ GCP Sentinel

> AI-powered Google Cloud security monitoring with automatic threat response, IP blocking, IAM revocation, MFA, and SMS/call alerts.

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Flask-3.0+-000000?style=for-the-badge&logo=flask&logoColor=white"/>
  <img src="https://img.shields.io/badge/Claude_AI-Sonnet-FF6B35?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Google_Cloud-4285F4?style=for-the-badge&logo=google-cloud&logoColor=white"/>
  <img src="https://img.shields.io/badge/Twilio-F22F46?style=for-the-badge&logo=twilio&logoColor=white"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge"/>
</p>

---

## 📖 Overview

GCP Sentinel watches your Google Cloud infrastructure 24/7 and automatically responds when an unknown or malicious account tries to access your resources — compressing the detection-to-response time from hours to **seconds**.

When a threat is detected, it simultaneously:

```
Unknown login detected
        │
        ├─ 🚫  Blocks the IP          → GCP Firewall DENY rule
        ├─ 🔐  Revokes the account    → Strips all IAM bindings
        ├─ 🔴  Shuts down the server  → GCP Compute Engine API
        └─ 🤖  Asks Claude AI         → Hardening recommendations
```

All of this happens **automatically**, before a human even sees the alert.

---

## ✨ Features

- **🤖 AI Security Assistant** — Claude-powered chat that knows your live server state, threat history, and blocked IPs. Streaming responses in the dashboard.
- **⚡ Auto-Response Engine** — Automatically blocks IPs, revokes IAM access, and shuts down servers on CRITICAL threats. Each action is individually toggleable.
- **📱 SMS & Voice Alerts** — Notifies multiple phone numbers via Twilio SMS or voice call the moment a threat is detected.
- **🔐 MFA / Two-Factor Auth** — TOTP-based 2FA via Google Authenticator, Authy, or any authenticator app.
- **🔒 Secure Login** — Session-based auth, rate limiting (5 attempts = 5 min lockout), full audit log.
- **📊 Live Dashboard** — Real-time threat feed, server control panel, blocked IPs, revoked accounts — all updated via WebSocket.
- **⚙️ Settings Page** — Manage phone numbers, MFA, users, and passwords through a clean UI.
- **🧪 Demo Mode** — Works with zero GCP setup. Generates realistic simulated threats so you can test the full pipeline locally.

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- An [Anthropic API key](https://console.anthropic.com)

### 1. Clone the repo

```bash
git clone https://github.com/yourname/gcp-sentinel.git
cd gcp-sentinel
```

### 2. Install dependencies

```bash
# Windows
py -m pip install -r requirements.txt

# Mac / Linux
pip install -r requirements.txt
```

### 3. Configure environment

```bash
# Windows
copy .env.example .env
notepad .env

# Mac / Linux
cp .env.example .env
nano .env
```

At minimum, set your Anthropic API key:

```env
ANTHROPIC_API_KEY=sk-ant-your-key-here
```

### 4. Run

```bash
# Windows
py app.py

# Mac / Linux
python app.py
```

Open **http://localhost:5000** and log in with:

```
Username: admin
Password: sentinel123
```

> ⚠️ Change the default password immediately in **Settings → Password**

---

## 📁 Project Structure

```
gcp-sentinel/
├── app.py                    # Flask backend — auth, APIs, auto-response engine
├── requirements.txt          # Python dependencies
├── .env.example              # Config template
├── .env                      # Your config (never commit this)
├── sentinel_settings.json    # Persisted settings — users, MFA, notifications
├── setup_gcp.sh              # One-time GCP infrastructure setup (bash)
├── setup_gcp.ps1             # One-time GCP infrastructure setup (PowerShell)
└── templates/
    ├── login.html            # Login page with animated UI
    ├── dashboard.html        # Main real-time dashboard
    └── settings.html         # Settings — MFA, notifications, users, password
```

---

## ⚙️ Configuration

All settings are in your `.env` file:

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | ✅ | Claude API key from [console.anthropic.com](https://console.anthropic.com) |
| `SENTINEL_PASSWORD` | | Dashboard password (default: `sentinel123`) |
| `TWILIO_ACCOUNT_SID` | | Twilio SID for SMS/call alerts |
| `TWILIO_AUTH_TOKEN` | | Twilio auth token |
| `TWILIO_FROM_NUMBER` | | Twilio phone number (e.g. `+15550000000`) |
| `GCP_PROJECT_ID` | | GCP project ID — enables live mode |
| `GCP_CREDENTIALS_FILE` | | Path to service account JSON key |
| `KNOWN_DOMAINS` | | Trusted email domains (e.g. `@yourcompany.com`) |
| `PORT` | | Server port (default: `5000`) |
| `SECRET_KEY` | | Flask session secret — change in production |

---

## ☁️ Connecting to Real GCP

By default GCP Sentinel runs in **demo mode** — all threats are simulated. To connect to a real GCP project:

### Option A — PowerShell (Windows)

```powershell
# Install gcloud CLI first: https://cloud.google.com/sdk
gcloud auth login
.\setup_gcp.ps1 -Project your-project-id -Domain yourcompany.com
```

### Option B — Bash (Mac / Linux)

```bash
gcloud auth login
bash setup_gcp.sh your-project-id yourcompany.com
```

The script automatically creates:

| Resource | Name | Purpose |
|---|---|---|
| Pub/Sub topic | `sentinel-alerts` | Receives security events |
| Pub/Sub subscription | `sentinel-sub` | App listens here |
| Cloud Audit Log sink | `sentinel-audit-sink` | Forwards unknown logins → Pub/Sub |
| Service account | `gcp-sentinel-v2@...` | App credentials |
| Firewall rule | `sentinel-auto-block-base` | Base rule for auto-blocking |

Then update `.env`:

```env
GCP_PROJECT_ID=your-project-id
GCP_CREDENTIALS_FILE=./gcp-credentials.json
KNOWN_DOMAINS=@yourcompany.com
```

Install GCP packages:

```bash
pip install google-cloud-compute google-cloud-pubsub google-cloud-logging google-auth
```

Restart the app — the dashboard badge changes from **DEMO** to **LIVE GCP**.

---

## 📱 SMS & Voice Alerts

1. Sign up at [twilio.com](https://twilio.com) (free trial includes credits)
2. Get your Account SID, Auth Token, and a phone number
3. Add them to `.env`
4. Go to **Settings → Notifications** in the dashboard
5. Add phone numbers and click **Test SMS** or **Test Call** to verify

Supports multiple recipients, per-severity filtering, and cooldown timers to prevent notification spam.

---

## 🔐 MFA Setup

1. Install [Google Authenticator](https://apps.apple.com/app/google-authenticator/id388497605) or [Authy](https://authy.com) on your phone
2. Install required packages:
   ```bash
   pip install pyotp "qrcode[pil]"
   ```
3. Go to **Settings → MFA** in the dashboard
4. Click **Generate QR Code** and scan with your app
5. Enter the 6-digit code to confirm — MFA is now active

Every login will require your password **plus** a 6-digit code from your authenticator app.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Google Cloud Platform                     │
│                                                             │
│  Cloud Audit Logs ──► Log Sink ──► Pub/Sub Topic           │
│                                         │                   │
│  Compute Engine API ◄───────────────────┤                   │
│  Firewall API       ◄───────────────────┤                   │
│  IAM API            ◄───────────────────┤                   │
└─────────────────────────────────────────┼───────────────────┘
                                          │
                              ┌───────────▼────────────┐
                              │    app.py (Flask)       │
                              │                        │
                              │  ┌─ Auth & Sessions    │
                              │  ├─ Pub/Sub Listener   │
                              │  ├─ Auto-Response      │◄──► Claude AI
                              │  ├─ REST API           │◄──► Twilio
                              │  └─ WebSocket Server   │
                              └───────────┬────────────┘
                                          │
                              ┌───────────▼────────────┐
                              │   Browser Dashboard     │
                              │                        │
                              │  login.html            │
                              │  dashboard.html        │
                              │  settings.html         │
                              └────────────────────────┘
```

---

## 🔧 Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask, Flask-SocketIO |
| AI | Anthropic Claude Sonnet (streaming) |
| Real-time | WebSockets via Socket.IO |
| GCP | Compute Engine API, Pub/Sub, Cloud Audit Logs, IAM |
| Notifications | Twilio SMS + Voice |
| MFA | pyotp (TOTP), qrcode |
| Frontend | HTML, CSS, JavaScript — no framework |

---

## 🛡️ Security Notes

> **Never commit** `.env`, `gcp-credentials.json`, or `sentinel_settings.json` to Git.

Add to your `.gitignore`:

```gitignore
.env
gcp-credentials.json
sentinel_settings.json
__pycache__/
*.pyc
```

Additional recommendations:

- Change the default password (`sentinel123`) immediately
- Set a strong random `SECRET_KEY` in `.env` before deploying
- Run behind HTTPS in production (use nginx as a reverse proxy)
- Rotate GCP service account keys every 90 days
- Use GCP VPC Service Controls for additional perimeter security
- Enable MFA on all admin accounts

---

## 📋 Auto-Defense Settings

Each automated response can be toggled individually from the dashboard:

| Setting | Default | What it does |
|---|---|---|
| Auto-shutdown | ✅ On | Takes the affected server offline |
| Auto-block IP | ✅ On | Creates a GCP firewall DENY rule |
| Auto-revoke IAM | ✅ On | Strips all IAM role bindings from the account |
| AI analysis | ✅ On | Asks Claude for hardening recommendations |
| Geo anomaly alert | ✅ On | Flags logins from unexpected countries |
| Block brute-force | ✅ On | Blocks IPs with repeated failed attempts |

---

## 📄 License

MIT — use freely, modify as needed.

---

## 🙏 Acknowledgements

Built with [Flask](https://flask.palletsprojects.com), [Anthropic Claude](https://anthropic.com), [Socket.IO](https://socket.io), [Twilio](https://twilio.com), and [Google Cloud](https://cloud.google.com).

---

## 👨‍💻 Human-Made

This project was **designed, directed, and built by a human developer**. Every architectural decision, feature requirement, security design, and implementation detail was conceived and guided by a person — not generated autonomously by AI.

[Claude AI](https://anthropic.com) was used as a coding assistant throughout development — helping write boilerplate, suggest implementations, and accelerate iteration — in the same way a developer might use any other tool. All logic, structure, and intent behind the project is human-authored.
