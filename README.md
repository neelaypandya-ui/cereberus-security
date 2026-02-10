<p align="center">
  <img src="https://img.shields.io/badge/version-1.6.0-cyan?style=flat-square" alt="Version" />
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/react-18-61DAFB?style=flat-square&logo=react&logoColor=white" alt="React" />
  <img src="https://img.shields.io/badge/pytorch-2.5+-EE4C2C?style=flat-square&logo=pytorch&logoColor=white" alt="PyTorch" />
  <img src="https://img.shields.io/badge/platform-Windows-0078D6?style=flat-square&logo=windows&logoColor=white" alt="Windows" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License" />
</p>

# CEREBERUS

**AI-Powered Cybersecurity Defense System for Windows**

Cereberus is a real-time security monitoring and automated defense platform that combines 15 specialized detection modules, ensemble AI anomaly detection, YARA scanning, memory forensics, and autonomous response into a single intelligence-agency-styled dashboard. Built for Windows environments, it provides continuous network surveillance, vulnerability assessment, threat correlation, and automated threat neutralization.

---

## Features

### 15 Security Modules
| Module | Description |
|--------|-------------|
| **VPN Guardian** | VPN connection monitoring, kill switch, DNS/IP/IPv6 leak detection |
| **Network Sentinel** | Live connection monitoring, suspicious port detection, IOC matching |
| **Brute Force Shield** | Windows Event Log monitoring, auto-block via firewall rules |
| **File Integrity** | SHA-256 baseline hashing, change detection, IOC hash checking |
| **Process Analyzer** | Process enumeration, unsigned/hidden/injected process detection, dynamic CPU thresholds |
| **Vulnerability Scanner** | Port scanning, weak config detection, one-click remediation |
| **Email Analyzer** | NLP-based phishing detection, URL extraction, threat scoring |
| **Resource Monitor** | CPU/memory/disk/network metrics, threshold alerting |
| **Persistence Scanner** | Registry Run keys, startup folders, scheduled task tracking |
| **Threat Intelligence** | Correlation engine (14 patterns), cross-module event fusion |
| **Event Log Monitor** | Windows Event Log + Sysmon (17 event types), EvtSubscribe push-based |
| **Ransomware Detector** | Canary files, entropy analysis, extension monitoring |
| **Commander Bond** | OSINT feeds, YARA scanning, Sword Protocol, Overwatch integrity |
| **Memory Scanner** | RWX regions, injected DLLs, shellcode detection, YARA memory scan |
| **Disk Analyzer** | Disk usage analysis and monitoring |

### AI System
- **Ensemble Anomaly Detection** &mdash; Autoencoder + Isolation Forest + Z-Score with consensus voting
- **50 Detection Rules** &mdash; Rule-based engine covering MITRE ATT&CK (~43 techniques)
- **Behavioral Baselines** &mdash; Welford's online algorithm for drift detection
- **LSTM Threat Forecasting** &mdash; Predict threat escalation before it happens
- **Explainability** &mdash; Feature attribution for every anomaly detection
- **Auto-Retrain** &mdash; Models retrain on fresh data automatically

### YARA Integration
- **61 YARA rules** across 4 categories: malware signatures, webshells, suspicious strings, ransomware indicators
- **File, directory, and memory scanning** with configurable timeouts
- **Custom rule management** via API

### Automated Response
- **Sword Protocol** &mdash; 5 autonomous response policies (THUNDERBALL, GOLDENEYE, SKYFALL, SPECTRE, GHOST PROTOCOL)
- **9 remediation actions** &mdash; block IP, kill process, quarantine file, isolate network, disable user, block port, disable guest account, enable firewall, disable autologin
- **Playbook automation** &mdash; Rule-based triggers with cooldowns and confirmation gates
- **Incident lifecycle** &mdash; Open &rarr; Investigating &rarr; Contained &rarr; Resolved &rarr; Closed
- **Rollback support** &mdash; Every action can be reversed
- **Overwatch Protocol** &mdash; SHA-256 integrity baselines for all backend files

### Threat Intelligence
- **Feed integrations** &mdash; VirusTotal, AbuseIPDB, URLhaus, CISA KEV, NVD, Feodo, ThreatFox
- **IOC database** &mdash; IP, hash, and URL indicators with severity scoring
- **Intelligence Brain** &mdash; Automated threat assessment and risk scoring
- **Notification channels** &mdash; Webhook and SMTP alerting
- **Data export** &mdash; CSV and JSON export of all security data

### Access Control
- **JWT (PyJWT) + API key** dual authentication with httpOnly cookies
- **4 roles** &mdash; Admin, Analyst, Operator, Viewer
- **13 granular permissions** across all endpoints
- **CSRF protection** with token-based middleware
- **Registration lockdown** &mdash; locked after first user creation
- **Forced password change** on initial login
- **Data retention** &mdash; Automatic cleanup of aged records with configurable policies

### Command Center
- **35 automated verification checks** across 7 categories (Situation Room, Shield, Sword, Threat Assessment, AI Warfare, Incident Response, Combat Readiness)
- **Bulk alert management** &mdash; dismiss-all, acknowledge-all, one-click triage
- **Parallelized report generation** &mdash; all module health checks run concurrently with 5-second timeouts
- **Auto-port cleanup** &mdash; stale backend processes killed automatically on startup

### Dashboard
25 real-time panels with an intelligence-agency aesthetic, WebSocket live updates, keyboard shortcuts, and DEFCON-style threat level indicators.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI, SQLAlchemy (async), aiosqlite, Pydantic |
| Frontend | React 18, TypeScript, Vite, Recharts |
| AI/ML | PyTorch, scikit-learn, NumPy, Pandas |
| Auth | JWT (PyJWT), httpOnly cookies, CSRF, RBAC |
| Scanning | YARA, ctypes Win32 memory access |
| Networking | psutil, aiohttp, httpx |
| Deployment | Docker, nginx (TLS), docker-compose |

---

## Quick Start

### Prerequisites
- **Windows 10/11** (modules use Windows APIs, Event Log, netsh, WMI)
- **Python 3.11+**
- **Node.js 18+**
- **Administrator privileges** (required for firewall rules, process inspection, event log access)

### Installation

```bash
# Clone the repository
git clone https://github.com/neelaypandya-ui/cereberus-security.git
cd cereberus-security

# Install Python dependencies
pip install -r requirements.txt

# Install frontend dependencies
cd frontend
npm install
cd ..
```

### Configuration

Copy `.env.example` to `.env` and configure:

```env
# REQUIRED — generate a secure key
SECRET_KEY=your-secret-key-here

DEBUG=false
HOST=127.0.0.1
PORT=8000

# Set to true in production with TLS
COOKIE_SECURE=false

# Comma-separated allowed origins
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

### Running

Start the backend and frontend in separate terminals:

```bash
# Terminal 1 — Backend (run as Administrator)
cd cereberus
python -c "from backend.main import main; main()"

# Terminal 2 — Frontend (development only)
cd cereberus/frontend
npm run dev
```

Open **http://localhost:5173** in your browser (development) or **https://localhost** (production with nginx). The first user registered becomes admin. You will be prompted to change the default password on first login.

> **Note:** In production, the backend serves the frontend SPA directly — no separate frontend server needed. The two-server setup is for development only (Vite provides hot module reload).

### Docker Deployment

```bash
docker-compose up --build
```

This starts Cereberus with:
- Backend on port 8000
- nginx reverse proxy with TLS on ports 80 (redirect) and 443

### TLS Setup

For production, place your SSL certificates in the `certs/` directory:

```bash
# Self-signed (development)
openssl req -x509 -newkey rsa:4096 -keyout certs/cereberus.key -out certs/cereberus.crt -days 365 -nodes

# Or use Let's Encrypt for production
```

See `certs/README.md` for detailed instructions.

---

## Project Structure

```
cereberus/
├── backend/
│   ├── ai/                 # 10 AI classes (anomaly, ensemble, LSTM, rules, correlation)
│   ├── alerting/           # Alert manager
│   ├── api/routes/         # 42 route files, 200+ endpoints
│   ├── auth/               # RBAC system (4 roles, 13 permissions)
│   ├── engine/             # Remediation, incidents, playbooks
│   ├── intel/              # Threat feeds, IOC matcher, YARA scanner
│   ├── maintenance/        # Retention cleanup, backup/restore
│   ├── models/             # 37 SQLAlchemy tables
│   ├── modules/            # 15 security modules
│   ├── notifications/      # Webhook + SMTP dispatchers
│   ├── service/            # Windows Service wrapper
│   └── main.py             # FastAPI app + lifespan
├── frontend/
│   ├── src/components/     # 25 dashboard panels
│   ├── src/hooks/          # WebSocket, permissions, keyboard shortcuts
│   ├── src/pages/          # Dashboard, Login, ChangePassword
│   └── src/services/       # API client
├── yara_rules/             # 61 YARA rules (4 categories)
├── scripts/                # Windows Service installer
├── docs/                   # System documentation
├── tests/                  # Unit + integration tests
├── Dockerfile
├── docker-compose.yml
└── nginx.conf
```

---

## API Overview

All endpoints are under `/api/v1/`. Authentication is required via httpOnly session cookie or `X-API-Key` header.

| Category | Endpoints | Description |
|----------|-----------|-------------|
| Auth | 6 | Login, register, refresh, logout, change-password, profile |
| Modules | 4 | Start/stop/health for all 15 modules |
| Network | 5 | Live connections, stats, flagged, anomalies |
| Processes | 4 | Process list, suspicious, tree, kill |
| Integrity | 4 | File baseline, changes, scan, IOC matches |
| Vulnerabilities | 5 | Scan, findings, remediate |
| VPN | 6 | Status, leak check, kill switch, config audit |
| Alerts | 8 | List, create, acknowledge, resolve, bulk dismiss, bulk acknowledge |
| Threats | 5 | Events, correlations, threat level, forecast |
| AI | 8 | Model status, retrain, predictions, explainability |
| Detection Rules | 5 | List, toggle, create, stats |
| Incidents | 9 | CRUD, lifecycle transitions, timeline |
| Playbooks | 9 | CRUD, enable/disable, trigger history |
| Remediation | 7 | Execute, rollback, action log |
| Feeds | 7 | CRUD, sync, IOC ingestion |
| IOC | 8 | Search, create, bulk import, matching |
| Notifications | 7 | Channel CRUD, test, dispatch |
| Export | 5 | Create jobs, download CSV/JSON |
| Users | 12 | CRUD, roles, API keys |
| Maintenance | 4 | Retention, backup, restore |
| Dashboard | 6 | Layouts, panels, overview stats |
| YARA | 11 | Rule CRUD, file/dir/memory scan |
| Memory | 5 | Process scan, results, anomalies |
| Commander Bond | 16 | OSINT, Sword policies, Overwatch |
| Reports | 1 | Full system report with parallel health checks |
| Checklists | 1 | 35-item automated verification across 7 categories |
| Search | 1 | Global cross-module search |

See the [full API reference](docs/index.html#api-reference) in the documentation.

---

## License

MIT
