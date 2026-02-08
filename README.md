<p align="center">
  <img src="https://img.shields.io/badge/version-0.9.0-cyan?style=flat-square" alt="Version" />
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/react-18-61DAFB?style=flat-square&logo=react&logoColor=white" alt="React" />
  <img src="https://img.shields.io/badge/pytorch-2.5+-EE4C2C?style=flat-square&logo=pytorch&logoColor=white" alt="PyTorch" />
  <img src="https://img.shields.io/badge/platform-Windows-0078D6?style=flat-square&logo=windows&logoColor=white" alt="Windows" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License" />
</p>

# CEREBERUS

**AI-Powered Cybersecurity Defense System for Windows**

Cereberus is a real-time security monitoring and automated defense platform that combines 10 specialized detection modules, ensemble AI anomaly detection, and automated remediation into a single intelligence-agency-styled dashboard. Built for Windows environments, it provides continuous network surveillance, vulnerability assessment, threat correlation, and one-click threat neutralization.

---

## Features

### 10 Security Modules
| Module | Description |
|--------|-------------|
| **VPN Guardian** | VPN connection monitoring, kill switch, DNS/IP/IPv6 leak detection |
| **Network Sentinel** | Live connection monitoring, suspicious port detection, IOC matching |
| **Brute Force Shield** | Windows Event Log monitoring, auto-block via firewall rules |
| **File Integrity** | SHA-256 baseline hashing, change detection, IOC hash checking |
| **Process Analyzer** | Process enumeration, unsigned/hidden/injected process detection |
| **Vulnerability Scanner** | Port scanning, weak config detection, one-click remediation |
| **Email Analyzer** | NLP-based phishing detection, URL extraction, threat scoring |
| **Resource Monitor** | CPU/memory/disk/network metrics, threshold alerting |
| **Persistence Scanner** | Registry Run keys, startup folders, scheduled task tracking |
| **Threat Intelligence** | Correlation engine (10 patterns), cross-module event fusion |

### AI System
- **Ensemble Anomaly Detection** &mdash; Autoencoder + Isolation Forest + Z-Score with consensus voting
- **Behavioral Baselines** &mdash; Welford's online algorithm for drift detection
- **LSTM Threat Forecasting** &mdash; Predict threat escalation before it happens
- **Explainability** &mdash; Feature attribution for every anomaly detection
- **Auto-Retrain** &mdash; Models retrain on fresh data automatically

### Automated Response
- **9 remediation actions** &mdash; block IP, kill process, quarantine file, isolate network, disable user, block port, disable guest account, enable firewall, disable autologin
- **Playbook automation** &mdash; Rule-based triggers with cooldowns and confirmation gates
- **Incident lifecycle** &mdash; Open &rarr; Investigating &rarr; Contained &rarr; Resolved &rarr; Closed
- **Rollback support** &mdash; Every action can be reversed

### Threat Intelligence
- **Feed integrations** &mdash; VirusTotal, AbuseIPDB, URLhaus
- **IOC database** &mdash; IP, hash, and URL indicators with severity scoring
- **Notification channels** &mdash; Webhook and SMTP alerting
- **Data export** &mdash; CSV and JSON export of all security data

### Access Control
- **JWT + API key** dual authentication
- **4 roles** &mdash; Admin, Analyst, Operator, Viewer
- **13 granular permissions** across all endpoints
- **Data retention** &mdash; Automatic cleanup of aged records with configurable policies

### Dashboard
19 real-time panels with an intelligence-agency aesthetic, WebSocket live updates, keyboard shortcuts, and DEFCON-style threat level indicators.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI, SQLAlchemy (async), aiosqlite, Pydantic |
| Frontend | React 18, TypeScript, Vite, Recharts |
| AI/ML | PyTorch, scikit-learn, NumPy, Pandas |
| Auth | JWT (python-jose), bcrypt (passlib), RBAC |
| Networking | psutil, scapy, aiohttp, httpx |
| Deployment | Docker, nginx, docker-compose |

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

Create a `.env` file in the project root:

```env
SECRET_KEY=your-secret-key-here
ADMIN_USERNAME=admin
ADMIN_PASSWORD=cereberus
DEBUG=true
HOST=127.0.0.1
PORT=8001
```

### Running

Start the backend and frontend in separate terminals:

```bash
# Terminal 1 — Backend (run as Administrator)
python -B -m uvicorn cereberus.backend.main:app --host 127.0.0.1 --port 8001

# Terminal 2 — Frontend
cd frontend
npm run dev
```

Open **http://localhost:5173** in your browser. Log in with the credentials from your `.env` file.

### Docker

```bash
docker-compose up --build
```

This starts Cereberus on port 8000 with an nginx reverse proxy on port 80.

---

## Project Structure

```
cereberus/
├── backend/
│   ├── ai/                 # 9 AI classes (anomaly, ensemble, LSTM, explainability)
│   ├── alerting/           # Alert manager
│   ├── api/routes/         # 32 route files, 131+ endpoints
│   ├── auth/               # RBAC system (4 roles, 13 permissions)
│   ├── engine/             # Remediation, incidents, playbooks
│   ├── export/             # CSV/JSON data export
│   ├── intel/              # Threat feed providers, IOC matcher
│   ├── maintenance/        # Retention cleanup, backup/restore
│   ├── models/             # 30 SQLAlchemy tables
│   ├── modules/            # 10 security modules
│   ├── notifications/      # Webhook + SMTP dispatchers
│   └── main.py             # FastAPI app + lifespan
├── frontend/
│   ├── src/components/     # 19 dashboard panels
│   ├── src/hooks/          # WebSocket, permissions, keyboard shortcuts
│   ├── src/pages/          # Dashboard layout
│   └── src/services/       # API client
├── docs/                   # System documentation (self-contained HTML)
├── tests/                  # Unit + integration tests
├── Dockerfile
├── docker-compose.yml
└── nginx.conf
```

---

## Documentation

Full system documentation is available at [`docs/index.html`](docs/index.html). It covers every dashboard panel, the AI system, remediation workflows, RBAC, the complete API reference, and is written for users with no cybersecurity experience.

---

## API Overview

All endpoints are under `/api/v1/`. Authentication is required via JWT bearer token or `X-API-Key` header.

| Category | Endpoints | Description |
|----------|-----------|-------------|
| Auth | 4 | Login, register, refresh, profile |
| Modules | 4 | Start/stop/health for all 10 modules |
| Network | 5 | Live connections, stats, flagged, anomalies |
| Processes | 4 | Process list, suspicious, tree, kill |
| Integrity | 4 | File baseline, changes, scan, IOC matches |
| Vulnerabilities | 5 | Scan, findings, remediate |
| VPN | 6 | Status, leak check, kill switch, config audit |
| Alerts | 6 | List, create, acknowledge, resolve |
| Threats | 5 | Events, correlations, threat level, forecast |
| AI | 8 | Model status, retrain, predictions, explainability |
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

See the [full API reference](docs/index.html#api-reference) in the documentation.

---

## License

MIT
