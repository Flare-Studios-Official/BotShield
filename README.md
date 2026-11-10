# BotShield 🛡️

**Open-Source Website Security, Intelligent Bot Detection, IP Reputation & Proxy Analysis Platform**

> *"Understand. Detect. Defend."*

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat&logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4+-3178C6?style=flat&logo=typescript&logoColor=white)](https://typescriptlang.org)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-3.4+-06B6D4?style=flat&logo=tailwind-css&logoColor=white)](https://tailwindcss.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📌 Overview

**BotShield** is a modern, transparent, and defensive cybersecurity operations toolkit designed for developers, penetration testers, and SOC engineering teams. It bridges the gap between passive website security auditing, multi-signal behavioral bot telemetry, and reputation intelligence.

Unlike black-box scanners that fabricate scores or classify requests solely based on easily forged User-Agent headers, BotShield is built around **measurable evidence, explainable scoring heuristics, and strict defensive boundaries**.

---

## 🚀 Key Modules & Capabilities

### 1. 🌐 Website Security Scanner
* **Defensive SSRF Protection**: Comprehensive destination validation blocking RFC 1918 private subnets, loopback addresses (`127.0.0.0/8`, `::1`), link-local spaces, and cloud provider metadata services (`169.254.169.254`).
* **Hop-by-Hop Redirect Validation**: Follows redirects manually while re-verifying every destination IP to stop redirect-based SSRF and DNS rebinding attacks.
* **Security Header Matrix**: Context-aware analysis of `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and `Permissions-Policy` with actionable remediation guidance.
* **TLS & Cryptographic Auditing**: Safe peer certificate inspection reporting TLS protocol versions, expiration dates, and issuing certificate authorities.
* **robots.txt Advisory**: Parses user-agent groups, disallow directives, and sitemaps with clear defensive advisories explaining that robots.txt is a crawling convention, not an access control barrier.
* **Rate-Limit Indicator Detection**: Passive inspection of standardized IETF (`RateLimit-*`) and vendor-specific headers without flooding targets.
* **Bot Defense Fingerprinting**: Non-invasive signature detection of front-door CDN and WAF layers (Cloudflare, Akamai, AWS WAF, DataDome, Imperva, Fastly).

### 2. 🔍 IP Intelligence Analyzer
* **Universal IPv4 & IPv6 Support**: Dual-stack parsing powered by Python's `ipaddress` engine.
* **Local vs. Public Classification**: Distinguishes public routable IPs from loopback, private, carrier-grade NAT (RFC 6598), and bogon blocks.
* **Autonomous System & Network Profiling**: BGP ASN and organization lookup via Regional Internet Registry RDAP services (ARIN/RIPE).
* **Reverse DNS Inspection**: Automated PTR record lookup.
* **Multi-Source Reputation & Anonymization**: Heuristic detection of datacenter/hosting providers, commercial VPN networks, and Tor Project exit nodes.
* **Zero Hard Dependencies**: Gracefully operates 100% offline with zero third-party API keys required. Optional support for AbuseIPDB and IPinfo when keys are supplied.

### 3. 🤖 Behavioral Bot Detection Engine (Core Module)
The primary intelligence pillar of BotShield. Evaluates incoming request telemetry using measurable behavioral evidence rather than User-Agent strings alone:
* **High Request Frequency**: Sliding window volume tracking (default: >50 reqs / 5 mins).
* **Burst Velocity**: Micro-burst clustering identifying programmatic spikes (default: >15 reqs in 10s).
* **Endpoint Enumeration**: Broad path exploration and sensitive endpoint probing (`/.env`, `/wp-admin`, `/actuator/env`).
* **404 Error Cascades**: Tracking repeated HTTP 404 responses characteristic of blind directory brute-forcing.
* **Automation Signatures**: Identifies headless browsers and scraping libraries (curl, requests, Puppeteer, Scrapy) as a weak corroborative signal.
* **Rate-Limit Violations**: Penalizes clients that persistently send requests after receiving HTTP 429 status codes.
* **Unnatural Timing Cadence**: Computes inter-request interval distributions; sub-100ms deterministic intervals trigger sequence penalties.
* **Explainable Risk Scoring**: Scores from 0 to 100 with clear risk tiers (Low, Moderate, High, Critical) and analyst false-positive review workflows.

### 4. 🧪 Local Detection Lab
An isolated, controlled test harness to benchmark detection rules without touching external systems:
* **Normal Browser Simulator**: Human-speed navigation, standard User-Agents, organic paths.
* **Automated Scraper Simulator**: High-frequency pagination via programmatic clients.
* **Burst Bot Simulator**: Rapid cluster of checkout/inventory calls.
* **Endpoint Enumeration Simulator**: Vulnerability scanner probing sensitive files with 404 responses.
* **Rate-Limit Offender**: Repeated requests despite receiving 429 throttling.
* **Safe Demonstration Data**: All lab events are tagged with `is_lab_traffic=True` and can be purged at any time without altering production logs.

### 5. 🛡️ Proxy Intelligence Analyzer
* Diagnostic auditing of user-authorized HTTP and SOCKS5 proxies.
* Connection latency benchmarking and HTTP CONNECT support testing.
* Egress public IP discovery and network classification.
* **Automatic Credential Redaction**: Passwords and basic auth tokens are scrubbed before logging or saving.

### 6. 📄 Professional Reporting & History
* Persistent SQLite audit storage with search and filtering.
* Single-click **JSON export** of all structured findings.
* Executive-ready **PDF report generation** powered by ReportLab with severity badges and compliance notices.

---

## 🏗️ Architecture

```
BotShield/
├── backend/
│   ├── app/
│   │   ├── main.py                     # FastAPI application & rate-limiting middleware
│   │   ├── config.py                   # Pydantic environment configuration
│   │   ├── database.py                 # SQLite SQLAlchemy engine & schema initializer
│   │   ├── core/
│   │   │   ├── security.py             # SSRF protection, IP validator & credential scrubber
│   │   │   └── logging.py              # Redacting structured logger
│   │   ├── models/
│   │   │   └── schema_models.py        # SQLAlchemy relational entities
│   │   ├── schemas/                    # Pydantic request & response schemas
│   │   ├── services/
│   │   │   ├── website_scanner.py      # Safe HTTP traversal & scanner orchestrator
│   │   │   ├── header_analyzer.py      # Security header scoring & recommendations
│   │   │   ├── robots_analyzer.py      # robots.txt parsing & security advisory
│   │   │   ├── rate_limit_analyzer.py  # Standard & legacy rate limit inspection
│   │   │   ├── bot_fingerprint_analyzer.py # CDN & WAF fingerprint detection
│   │   │   ├── ip_analyzer.py          # IPv4/IPv6 classification & RDAP lookup
│   │   │   ├── reputation_service.py   # Multi-source threat intel & Tor cache
│   │   │   ├── bot_detector.py         # Behavioral multi-signal detection engine
│   │   │   ├── traffic_simulator.py    # Local detection lab generator
│   │   │   ├── proxy_analyzer.py       # Authorized proxy diagnostics
│   │   │   └── report_generator.py     # JSON and ReportLab PDF compiler
│   │   └── api/
│   │       └── routes/                 # REST endpoints (health, websites, ips, bots, proxies, lab, reports)
│   ├── tests/                          # Automated Pytest suite (22 unit & integration tests)
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── components/                 # Sidebar, Navbar, MetricCard, SeverityBadge
│   │   ├── pages/                      # Overview, WebsiteScanner, IPIntelligence, BotDetection, Proxy, Lab, History, Rules, Docs
│   │   ├── services/api.ts             # Type-safe API client
│   │   ├── types/index.ts              # TypeScript definitions
│   │   ├── App.tsx
│   │   └── main.tsx
│   ├── package.json
│   ├── vite.config.ts
│   └── tailwind.config.js
│
├── docs/                               # Architecture, Detection Engine, API, Security guides
├── docker-compose.yml
├── Dockerfile
└── LICENSE                             # MIT License
```

---

## 💻 Quick Start & Setup (Windows / Linux / macOS)

### Prerequisites
* **Python 3.11+** installed and available on PATH
* **Node.js 18+** & **npm** installed

### 1. Clone Repository
```bash
git clone https://github.com/Flare-Studios-Official/BotShield.git
cd BotShield
```

### 2. Backend Setup
```bash
cd backend

# Create virtual environment (optional but recommended)
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
# source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start FastAPI server
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
Backend API will be accessible at: `http://127.0.0.1:8000`
Interactive Swagger Documentation: `http://127.0.0.1:8000/api/docs`

### 3. Frontend Setup
In a new terminal window:
```bash
cd frontend

# Install dependencies
npm install

# Start Vite development server
npm run dev
```
Frontend dashboard will be accessible at: `http://localhost:5173`

---

## 🧪 Running Automated Tests

BotShield includes 22 automated tests covering SSRF prevention, security header analysis, robots.txt parsing, IPv4/IPv6 classification, bot behavioral scoring, and REST API routes.

```bash
cd backend
python -m pytest tests -v
```

---

## 🐳 Docker Deployment

To spin up BotShield with a single command via Docker:

```bash
docker-compose up --build
```
This launches the FastAPI backend on port 8000 and the production-built frontend on port 80.

---

## 🔒 Security Model & Safe Harbor

BotShield is intentionally engineered as a **defensive security and observability tool**.

* **No Circumvention Tools**: It does not implement CAPTCHA bypasses, identity spoofing, stealth scraping, or ban evasion.
* **SSRF Protection**: Outbound requests strictly forbid private IP addresses (RFC 1918), loopback, link-local, and cloud metadata services.
* **Safe Logging**: Credentials, authorization tokens, and proxy passwords are automatically sanitized and redacted.
* **Authorized Auditing**: Users must only scan websites, IPs, and proxies they own or have documented permission to assess.

---

## 📜 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.
