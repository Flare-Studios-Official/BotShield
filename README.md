# BotShield 🛡️

**Open-Source Website Security, Behavioral Bot Detection, IP Intelligence & Proxy Analysis Platform**

> *"Understand. Detect. Defend."*

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat&logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4+-3178C6?style=flat&logo=typescript&logoColor=white)](https://typescriptlang.org)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-3.4+-06B6D4?style=flat&logo=tailwind-css&logoColor=white)](https://tailwindcss.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-34%20Passed-brightgreen.svg)](backend/tests)

---

## 📌 Overview

**BotShield** is a transparent, defensive cybersecurity toolkit built for developers, site reliability engineers, and SOC teams. It unites passive website security analysis, multi-signal behavioral bot detection, and multi-source IP/proxy intelligence in a unified platform.

Unlike tools that fabricate scores, simulate external lookups, or rely on easily spoofed `User-Agent` strings, BotShield operates strictly on **verifiable network evidence, connection-level defensive controls, and explainable scoring heuristics**.

---

## 🚀 Key Modules & Capabilities

### 1. 🌐 Website Security Scanner
* **Defensive SSRF Protection**: Comprehensive destination validation blocking RFC 1918 private subnets, loopback addresses (`127.0.0.0/8`, `::1`), link-local spaces, carrier-grade NAT (`100.64.0.0/10`), documentation networks (TEST-NET), and cloud metadata addresses (`169.254.169.254`, `fd00:ec2::254`, metadata hostnames).
* **Connection-Level IP Pinning & DNS Rebinding Defense**: Eliminates Time-Of-Check / Time-Of-Use (TOCTOU) DNS rebinding by pinning the outbound TCP connection directly to the verified destination IP using a custom `httpcore` network backend (`SSRFPinnedSyncBackend`). TLS Server Name Indication (SNI) and certificate chain verification remain strictly enforced against the target hostname.
* **Hop-by-Hop Redirect Validation**: Follows HTTP redirects manually while independently resolving and validating each hop's IP before connection.
* **Streaming Response Limits**: Enforces strict maximum response-body limits (default: 2 MB). Downloads are aborted immediately if `Content-Length` or streamed chunk accumulation exceeds the ceiling, preventing resource exhaustion attacks.
* **Security Header Matrix**: Evaluates `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and `Permissions-Policy` with actionable remediation guidance.
* **TLS & Cryptographic Auditing**: Safe peer certificate inspection reporting TLS protocol versions, expiration dates, and issuing certificate authorities directly on the pinned destination socket.
* **robots.txt Security Advisory**: Parses user-agent groups, disallow directives, and sitemaps with clear defensive guidance noting that robots.txt is a crawling convention, not an access barrier.
* **Rate-Limit Indicator Detection**: Passive inspection of standardized IETF (`RateLimit-*`) and vendor headers without active traffic flooding.
* **Bot Defense Fingerprinting**: Passive signature detection of CDN and WAF front-door layers (Cloudflare, Akamai, AWS WAF, DataDome, Imperva, Fastly).

### 2. 🔍 IP Intelligence Analyzer
* **Universal IPv4 & IPv6 Support**: Dual-stack validation and classification via Python's `ipaddress` library.
* **Local vs. Public Classification**: Distinguishes public routable IPs from loopback, RFC 1918, link-local, CGNAT (RFC 6598), and reserved ranges.
* **Multi-RIR RDAP Discovery**: Queries Regional Internet Registries with automated discovery and fallback across ARIN, RIPE NCC, APNIC, and LACNIC.
* **RDAP vs. BGP ASN Differentiation**: Accurately distinguishes IP network registration data (network block name, handle, registrant organization) from BGP Autonomous System routing data, avoiding false claims regarding IP RDAP capabilities.
* **Policy: Never Label Unverified IPs as Malicious**: Unverified public IPs without documented abuse history default to clean, neutral reputation (Score: 0, Low Risk). Datacenter hosting is treated as an infrastructure context tag, not proof of malice.
* **Dynamic Tor Exit Node Intelligence**: Integrates live official Tor Project directory caching (`check.torproject.org/torbulkexitlist`) with a 1-hour TTL. If the directory is unreachable, the address is tagged as `unverified` without assigning false threat penalties.
* **Zero Hard External Dependencies**: Functions 100% offline out-of-the-box. Optional enrichment via AbuseIPDB and IPinfo when API credentials are provided.

### 3. 🤖 Behavioral Bot Detection Engine (Core Module)
Evaluates incoming HTTP request telemetry using measurable behavioral evidence rather than User-Agent headers alone:
* **High Request Frequency**: Sliding window volume tracking (default: >50 reqs / 5 mins).
* **Burst Velocity**: Micro-burst clustering identifying programmatic spikes (default: >15 reqs in 10s).
* **Endpoint Enumeration**: Broad path exploration and sensitive endpoint probing (`/.env`, `/wp-admin`, `/actuator/env`).
* **404 Error Cascades**: Tracking repeated HTTP 404 responses characteristic of blind directory brute-forcing.
* **Automation Signatures**: Identifies automated tools and headless clients (curl, requests, Puppeteer, Scrapy) as a corroborating signal.
* **Rate-Limit Violations**: Penalizes clients that persistently send requests after receiving HTTP 429 status codes.
* **Unnatural Timing Cadence**: Computes inter-request interval distributions; deterministic sub-100ms intervals trigger velocity penalties.
* **Explainable Risk Scoring**: Scores from 0 to 100 across 4 risk tiers (Low, Moderate, High, Critical) with analyst review and false-positive tracking.

### 4. 🧪 Local Detection Lab
An isolated, controlled test harness to benchmark detection rules without touching external systems:
* **Normal Browser Simulator**: Human-speed navigation, standard User-Agents, organic paths.
* **Automated Scraper Simulator**: High-frequency pagination via programmatic clients.
* **Burst Bot Simulator**: Rapid cluster of checkout/inventory calls.
* **Endpoint Enumeration Simulator**: Vulnerability scanner probing sensitive files with 404 responses.
* **Rate-Limit Offender**: Repeated requests despite receiving 429 throttling.
* **Safe Demonstration Data**: All lab events are tagged with `is_lab_traffic=True` and can be purged at any time without altering production logs.

### 5. 🛡️ Proxy Intelligence Analyzer
* Diagnostic auditing of user-authorized HTTP, HTTPS, and SOCKS5 proxies.
* SOCKS5 proxy protocol support powered by `socksio` out-of-the-box.
* Connection latency benchmarking and target egress verification.
* Egress public IP discovery and autonomous system classification.
* **Automatic Credential Redaction**: Passwords, tokens, and basic-auth credentials are scrubbed before logging or saving.

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
│   │   ├── main.py                     # FastAPI application, CORS, rate-limiting middleware
│   │   ├── config.py                   # Centralized Pydantic configuration & admin key settings
│   │   ├── database.py                 # SQLite SQLAlchemy engine & schema initializer
│   │   ├── core/
│   │   │   ├── security.py             # SSRF protection, IP pinning, streaming limits, admin auth
│   │   │   └── logging.py              # Redacting structured logger
│   │   ├── models/
│   │   │   └── schema_models.py        # SQLAlchemy relational entities
│   │   ├── schemas/                    # Pydantic request & response schemas
│   │   ├── services/
│   │   │   ├── website_scanner.py      # IP-pinned HTTP traversal & scanner orchestrator
│   │   │   ├── header_analyzer.py      # Security header scoring & recommendations
│   │   │   ├── robots_analyzer.py      # robots.txt parsing & security advisory
│   │   │   ├── rate_limit_analyzer.py  # Standard & legacy rate limit inspection
│   │   │   ├── bot_fingerprint_analyzer.py # CDN & WAF fingerprint detection
│   │   │   ├── ip_analyzer.py          # Dual-stack classification, multi-RIR RDAP discovery
│   │   │   ├── reputation_service.py   # Live Tor cache, AbuseIPDB/IPinfo fallback, threat scoring
│   │   │   ├── bot_detector.py         # Behavioral multi-signal detection engine
│   │   │   ├── traffic_simulator.py    # Local detection lab generator
│   │   │   ├── proxy_analyzer.py       # SOCKS5 & HTTP proxy diagnostics
│   │   │   └── report_generator.py     # JSON and ReportLab PDF compiler
│   │   └── api/
│   │       └── routes/                 # REST endpoints (health, websites, ips, bots, proxies, lab, reports)
│   ├── tests/                          # Automated Pytest suite (34 unit & integration tests)
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── components/                 # Sidebar, Navbar, MetricCard, SeverityBadge
│   │   ├── pages/                      # Scanner, IP Intel, Bot Detection, Proxy, Lab, History, Rules
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
├── pyproject.toml                      # Ruff & Pytest configuration
├── README.md
├── SECURITY.md
└── LICENSE                             # MIT License
```

---

## 💻 Quick Start & Setup

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

# Create virtual environment (recommended)
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

## 🧪 Verified Test Results

BotShield includes **34 automated regression and integration tests** covering connection-level IP pinning, streaming body limits, multi-RIR RDAP fallback, live Tor caching, administrative API security, behavioral bot detection heuristics, and REST API contracts.

```bash
cd backend
python -m pytest tests -v
```

### Verified Test Run Metrics:
```
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.2.0 -- C:\Users\ibbg\AppData\Local\Programs\Python\Python312\python.exe
rootdir: C:\Users\ibbg\.gemini\antigravity\scratch\BotShield
collected 34 items

backend/tests/test_api_endpoints.py::test_health_check_endpoint PASSED   [  2%]
backend/tests/test_api_endpoints.py::test_ssrf_protection_on_scan_endpoint PASSED [  5%]
backend/tests/test_api_endpoints.py::test_ip_analysis_private_endpoint PASSED [  8%]
backend/tests/test_api_endpoints.py::test_bot_telemetry_and_summary_endpoint PASSED [ 11%]
backend/tests/test_api_endpoints.py::test_invalid_telemetry_source_ip_rejected PASSED [ 14%]
backend/tests/test_api_endpoints.py::test_detection_rules_list PASSED    [ 17%]
backend/tests/test_api_endpoints.py::test_lab_simulation_and_reset PASSED [ 20%]
backend/tests/test_admin_auth_protection PASSED   [ 23%]
backend/tests/test_admin_auth_production_fail_closed PASSED [ 26%]
backend/tests/test_bot_detector.py::test_empty_ip_evaluation PASSED      [ 29%]
backend/tests/test_bot_detector.py::test_high_frequency_trigger PASSED   [ 32%]
backend/tests/test_bot_detector.py::test_lab_scenario_automated_scraper PASSED [ 35%]
backend/tests/test_header_analyzer.py::test_full_security_headers PASSED [ 38%]
backend/tests/test_header_analyzer.py::test_missing_headers_penalties PASSED [ 41%]
backend/tests/test_header_analyzer.py::test_unsafe_csp_directives PASSED [ 44%]
backend/tests/test_ip_analyzer.py::test_private_ip_local_analysis PASSED [ 47%]
backend/tests/test_ip_analyzer.py::test_loopback_ipv6_analysis PASSED    [ 50%]
backend/tests/test_ip_analyzer.py::test_invalid_ip_format PASSED         [ 52%]
backend/tests/test_ip_analyzer.py::test_unverified_public_ip_never_labeled_malicious PASSED [ 55%]
backend/tests/test_ip_analyzer.py::test_rdap_registration_vs_asn_distinction PASSED [ 58%]
backend/tests/test_ip_analyzer.py::test_asn_resolved_when_external_provider_available PASSED [ 61%]
backend/tests/test_ip_analyzer.py::test_tor_exit_live_and_fallback PASSED [ 64%]
backend/tests/test_robots_analyzer.py::test_standard_robots_parsing PASSED [ 67%]
backend/tests/test_robots_analyzer.py::test_missing_robots_txt PASSED    [ 70%]
backend/tests/test_ssrf_security.py::test_private_and_loopback_ip_blocking PASSED [ 73%]
backend/tests/test_ssrf_security.py::test_additional_disallowed_ranges PASSED [ 76%]
backend/tests/test_ssrf_security.py::test_disallowed_schemes PASSED      [ 79%]
backend/tests/test_ssrf_security.py::test_localhost_hostname_blocking PASSED [ 82%]
backend/tests/test_ssrf_security.py::test_blocked_ports PASSED           [ 85%]
backend/tests/test_ssrf_security.py::test_credential_sanitization PASSED [ 88%]
backend/tests/test_connection_level_ip_pinning PASSED [ 91%]
backend/tests/test_ip_pinning_blocks_private_dns_rebinding PASSED [ 94%]
backend/tests/test_streaming_body_size_limit_content_length PASSED [ 97%]
backend/tests/test_streaming_body_size_limit_chunked PASSED [100%]

======================= 34 passed, 1 warning in 21.52s ========================
```

---

## ⚠️ Operational Limitations & Data Sources

To maintain technical credibility, BotShield explicitly documents its operational boundaries:
1. **Passive Scanning Boundary**: Inspecting a public homepage cannot detect anti-bot technologies enabled solely on authenticated API endpoints or deep checkout flows.
2. **IP RDAP vs. BGP Routing**: Standard IP RDAP queries return network registration objects (CIDR handle, registrant name). They do not return BGP routing table announcements. When external routing feeds are disabled, AS numbers are accurately labeled as unannounced in IP RDAP.
3. **PTR Records**: Reverse DNS relies on the upstream network operator maintaining PTR records. Lack of a PTR record is an observed absence, not an anomaly.
4. **Third-Party API Limits**: Free external threat feeds (AbuseIPDB, IPinfo) may impose rate limits. BotShield operates 100% locally and gracefully falls back to local and official RIR sources.

---

## 🔒 Security Model & Safe Harbor

BotShield is engineered as a **defensive security operations tool**:
* **No Circumvention Tools**: Does not implement CAPTCHA bypasses, identity spoofing, stealth scraping, or ban evasion.
* **SSRF Guardrails**: Outbound requests strictly forbid private IP addresses (RFC 1918), loopback, link-local, and cloud metadata services.
* **Connection-Level Pinning**: Eliminates TOCTOU DNS rebinding by connecting directly to the validated destination IP while preserving SNI.
* **Safe Logging**: Credentials, authorization tokens, and proxy passwords are automatically sanitized and redacted.
* **Authorized Auditing**: Users must only scan websites, IPs, and proxies they own or have documented permission to assess.

---

## 📜 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.
