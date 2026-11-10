# BotShield REST API Reference

The BotShield API provides programmatic access to defensive scanning, IP intelligence lookups, telemetry ingestion, detection rule configuration, and report generation.

Interactive OpenAPI Swagger documentation is available locally at:
`http://127.0.0.1:8000/api/docs`

---

## Authentication & Authorization

Public and read-only endpoints do not require authentication by default.

Administrative endpoints (rule modifications, false-positive reviews, and telemetry resets) are protected by administrative authorization:
* **Header**: `X-API-Key: <BOTSHIELD_ADMIN_API_KEY>` or `Authorization: Bearer <BOTSHIELD_ADMIN_API_KEY>`
* **Production Behavior**: When `BOTSHIELD_ENV=production`, administrative endpoints fail closed (HTTP 403) unless `BOTSHIELD_ADMIN_API_KEY` is configured.
* **Telemetry Ingest Key**: When `BOTSHIELD_INGEST_API_KEY` is configured, telemetry ingestion (`POST /api/bots/events`) requires the corresponding `X-API-Key` header.

---

## Health Check

### `GET /api/health`
Returns system operational status, database connectivity, and environment settings.

**Response (200 OK):**
```json
{
  "status": "online",
  "app": "BotShield",
  "version": "1.0.0",
  "database": "connected",
  "environment": "development",
  "external_intelligence_enabled": true
}
```

---

## Website Security Scanner

### `POST /api/websites/scan`
Executes an SSRF-safe passive security inspection against a target URL. Outbound connections are pinned directly to the resolved IP to prevent DNS rebinding.

**Request:**
```json
{
  "target_url": "https://example.com"
}
```

**Response (200 OK):**
```json
{
  "id": "c1f7a0b2-3c4d-4e5f-9a1b-0123456789ab",
  "target_url": "https://example.com",
  "final_url": "https://example.com",
  "resolved_ip": "93.184.216.34",
  "status_code": 200,
  "response_time_ms": 142.5,
  "https_enforced": true,
  "tls_version": "TLSv1.3",
  "tls_cert_issuer": "DigiCert Global Root G2",
  "tls_cert_expiry": "Jan 15 23:59:59 2027 GMT",
  "security_score": 65,
  "findings": [
    {
      "id": "1",
      "category": "header",
      "name": "Content-Security-Policy (CSP)",
      "severity": "medium",
      "observed_value": "Header missing",
      "description": "Restricts approved sources of scripts, styles, objects, and frames.",
      "implication": "Absence of CSP increases impact of Cross-Site Scripting (XSS).",
      "recommendation": "Define a restrictive CSP starting with default-src 'self'.",
      "confidence": "confirmed"
    }
  ]
}
```

---

## IP Intelligence

### `POST /api/ips/analyze`
Analyzes an IPv4 or IPv6 address using multi-RIR RDAP discovery, reverse DNS, and live threat intelligence feeds.

**Request:**
```json
{
  "ip_address": "8.8.8.8"
}
```

**Response (200 OK):**
```json
{
  "id": "8a9b0c1d-2e3f-4a5b-6c7d-8e9f0a1b2c3d",
  "ip_address": "8.8.8.8",
  "ip_version": 4,
  "is_routable": true,
  "classification": "public",
  "asn": "AS15169",
  "as_org": "Google LLC",
  "reverse_dns": "dns.google",
  "country_name": "United States",
  "city": "Mountain View",
  "is_datacenter": true,
  "is_vpn": false,
  "is_tor": false,
  "reputation_score": 5,
  "threat_level": "low",
  "provider_sources": {
    "rdap": "ARIN RDAP",
    "ipinfo": "IPinfo Geolocation & Privacy API"
  }
}
```

---

## Bot Telemetry Ingestion

### `POST /api/bots/events`
Records an inbound HTTP request event and triggers behavioral evaluation.

**Request:**
```json
{
  "source_ip": "198.51.100.20",
  "http_method": "GET",
  "path": "/api/products?page=1",
  "user_agent": "python-requests/2.31.0",
  "response_status": 200,
  "duration_ms": 25.4
}
```

---

## Administrative Detection Rules

### `GET /api/bots/rules`
Lists all active behavioral detection rules, weights, and threshold values.

### `PUT /api/bots/rules/{rule_id}`
Updates scoring weights, thresholds, or enables/disables a rule. **Requires administrative authorization.**

**Request:**
```json
{
  "weight": 30,
  "threshold_value": 25.0,
  "enabled": true
}
```

---

## Proxy Intelligence & Diagnostics

### `POST /api/proxies/test`
Audits connectivity and egress characteristics of user-authorized HTTP, HTTPS, or SOCKS5 proxies.

**Request:**
```json
{
  "proxy_url": "socks5://proxy.example.com:1080",
  "target_url": "https://api.ipify.org?format=json"
}
```

---

## Detection Lab

### `POST /api/lab/run`
Triggers an isolated local traffic simulation against local endpoints.

**Request:**
```json
{
  "scenario": "automated_scraper",
  "request_count": 25,
  "interval_ms": 50
}
```

### `POST /api/lab/reset`
Clears demonstration events without altering production logs. **Requires administrative authorization.**
