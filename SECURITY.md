# Security Policy

## Responsible Use & Safe Harbor

BotShield is an open-source defensive security operations platform. It is engineered to help operators, system administrators, and security analysts audit security headers, identify suspicious traffic anomalies, evaluate IP reputation, and diagnose authorized proxies.

### Defensive Boundaries & Technical Controls
1. **SSRF Guardrails & Connection-Level IP Pinning**:
   - Outbound HTTP requests made by the website scanner, redirect hops, robots.txt fetching, and proxy egress validation resolve destinations through strict defense-in-depth filters.
   - Any address falling within RFC 1918 private subnets, loopback ranges (`127.0.0.0/8`, `::1`), link-local spaces, CGNAT (`100.64.0.0/10`), documentation networks (TEST-NET), or cloud metadata endpoints (`169.254.169.254`, `fd00:ec2::254`, metadata hostnames) is strictly blocked.
   - **DNS Rebinding Prevention**: Outbound TCP connections are pinned directly to the SSRF-validated IP using a custom `httpcore` network backend (`SSRFPinnedSyncBackend`). This eliminates Time-of-Check / Time-of-Use (TOCTOU) DNS rebinding windows while preserving TLS Server Name Indication (SNI) and strict certificate chain validation against the target hostname.
2. **HTTP Streaming Body Limits**:
   - Outbound HTTP requests enforce a strict maximum response body limit (default: 2 MB) using streaming chunk counters.
   - If a server responds with an oversized `Content-Length` or streams data beyond the configured ceiling, the connection is aborted immediately without buffering, preventing denial-of-service and memory exhaustion attacks.
3. **Administrative Access Control**:
   - Detection rule modifications (`PUT /api/bots/rules/{id}`), analyst review submissions (`POST /api/bots/detections/{id}/review`), and lab reset operations (`POST /api/lab/reset`) require administrative authorization via `BOTSHIELD_ADMIN_API_KEY` (`X-API-Key` or `Authorization: Bearer <key>`).
   - In production environments (`BOTSHIELD_ENV=production`), administrative endpoints fail closed (HTTP 403) unless an admin API key is explicitly configured.
4. **Credential Sanitization**: Passwords, authorization bearer tokens, and proxy basic-auth credentials are automatically scrubbed from logs and database storage using deterministic regex redactors.
5. **No Weaponization**: BotShield does not implement CAPTCHA bypasses, identity rotation, stealth scraping, or denial-of-service capabilities.
6. **Authorized Testing**: Users must ensure all targets are owned or explicitly authorized for security assessment.

## Reporting a Security Vulnerability

If you discover a security vulnerability in BotShield, please report it privately:

- **Email**: security@botshield.dev (or open a private security advisory on GitHub)
- **Do not open public GitHub issues** for security vulnerabilities.

Please provide:
- A clear description of the vulnerability.
- Steps to reproduce or proof-of-concept payload.
- Potential impact and affected components.

We acknowledge receipt within 48 hours and coordinate prompt remediation.
