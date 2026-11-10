# Security Policy

## Responsible Use & Safe Harbor

BotShield is an open-source defensive security operations platform. It is engineered to help operators, system administrators, and security analysts audit security headers, identify suspicious traffic anomalies, evaluate IP reputation, and diagnose authorized proxies.

### Defensive Boundaries
1. **SSRF Guardrails**: All outbound HTTP requests made by the website scanner and proxy analyzer resolve destinations through an isolated validator. Any address falling within RFC 1918 private subnets, loopback ranges (`127.0.0.0/8`, `::1`), link-local spaces, or cloud metadata endpoints (`169.254.169.254`) is strictly blocked.
2. **Credential Sanitization**: Passwords, authorization bearer tokens, and proxy basic-auth credentials are automatically scrubbed from logs and database storage.
3. **No Weaponization**: BotShield does not implement CAPTCHA bypasses, identity rotation, stealth scraping, or denial-of-service capabilities.
4. **Authorized Testing**: Users must ensure all targets are owned or explicitly authorized for security assessment.

## Reporting a Security Vulnerability

If you discover a security vulnerability in BotShield, please report it privately:

- **Email**: security@botshield.dev (or open a private security advisory on GitHub)
- **Do not open public GitHub issues** for zero-day vulnerabilities.
