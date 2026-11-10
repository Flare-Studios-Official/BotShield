"""BotShield robots.txt Analyzer

Parses and reviews robots.txt conventions responsibly without crawling
disallowed endpoints or treating crawl instructions as security barriers.
"""

from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse


class RobotsAnalysisResult:
    def __init__(
        self,
        found: bool,
        status_code: int,
        content: str,
        user_agents: List[str],
        disallow_rules: List[str],
        allow_rules: List[str],
        sitemaps: List[str],
        findings: List[Dict[str, Any]],
    ):
        self.found = found
        self.status_code = status_code
        self.content = content
        self.user_agents = user_agents
        self.disallow_rules = disallow_rules
        self.allow_rules = allow_rules
        self.sitemaps = sitemaps
        self.findings = findings

    def to_dict(self) -> Dict[str, Any]:
        return {
            "found": self.found,
            "status_code": self.status_code,
            "user_agents_count": len(self.user_agents),
            "disallow_rules_count": len(self.disallow_rules),
            "allow_rules_count": len(self.allow_rules),
            "sitemaps_count": len(self.sitemaps),
            "disallow_rules": self.disallow_rules[:20],  # preview top 20
            "sitemaps": self.sitemaps,
            "findings": self.findings,
        }


def parse_robots_txt(content: str, status_code: int) -> RobotsAnalysisResult:
    """Parses robots.txt text content into structured directives and defensive findings."""
    user_agents: List[str] = []
    disallow_rules: List[str] = []
    allow_rules: List[str] = []
    sitemaps: List[str] = []
    findings: List[Dict[str, Any]] = []

    if status_code != 200 or not content or not content.strip():
        findings.append({
            "name": "robots.txt Availability",
            "category": "robots",
            "severity": "info",
            "observed_value": f"HTTP {status_code}" if status_code != 200 else "Empty file",
            "description": "No accessible robots.txt was detected at /robots.txt.",
            "implication": "Search engines and automated web crawlers assume universal indexing permission.",
            "recommendation": "If indexing boundaries or sitemaps are desired, publish a standard robots.txt file.",
            "confidence": "confirmed",
        })
        return RobotsAnalysisResult(
            found=False,
            status_code=status_code,
            content="",
            user_agents=[],
            disallow_rules=[],
            allow_rules=[],
            sitemaps=[],
            findings=findings,
        )

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if ":" not in line:
            continue

        key, val = line.split(":", 1)
        key = key.strip().lower()
        val = val.strip()

        if key == "user-agent":
            if val not in user_agents:
                user_agents.append(val)
        elif key == "disallow":
            if val and val not in disallow_rules:
                disallow_rules.append(val)
        elif key == "allow":
            if val and val not in allow_rules:
                allow_rules.append(val)
        elif key == "sitemap":
            if val and val not in sitemaps:
                sitemaps.append(val)

    # Educational & Security Findings
    findings.append({
        "name": "robots.txt Advisory",
        "category": "robots",
        "severity": "info",
        "observed_value": f"{len(disallow_rules)} disallow rule(s), {len(sitemaps)} sitemap(s)",
        "description": "robots.txt is a voluntary crawling convention, not an authentication or access-control mechanism.",
        "implication": "Paths listed in Disallow are public. Malicious actors frequently review robots.txt to discover sensitive URL endpoints.",
        "recommendation": "Never rely on robots.txt for security. Enforce server-side authentication and authorization on all private endpoints.",
        "confidence": "confirmed",
    })

    # Sensitive path indicators in disallow
    sensitive_keywords = ["admin", "login", "secret", "private", "backup", "db", "config", "internal"]
    flagged_paths = [p for p in disallow_rules if any(k in p.lower() for k in sensitive_keywords)]

    if flagged_paths:
        findings.append({
            "name": "Sensitive Path Exposure in robots.txt",
            "category": "robots",
            "severity": "low",
            "observed_value": f"Flagged paths: {', '.join(flagged_paths[:5])}",
            "description": "Potentially sensitive endpoint names are explicitly enumerated in public disallow rules.",
            "implication": "Disclosing admin or backup directories in robots.txt gives attackers high-value targets to probe.",
            "recommendation": "Protect administrative resources with robust authentication; avoid publicizing unauthenticated internal paths.",
            "confidence": "observed",
        })

    return RobotsAnalysisResult(
        found=True,
        status_code=status_code,
        content=content,
        user_agents=user_agents,
        disallow_rules=disallow_rules,
        allow_rules=allow_rules,
        sitemaps=sitemaps,
        findings=findings,
    )
