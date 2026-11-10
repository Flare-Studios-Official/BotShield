"""Tests for robots.txt parsing and sensitive path indicators."""

from app.services.robots_analyzer import parse_robots_txt


def test_standard_robots_parsing():
    content = """
User-agent: Googlebot
Disallow: /private/
Allow: /public/

User-agent: *
Disallow: /admin/
Disallow: /backup/
Sitemap: https://example.com/sitemap.xml
"""
    result = parse_robots_txt(content, status_code=200)
    assert result.found is True
    assert "Googlebot" in result.user_agents
    assert "*" in result.user_agents
    assert "/private/" in result.disallow_rules
    assert "/admin/" in result.disallow_rules
    assert "https://example.com/sitemap.xml" in result.sitemaps

    finding_names = [f["name"] for f in result.findings]
    assert "robots.txt Advisory" in finding_names
    assert "Sensitive Path Exposure in robots.txt" in finding_names


def test_missing_robots_txt():
    result = parse_robots_txt("", status_code=404)
    assert result.found is False
    assert len(result.findings) == 1
    assert result.findings[0]["name"] == "robots.txt Availability"
