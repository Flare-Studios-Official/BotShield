"""Report Export API Routes (JSON & PDF)."""

import json
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.schema_models import IPAnalysisRecord, WebsiteFinding, WebsiteScan
from app.services.report_generator import generate_json_report, generate_pdf_report

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/website/{scan_id}/json")
def export_website_scan_json(scan_id: str, db: Session = Depends(get_db)):
    """Exports website scan findings as structured JSON."""
    scan = db.query(WebsiteScan).filter(WebsiteScan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    findings = db.query(WebsiteFinding).filter(WebsiteFinding.scan_id == scan.id).all()
    data = {
        "scan_id": scan.id,
        "target_url": scan.target_url,
        "final_url": scan.final_url,
        "resolved_ip": scan.resolved_ip,
        "status_code": scan.status_code,
        "security_score": scan.security_score,
        "https_enforced": scan.https_enforced,
        "tls_version": scan.tls_version,
        "tls_cert_issuer": scan.tls_cert_issuer,
        "tls_cert_expiry": scan.tls_cert_expiry,
        "created_at": scan.created_at.isoformat(),
        "findings": [
            {
                "category": f.category,
                "name": f.name,
                "severity": f.severity,
                "observed_value": f.observed_value,
                "description": f.description,
                "recommendation": f.recommendation,
                "confidence": f.confidence,
            }
            for f in findings
        ]
    }

    json_str = generate_json_report(data)
    return Response(
        content=json_str,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=botshield_scan_{scan_id[:8]}.json"}
    )


@router.get("/website/{scan_id}/pdf")
def export_website_scan_pdf(scan_id: str, db: Session = Depends(get_db)):
    """Exports website scan findings as a formatted executive PDF report."""
    scan = db.query(WebsiteScan).filter(WebsiteScan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    findings = db.query(WebsiteFinding).filter(WebsiteFinding.scan_id == scan.id).all()
    findings_list = [
        {
            "name": f.name,
            "severity": f.severity,
            "observed_value": f.observed_value,
            "description": f.implication,
            "recommendation": f.recommendation,
        }
        for f in findings
    ]

    metadata = {
        "Final Resolved URL": scan.final_url,
        "Resolved IP Address": scan.resolved_ip,
        "HTTP Status Code": str(scan.status_code),
        "Response Time": f"{scan.response_time_ms} ms",
        "HTTPS / TLS Version": f"{scan.tls_version} ({'Enforced' if scan.https_enforced else 'Not enforced'})",
        "Certificate Issuer": scan.tls_cert_issuer,
    }

    pdf_bytes = generate_pdf_report(
        title="BotShield Website Security Report",
        target=scan.target_url,
        category="Website Security Audit",
        score=scan.security_score,
        findings=findings_list,
        metadata=metadata,
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=botshield_scan_{scan_id[:8]}.pdf"}
    )


@router.get("/ip/{ip_record_id}/json")
def export_ip_analysis_json(ip_record_id: str, db: Session = Depends(get_db)):
    """Exports IP intelligence analysis as structured JSON."""
    rec = db.query(IPAnalysisRecord).filter(IPAnalysisRecord.id == ip_record_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="IP analysis record not found.")

    try:
        signals = json.loads(rec.signals_json or "[]")
    except Exception:
        signals = []

    try:
        sources = json.loads(rec.provider_sources_json or "{}")
    except Exception:
        sources = {}

    data = {
        "record_id": rec.id,
        "ip_address": rec.ip_address,
        "classification": rec.classification,
        "asn": rec.asn,
        "as_org": rec.as_org,
        "reverse_dns": rec.reverse_dns,
        "country": rec.country_name,
        "city": rec.city,
        "reputation_score": rec.reputation_score,
        "threat_level": rec.threat_level,
        "is_datacenter": rec.is_datacenter,
        "is_vpn": rec.is_vpn,
        "is_tor": rec.is_tor,
        "sources": sources,
        "signals": signals,
        "created_at": rec.created_at.isoformat(),
    }

    json_str = generate_json_report(data)
    return Response(
        content=json_str,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=botshield_ip_{rec.ip_address.replace(':', '_')}.json"}
    )


@router.get("/ip/{ip_record_id}/pdf")
def export_ip_analysis_pdf(ip_record_id: str, db: Session = Depends(get_db)):
    """Exports IP intelligence analysis as a formatted PDF report."""
    rec = db.query(IPAnalysisRecord).filter(IPAnalysisRecord.id == ip_record_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="IP analysis record not found.")

    try:
        signals = json.loads(rec.signals_json or "[]")
    except Exception:
        signals = []

    metadata = {
        "IP Version": f"IPv{rec.ip_version}",
        "Routing Classification": rec.classification.capitalize(),
        "Autonomous System": f"{rec.asn} ({rec.as_org})",
        "Reverse DNS Hostname": rec.reverse_dns or "None",
        "Approximate Location": f"{rec.city}, {rec.country_name}",
        "Infrastructure Flags": f"Datacenter: {rec.is_datacenter} | VPN: {rec.is_vpn} | Tor: {rec.is_tor}",
    }

    findings = [
        {
            "name": s.get("indicator", "Signal"),
            "severity": s.get("severity", "info"),
            "observed_value": f"Source: {s.get('source', 'Local')}",
            "description": s.get("details", ""),
            "recommendation": "Review threat reputation before whitelisting or blocking this subnet.",
        }
        for s in signals
    ]

    pdf_bytes = generate_pdf_report(
        title="BotShield IP Reputation Intelligence Report",
        target=rec.ip_address,
        category="IP Intelligence Assessment",
        score=rec.reputation_score,
        findings=findings,
        metadata=metadata,
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=botshield_ip_{rec.ip_address.replace(':', '_')}.pdf"}
    )
