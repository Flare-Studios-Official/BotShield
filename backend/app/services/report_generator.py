"""BotShield Report Generation Service

Compiles audit findings and metrics into structured JSON and executive-ready
PDF documents with severity color-coding, tables, and compliance notices.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.config import settings


def generate_audit_pdf(scan_data: Dict[str, Any], output_path: Path) -> Path:
    """Generates an executive-ready PDF report using ReportLab."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    primary_color = colors.HexColor("#0f172a")  # Slate 900
    brand_blue = colors.HexColor("#0284c7")     # Sky 600

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=primary_color
    )

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748b")
    )

    heading2 = ParagraphStyle(
        "H2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=primary_color
    )

    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#334155")
    )

    bold_body = ParagraphStyle(
        "BoldBody",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#1e293b")
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph("BotShield Security Assessment Report", title_style))
    story.append(Spacer(1, 4))
    gen_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    story.append(Paragraph(f"Generated on {gen_time} &bull; Open-Source Cybersecurity Operations Platform", subtitle_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=2, color=brand_blue, spaceBefore=4, spaceAfter=14))

    # 2. Executive Overview Table
    sec_score = scan_data.get("security_score", 0)
    score_color = colors.HexColor("#16a34a") if sec_score >= 80 else colors.HexColor("#ea580c") if sec_score >= 50 else colors.HexColor("#dc2626")

    meta_table_data = [
        [Paragraph("Target URL:", bold_body), Paragraph(scan_data.get("target_url", "N/A"), body_style),
         Paragraph("Security Score:", bold_body), Paragraph(f"<font color='{score_color.hexval()}'><b>{sec_score} / 100</b></font>", bold_body)],
        [Paragraph("Final Resolved URL:", bold_body), Paragraph(scan_data.get("final_url", "N/A"), body_style),
         Paragraph("HTTP Status:", bold_body), Paragraph(str(scan_data.get("status_code", "N/A")), body_style)],
        [Paragraph("Resolved IP:", bold_body), Paragraph(scan_data.get("resolved_ip", "N/A"), body_style),
         Paragraph("Response Time:", bold_body), Paragraph(f"{scan_data.get('response_time_ms', 0)} ms", body_style)],
        [Paragraph("HTTPS Enforced:", bold_body), Paragraph("Yes" if scan_data.get("https_enforced") else "No", body_style),
         Paragraph("TLS Version:", bold_body), Paragraph(scan_data.get("tls_version", "N/A"), body_style)],
        [Paragraph("TLS Cert Issuer:", bold_body), Paragraph(scan_data.get("tls_cert_issuer", "N/A"), body_style),
         Paragraph("TLS Expiry:", bold_body), Paragraph(scan_data.get("tls_cert_expiry", "N/A"), body_style)],
    ]

    meta_table = Table(meta_table_data, colWidths=[110, 160, 110, 160])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 16))

    # 3. Security Findings
    story.append(Paragraph("Detailed Security Findings & Matrix", heading2))
    story.append(Spacer(1, 6))

    findings = scan_data.get("findings", [])
    if not findings:
        story.append(Paragraph("No security findings or warnings were recorded for this target.", body_style))
    else:
        for idx, f in enumerate(findings, 1):
            sev = (f.get("severity") or "INFO").upper()
            name = f.get("name") or "Finding"
            obs = f.get("observed_value") or "N/A"
            desc = f.get("description") or ""
            rec = f.get("recommendation") or ""

            # Severity badge colors
            sev_color = colors.HexColor("#0284c7")  # blue
            if sev == "CRITICAL":
                sev_color = colors.HexColor("#dc2626")  # red
            elif sev == "HIGH":
                sev_color = colors.HexColor("#ea580c")    # orange
            elif sev == "MEDIUM":
                sev_color = colors.HexColor("#d97706")  # amber
            elif sev == "LOW":
                sev_color = colors.HexColor("#ca8a04")     # yellow

            finding_box = [
                [
                    Paragraph(f"<b>{idx}. {name}</b>", bold_body),
                    Paragraph(f"<font color='{sev_color.hexval()}'><b>[{sev}]</b></font>", bold_body)
                ],
                [Paragraph("Observed:", bold_body), Paragraph(obs, body_style)],
                [Paragraph("Description:", bold_body), Paragraph(desc, body_style)],
                [Paragraph("Remediation:", bold_body), Paragraph(rec, body_style)],
            ]

            f_table = Table(finding_box, colWidths=[90, 450])
            f_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ffffff")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("LINEBELOW", (0, 0), (-1, 0), 1, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(f_table)
            story.append(Spacer(1, 8))

    # 4. Safe Harbor & Methodology Disclaimer
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceBefore=6, spaceAfter=8))
    disclaimer_text = (
        "<b>Responsible Use Notice:</b> BotShield reports are strictly defensive assessments intended for authorized "
        "system auditing. Absence of a security header or rate-limit disclosure does not guarantee exploitable vulnerability. "
        "All tests originate from safe, non-invasive passive HTTP requests adhering strictly to RFC standards."
    )
    story.append(Paragraph(disclaimer_text, subtitle_style))

    doc.build(story)
    return output_path
