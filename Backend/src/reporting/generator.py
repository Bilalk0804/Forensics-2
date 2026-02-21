"""
Report Generator Module
Reads from database and creates PDF reports.
"""

from datetime import datetime
from typing import List, Dict, Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


class ReportGenerator:
    """Generates PDF reports from database analysis results."""

    def generate(
        self,
        report_data: Dict[str, Any],
        files: List[Dict[str, Any]],
        output_path: str,
    ) -> str:
        """Generate PDF report from analysis data."""
        from reportlab.lib.units import inch
        from reportlab.pdfgen import canvas
        
        styles = getSampleStyleSheet()
        title_style = styles["Title"]
        normal_style = styles["BodyText"]
        heading_style = styles["Heading2"]

        doc = SimpleDocTemplate(output_path, pagesize=letter)
        story = []

        # Title and metadata
        story.append(Paragraph("Sentinel Forensics Analysis Report", title_style))
        timestamp = report_data.get("timestamp", datetime.now().isoformat())
        story.append(Paragraph(f"Generated: {timestamp}", normal_style))
        story.append(Spacer(1, 12))

        # Case Summary
        story.append(Paragraph("Case Summary", heading_style))
        verdict = report_data.get("verdict", "NOT_SURE")
        confidence = report_data.get("confidence", 0)
        total_files = report_data.get("total_files", 0)
        execution_time = report_data.get("execution_time", 0)
        
        # Color-code verdict
        verdict_color = "#d9534f" if verdict == "MALICIOUS" else ("#f0ad4e" if verdict == "SUSPICIOUS" else "#5cb85c")

        summary_lines = [
            f"<b>Verdict:</b> <font color='{verdict_color}'><b>{verdict}</b></font>",
            f"<b>Confidence:</b> {confidence * 100:.1f}%",
            f"<b>Total Files Analyzed:</b> {total_files:,}",
            f"<b>Analysis Duration:</b> {execution_time:.2f} seconds",
        ]
        story.append(Paragraph("<br />".join(summary_lines), normal_style))
        story.append(Spacer(1, 12))

        risk_breakdown = report_data.get("risk_breakdown") or {}
        if risk_breakdown:
            story.append(Paragraph("Risk Breakdown", heading_style))
            breakdown_lines = [
                f"HIGH: {risk_breakdown.get('HIGH', 0)}",
                f"MEDIUM: {risk_breakdown.get('MEDIUM', 0)}",
                f"LOW: {risk_breakdown.get('LOW', 0)}",
            ]
            story.append(Paragraph("<br />".join(breakdown_lines), normal_style))
            story.append(Spacer(1, 12))

        threats = report_data.get("threats_found") or []
        if threats:
            story.append(Paragraph("Threats Found", heading_style))
            threat_rows = [["Source", "Severity", "Description"]]
            for threat in threats:
                threat_rows.append(
                    [
                        str(threat.get("source", "")),
                        str(threat.get("severity", "")),
                        Paragraph(str(threat.get("description", "")), normal_style),
                    ]
                )
            threat_table = Table(threat_rows, repeatRows=1, colWidths=[90, 70, 380])
            threat_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ]
                )
            )
            story.append(threat_table)
            story.append(Spacer(1, 12))

        story.append(Paragraph("Files Scanned", heading_style))
        file_rows = [["File Path", "Size", "MIME", "Artifacts", "Risk"]]
        for file_item in files:
            file_rows.append(
                [
                    Paragraph(str(file_item.get("file_path", "")), normal_style),
                    str(file_item.get("file_size", "")),
                    str(file_item.get("mime_type", "")),
                    str(file_item.get("artifact_count", "")),
                    str(file_item.get("risk_level", "")),
                ]
            )

        file_table = Table(file_rows, repeatRows=1, colWidths=[250, 60, 110, 60, 50])
        file_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ]
            )
        )
        story.append(file_table)

        doc.build(story)
        return output_path
