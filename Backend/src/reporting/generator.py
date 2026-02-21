"""
Professional Forensic PDF Report Generator
Produces a colour-coded, section-structured report with:
  - Cover / header banner with verdict
  - Executive summary with risk breakdown
  - Threats table (severity-coloured rows)
  - Per-file evidence cards with keyword findings
  - Page headers / footers / page numbers
"""

from datetime import datetime
from typing import List, Dict, Any, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether,
)

# ── Colour palette ─────────────────────────────────────────────────
_DARK = colors.HexColor("#0f172a")
_SLATE = colors.HexColor("#334155")
_MUTED = colors.HexColor("#64748b")
_BORDER = colors.HexColor("#cbd5e1")
_BG_LIGHT = colors.HexColor("#f8fafc")

_RED = colors.HexColor("#dc2626")
_RED_LIGHT = colors.HexColor("#fee2e2")
_ORANGE = colors.HexColor("#ea580c")
_ORANGE_LIGHT = colors.HexColor("#fff7ed")
_YELLOW = colors.HexColor("#ca8a04")
_YELLOW_LIGHT = colors.HexColor("#fefce8")
_GREEN = colors.HexColor("#16a34a")
_GREEN_LIGHT = colors.HexColor("#f0fdf4")


def _risk_colors(level: str):
    """Return (text_color, bg_color) for a risk level."""
    level = (level or "").upper()
    if level in ("CRITICAL", "HIGH"):
        return _RED, _RED_LIGHT
    if level == "MEDIUM":
        return _ORANGE, _ORANGE_LIGHT
    return _GREEN, _GREEN_LIGHT


def _verdict_colors(verdict: str):
    verdict = (verdict or "").upper()
    if verdict == "MALICIOUS":
        return colors.white, _RED
    if verdict == "SUSPICIOUS":
        return colors.white, _ORANGE
    return colors.white, _GREEN


class ReportGenerator:
    """Generates professional forensic PDF reports."""

    # ── Styles ──────────────────────────────────────────────────────
    def _build_styles(self):
        base = getSampleStyleSheet()
        s = {}
        s["body"] = base["BodyText"]
        s["body"].fontSize = 9
        s["body"].leading = 13

        s["title"] = ParagraphStyle(
            "RptTitle", parent=base["Title"],
            fontSize=22, leading=28, textColor=_DARK,
            spaceAfter=4, alignment=TA_CENTER,
        )
        s["subtitle"] = ParagraphStyle(
            "RptSub", parent=base["Normal"],
            fontSize=10, textColor=_MUTED, alignment=TA_CENTER, spaceAfter=14,
        )
        s["h1"] = ParagraphStyle(
            "RptH1", parent=base["Heading1"],
            fontSize=15, leading=20, textColor=_DARK,
            spaceBefore=18, spaceAfter=6,
            borderWidth=0, borderPadding=0,
        )
        s["h2"] = ParagraphStyle(
            "RptH2", parent=base["Heading2"],
            fontSize=12, leading=16, textColor=_SLATE,
            spaceBefore=10, spaceAfter=4,
        )
        s["small"] = ParagraphStyle(
            "RptSmall", parent=base["Normal"],
            fontSize=8, textColor=_MUTED,
        )
        s["kw_critical"] = ParagraphStyle(
            "KwC", parent=base["Normal"],
            fontSize=9, textColor=_RED, leading=12,
        )
        s["kw_high"] = ParagraphStyle(
            "KwH", parent=base["Normal"],
            fontSize=9, textColor=_ORANGE, leading=12,
        )
        s["kw_medium"] = ParagraphStyle(
            "KwM", parent=base["Normal"],
            fontSize=9, textColor=_YELLOW, leading=12,
        )
        s["verdict_label"] = ParagraphStyle(
            "VLabel", parent=base["Normal"],
            fontSize=16, leading=22, alignment=TA_CENTER,
        )
        return s

    # ── Page chrome ─────────────────────────────────────────────────
    @staticmethod
    def _header_footer(canvas_obj, doc):
        canvas_obj.saveState()
        # Header line
        canvas_obj.setStrokeColor(_BORDER)
        canvas_obj.setLineWidth(0.5)
        canvas_obj.line(doc.leftMargin, doc.height + doc.topMargin + 6,
                        doc.width + doc.leftMargin, doc.height + doc.topMargin + 6)
        canvas_obj.setFont("Helvetica", 7)
        canvas_obj.setFillColor(_MUTED)
        canvas_obj.drawString(doc.leftMargin, doc.height + doc.topMargin + 10,
                              "SENTINEL FORENSICS  \u2022  CONFIDENTIAL")
        # Footer
        canvas_obj.line(doc.leftMargin, doc.bottomMargin - 12,
                        doc.width + doc.leftMargin, doc.bottomMargin - 12)
        canvas_obj.drawString(doc.leftMargin, doc.bottomMargin - 24,
                              f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
        canvas_obj.drawRightString(doc.width + doc.leftMargin, doc.bottomMargin - 24,
                                   f"Page {doc.page}")
        canvas_obj.restoreState()

    # ── Public API ──────────────────────────────────────────────────
    def generate(
        self,
        report_data: Dict[str, Any],
        files: List[Dict[str, Any]],
        output_path: str,
    ) -> str:
        """Generate professional PDF report from analysis data."""
        s = self._build_styles()

        doc = SimpleDocTemplate(
            output_path, pagesize=letter,
            topMargin=0.75 * inch, bottomMargin=0.75 * inch,
            leftMargin=0.65 * inch, rightMargin=0.65 * inch,
        )
        story: list = []

        verdict = report_data.get("verdict", "UNKNOWN")
        confidence = report_data.get("confidence", 0)
        total_files = report_data.get("total_files", 0)
        flagged_files = report_data.get("flagged_files", len(files))
        exec_time = report_data.get("execution_time", 0)
        risk_bk = report_data.get("risk_breakdown") or {}
        threats = report_data.get("threats_found") or []
        evidence = report_data.get("evidence_details") or []
        evidence_path = report_data.get("evidence_path", "")
        models_used = report_data.get("models_used") or []

        # ─── 1. COVER / HEADER ─────────────────────────────────────
        story.append(Spacer(1, 24))
        story.append(Paragraph("SENTINEL FORENSICS", s["title"]))
        story.append(Paragraph("Digital Evidence Analysis Report", s["subtitle"]))
        story.append(Spacer(1, 8))

        # Verdict banner
        v_fg, v_bg = _verdict_colors(verdict)
        verdict_table = Table(
            [[Paragraph(
                f"<font color='#{v_fg.hexval()[2:]}'><b>VERDICT: {verdict}  \u2014  "
                f"Confidence {confidence * 100:.1f}%</b></font>",
                s["verdict_label"],
            )]],
            colWidths=[doc.width],
        )
        verdict_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), v_bg),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("ROUNDEDCORNERS", [6, 6, 6, 6]),
        ]))
        story.append(verdict_table)
        story.append(Spacer(1, 16))

        # ─── 2. EXECUTIVE SUMMARY ──────────────────────────────────
        story.append(Paragraph("Executive Summary", s["h1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=_BORDER, spaceAfter=8))

        meta_rows = [
            ["Evidence Path", evidence_path or "\u2014"],
            ["Models Used", ", ".join(models_used) if models_used else "\u2014"],
            ["Total Files Scanned", str(total_files)],
            ["Flagged Files (shown below)", str(flagged_files)],
            ["Analysis Duration", f"{exec_time:.2f}s"],
        ]
        meta_table = Table(meta_rows, colWidths=[170, doc.width - 170])
        meta_table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("TEXTCOLOR", (0, 0), (0, -1), _SLATE),
            ("TEXTCOLOR", (1, 0), (1, -1), _DARK),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("LINEBELOW", (0, 0), (-1, -2), 0.3, _BORDER),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 12))

        # Risk breakdown bar
        story.append(Paragraph("Risk Distribution", s["h2"]))
        rb_data = [
            ["CRITICAL / HIGH", str(risk_bk.get("HIGH", 0)), ""],
            ["MEDIUM", str(risk_bk.get("MEDIUM", 0)), ""],
            ["LOW", str(risk_bk.get("LOW", 0)), ""],
        ]
        rb_table = Table(rb_data, colWidths=[130, 50, doc.width - 180])
        rb_styles = [
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("TEXTCOLOR", (0, 0), (0, 0), _RED),
            ("TEXTCOLOR", (0, 1), (0, 1), _ORANGE),
            ("TEXTCOLOR", (0, 2), (0, 2), _GREEN),
        ]
        rb_table.setStyle(TableStyle(rb_styles))
        story.append(rb_table)
        story.append(Spacer(1, 14))

        # ─── 3. THREATS TABLE ──────────────────────────────────────
        if threats:
            story.append(Paragraph("Threats Detected", s["h1"]))
            story.append(HRFlowable(width="100%", thickness=1, color=_BORDER, spaceAfter=8))

            t_rows = [["#", "Source", "Severity", "Description"]]
            for idx, t in enumerate(threats, 1):
                sev = str(t.get("severity", "")).upper()
                t_rows.append([
                    str(idx),
                    str(t.get("source", "")),
                    sev,
                    Paragraph(str(t.get("description", "")), s["body"]),
                ])
            t_table = Table(t_rows, repeatRows=1, colWidths=[28, 100, 70, doc.width - 198])
            t_styles = [
                ("BACKGROUND", (0, 0), (-1, 0), _DARK),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.4, _BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
            # Colour each row by severity
            for row_idx in range(1, len(t_rows)):
                sev = t_rows[row_idx][2]
                _, bg = _risk_colors(sev)
                t_styles.append(("BACKGROUND", (0, row_idx), (-1, row_idx), bg))
            t_table.setStyle(TableStyle(t_styles))
            story.append(t_table)
            story.append(Spacer(1, 14))

        # ─── 4. FLAGGED FILES TABLE ────────────────────────────────
        if files:
            story.append(Paragraph("Flagged Files", s["h1"]))
            story.append(HRFlowable(width="100%", thickness=1, color=_BORDER, spaceAfter=8))

            f_rows = [["#", "File Path", "Size", "MIME", "Risk"]]
            for idx, fi in enumerate(files, 1):
                risk = fi.get("risk_level", "LOW")
                f_rows.append([
                    str(idx),
                    Paragraph(str(fi.get("file_path", "")), s["body"]),
                    str(fi.get("file_size", "")),
                    str(fi.get("mime_type", "")),
                    risk,
                ])
            f_table = Table(f_rows, repeatRows=1, colWidths=[28, doc.width - 228, 60, 90, 50])
            f_styles = [
                ("BACKGROUND", (0, 0), (-1, 0), _DARK),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.4, _BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
            for row_idx in range(1, len(f_rows)):
                risk = f_rows[row_idx][4]
                fg, bg = _risk_colors(risk)
                f_styles.append(("BACKGROUND", (4, row_idx), (4, row_idx), bg))
                f_styles.append(("TEXTCOLOR", (4, row_idx), (4, row_idx), fg))
                f_styles.append(("FONTNAME", (4, row_idx), (4, row_idx), "Helvetica-Bold"))
            f_table.setStyle(TableStyle(f_styles))
            story.append(f_table)
            story.append(Spacer(1, 14))

        # ─── 5. EVIDENCE DETAIL CARDS ──────────────────────────────
        if evidence:
            story.append(PageBreak())
            story.append(Paragraph("Evidence Detail", s["h1"]))
            story.append(HRFlowable(width="100%", thickness=1, color=_BORDER, spaceAfter=8))
            story.append(Paragraph(
                "Each card shows per-file findings from the analysis models. "
                "Only files with MEDIUM / HIGH / CRITICAL risk are included.",
                s["body"],
            ))
            story.append(Spacer(1, 10))

            for ev in evidence:
                risk = ev.get("risk_level", "MEDIUM")
                fg, bg = _risk_colors(risk)
                fname = ev.get("file", "unknown")
                model = ev.get("model", "")

                card_items: list = []

                # Card header row
                hdr = Table(
                    [[
                        Paragraph(f"<b>{fname}</b>", s["body"]),
                        Paragraph(f"<font color='#{fg.hexval()[2:]}'><b>{risk}</b></font>", s["body"]),
                    ]],
                    colWidths=[doc.width - 80, 60],
                )
                hdr.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), bg),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("ALIGN", (1, 0), (1, 0), "CENTER"),
                    ("ROUNDEDCORNERS", [4, 4, 0, 0]),
                ]))
                card_items.append(hdr)

                # Card body rows
                body_rows = []
                if model:
                    body_rows.append(["Model", model])
                label = ev.get("label") or ev.get("threat_label") or ""
                if label:
                    body_rows.append(["Label", label])
                conf = ev.get("confidence", 0)
                if conf:
                    body_rows.append(["Confidence", f"{conf * 100:.1f}%"])
                summary = ev.get("summary", "")
                if summary:
                    body_rows.append(["Summary", Paragraph(str(summary)[:300], s["body"])])

                # Keywords
                crit_kws = ev.get("critical_keywords") or []
                high_kws = ev.get("high_keywords") or []
                med_kws = ev.get("medium_keywords") or []
                if crit_kws:
                    body_rows.append(["Critical Keywords",
                                      Paragraph(", ".join(crit_kws[:15]), s["kw_critical"])])
                if high_kws:
                    body_rows.append(["High Keywords",
                                      Paragraph(", ".join(high_kws[:15]), s["kw_high"])])
                if med_kws:
                    body_rows.append(["Medium Keywords",
                                      Paragraph(", ".join(med_kws[:15]), s["kw_medium"])])

                # Boolean flags
                flags = []
                if ev.get("is_malicious"):
                    flags.append("Malware Detected")
                if ev.get("is_deepfake"):
                    flags.append("Deepfake Detected")
                if ev.get("violence_detected"):
                    flags.append("Violence Detected")
                if flags:
                    body_rows.append(["Flags", ", ".join(flags)])

                if body_rows:
                    body_table = Table(body_rows, colWidths=[110, doc.width - 130])
                    body_table.setStyle(TableStyle([
                        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("TEXTCOLOR", (0, 0), (0, -1), _SLATE),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("LINEBELOW", (0, 0), (-1, -2), 0.3, _BORDER),
                        ("BOX", (0, 0), (-1, -1), 0.5, _BORDER),
                    ]))
                    card_items.append(body_table)

                card_items.append(Spacer(1, 12))
                story.append(KeepTogether(card_items))

        # ─── 6. FOOTER NOTE ────────────────────────────────────────
        story.append(Spacer(1, 24))
        story.append(HRFlowable(width="100%", thickness=0.5, color=_MUTED, spaceAfter=6))
        story.append(Paragraph(
            "This report was automatically generated by Sentinel Forensics. "
            "Contents are confidential and intended for authorized personnel only.",
            s["small"],
        ))

        doc.build(story, onFirstPage=self._header_footer, onLaterPages=self._header_footer)
        return output_path
