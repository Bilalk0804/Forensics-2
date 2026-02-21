"""
Forensics PDF Report Generator
Creates professional PDF reports using ReportLab.
"""

from datetime import datetime
import os

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, cm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    from reportlab.platypus import PageBreak, KeepTogether
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class ForensicsReportGenerator:
    """Generates professional forensics PDF reports."""
    
    # Color scheme
    COLORS = {
        'critical': colors.Color(0.8, 0.1, 0.1),  # Dark red
        'high': colors.Color(0.9, 0.3, 0.1),       # Orange-red
        'medium': colors.Color(0.9, 0.6, 0.1),    # Orange
        'low': colors.Color(0.2, 0.6, 0.2),       # Green
        'header': colors.Color(0.1, 0.2, 0.4),    # Dark blue
        'subheader': colors.Color(0.2, 0.3, 0.5),
    }
    
    def __init__(self):
        if not REPORTLAB_AVAILABLE:
            raise ImportError("ReportLab is required for PDF generation. Install with: pip install reportlab")
        
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles."""
        self.styles.add(ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            textColor=self.COLORS['header'],
            spaceAfter=30
        ))
        
        self.styles.add(ParagraphStyle(
            'SectionHeader',
            parent=self.styles['Heading1'],
            fontSize=16,
            textColor=self.COLORS['header'],
            spaceBefore=20,
            spaceAfter=10
        ))
        
        self.styles.add(ParagraphStyle(
            'FileHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=self.COLORS['subheader'],
            spaceBefore=15,
            spaceAfter=8
        ))
        
        self.styles.add(ParagraphStyle(
            'RiskCritical',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=self.COLORS['critical'],
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            'RiskHigh',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=self.COLORS['high'],
            fontName='Helvetica-Bold'
        ))
    
    def generate_report(self, job_id: str, results: list, output_path: str):
        """
        Generate a PDF forensics report.
        
        Args:
            job_id: Unique job identifier
            results: List of file analysis results
            output_path: Path to save PDF
        """
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=1*cm,
            leftMargin=1*cm,
            topMargin=2*cm,
            bottomMargin=2*cm
        )
        
        story = []
        
        # Title
        story.append(Paragraph("FORENSICS ANALYSIS REPORT", self.styles['CustomTitle']))
        story.append(Spacer(1, 0.3*inch))
        
        # Report metadata
        meta_data = [
            ['Report ID:', job_id],
            ['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
            ['Files Analyzed:', str(len(results))],
        ]
        
        # Calculate overall risk
        overall_risk = self._calculate_overall_risk(results)
        meta_data.append(['Overall Risk:', overall_risk.upper()])
        
        meta_table = Table(meta_data, colWidths=[3*cm, 10*cm])
        meta_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('TEXTCOLOR', (1, -1), (1, -1), self.COLORS.get(overall_risk, colors.black)),
            ('FONTNAME', (1, -1), (1, -1), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.5*inch))
        
        # Executive Summary
        story.append(Paragraph("EXECUTIVE SUMMARY", self.styles['SectionHeader']))
        
        total_evidence = sum(r.get('evidence_count', 0) for r in results)
        high_risk_files = [r['filename'] for r in results if r.get('risk_level') in ['high', 'critical']]
        
        summary_text = f"""
        This report contains the analysis of {len(results)} file(s) for forensic evidence.
        A total of <b>{total_evidence}</b> evidence items were detected.
        """
        
        if high_risk_files:
            summary_text += f"""<br/><br/>
            <b>⚠️ HIGH RISK FILES REQUIRING IMMEDIATE ATTENTION:</b><br/>
            {', '.join(high_risk_files)}
            """
        
        story.append(Paragraph(summary_text, self.styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Risk Summary Table
        story.append(Paragraph("RISK BREAKDOWN", self.styles['SectionHeader']))
        
        risk_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for result in results:
            for e in result.get('evidence', []):
                risk = e.get('risk_level', 'low')
                risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        risk_data = [['Risk Level', 'Count']]
        for risk, count in risk_counts.items():
            if count > 0:
                risk_data.append([risk.upper(), str(count)])
        
        if len(risk_data) > 1:
            risk_table = Table(risk_data, colWidths=[5*cm, 3*cm])
            risk_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['header']),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('BACKGROUND', (0, 1), (-1, -1), colors.Color(0.95, 0.95, 0.95)),
            ]))
            story.append(risk_table)
        
        story.append(PageBreak())
        
        # Detailed File Analysis
        story.append(Paragraph("DETAILED FILE ANALYSIS", self.styles['SectionHeader']))
        
        for result in results:
            filename = result.get('filename', 'Unknown')
            risk_level = result.get('risk_level', 'unknown')
            evidence_list = result.get('evidence', [])
            
            # File header
            risk_color = self.COLORS.get(risk_level, colors.grey)
            file_header = f"📄 {filename} - Risk: {risk_level.upper()}"
            
            file_style = ParagraphStyle(
                'FileHeaderDynamic',
                parent=self.styles['FileHeader'],
                textColor=risk_color
            )
            story.append(Paragraph(file_header, file_style))
            
            if result.get('status') == 'error':
                story.append(Paragraph(f"Error: {result.get('error', 'Unknown error')}", self.styles['Normal']))
                story.append(Spacer(1, 0.2*inch))
                continue
            
            if not evidence_list:
                story.append(Paragraph("No suspicious evidence detected.", self.styles['Normal']))
                story.append(Spacer(1, 0.2*inch))
                continue
            
            # Evidence table
            table_data = [['Type', 'Value', 'Risk', 'Category']]
            for e in evidence_list[:20]:  # Limit to 20 items per file
                table_data.append([
                    e.get('type', ''),
                    e.get('value', '')[:40] + ('...' if len(e.get('value', '')) > 40 else ''),
                    e.get('risk_level', '').upper(),
                    e.get('category', '')
                ])
            
            evidence_table = Table(table_data, colWidths=[2.5*cm, 8*cm, 2*cm, 3.5*cm])
            evidence_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['subheader']),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BACKGROUND', (0, 1), (-1, -1), colors.Color(0.97, 0.97, 0.97)),
            ]))
            
            story.append(evidence_table)
            story.append(Spacer(1, 0.3*inch))
        
        # Footer
        story.append(Spacer(1, 0.5*inch))
        story.append(Paragraph(
            "— End of Report —",
            ParagraphStyle('Footer', parent=self.styles['Normal'], alignment=1, textColor=colors.grey)
        ))
        
        # Build PDF
        doc.build(story)
        return output_path
    
    def _calculate_overall_risk(self, results: list) -> str:
        """Calculate overall risk from all results."""
        for result in results:
            if result.get('risk_level') == 'critical':
                return 'critical'
        
        high_count = sum(1 for r in results if r.get('risk_level') == 'high')
        if high_count > 0:
            return 'high'
        
        medium_count = sum(1 for r in results if r.get('risk_level') == 'medium')
        if medium_count > 0:
            return 'medium'
        
        return 'low'
