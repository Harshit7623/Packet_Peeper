"""
Report Generation Service
Generates PDF and CSV reports from captured packet data and alerts
"""

import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
import io

logger = logging.getLogger(__name__)

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    logger.info("[Report] Matplotlib not available; PDF charts disabled")

# Try importing PDF libraries; gracefully degrade if unavailable
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning("[WARN] ReportLab not available; PDF reports disabled")

from config.config import REPORTS_DIR, REPORT_FORMATS

class ReportGenerator:
    """Generates network analysis reports in multiple formats"""
    
    def __init__(self, output_dir: Path = REPORTS_DIR):
        """
        Initialize report generator.
        
        Args:
            output_dir: Directory to store generated reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"[Report] Generator initialized, output: {self.output_dir}")
    
    def generate_csv_report(self,
                          packets: List[Dict],
                          alerts: List[Dict],
                          filename: Optional[str] = None) -> Optional[Path]:
        """
        Generate CSV report from packets and alerts.
        
        Args:
            packets: List of packet dictionaries
            alerts: List of alert dictionaries
            filename: Optional custom filename
            
        Returns:
            Path to generated CSV file or None on error
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = filename or f"report_packets_{timestamp}.csv"
            filepath = self.output_dir / filename
            
            with open(filepath, 'w', newline='') as csvfile:
                # Write packet data
                if packets:
                    fieldnames = ['timestamp', 'protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 
                                 'length', 'service', 'tcp_flags']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    
                    writer.writeheader()
                    for packet in packets:
                        writer.writerow({k: packet.get(k, '') for k in fieldnames})
                    
                    logger.info(f"[Report] CSV report generated: {filepath}")
            
            return filepath
        
        except Exception as e:
            logger.error(f"[ERROR] Error generating CSV report: {str(e)}")
            return None
    
    def generate_alert_csv_report(self,
                                 alerts: List[Dict],
                                 filename: Optional[str] = None) -> Optional[Path]:
        """
        Generate CSV report specifically for alerts.
        
        Args:
            alerts: List of alert dictionaries
            filename: Optional custom filename
            
        Returns:
            Path to generated CSV file or None on error
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = filename or f"report_alerts_{timestamp}.csv"
            filepath = self.output_dir / filename
            
            with open(filepath, 'w', newline='') as csvfile:
                if alerts:
                    fieldnames = ['timestamp', 'alert_type', 'severity', 'source_ip', 'destination_ip',
                                 'title', 'description']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    
                    writer.writeheader()
                    for alert in alerts:
                        writer.writerow({k: alert.get(k, '') for k in fieldnames})
                    
                    logger.info(f"[Report] Alert CSV report generated: {filepath}")
            
            return filepath
        
        except Exception as e:
            logger.error(f"[ERROR] Error generating alert CSV report: {str(e)}")
            return None
    
    def generate_pdf_report(self,
                          packets: List[Dict],
                          alerts: List[Dict],
                          title: str = "Network Analysis Report",
                          filename: Optional[str] = None) -> Optional[Path]:
        """
        Generate comprehensive PDF report.
        
        Args:
            packets: List of packet dictionaries
            alerts: List of alert dictionaries
            title: Report title
            filename: Optional custom filename
            
        Returns:
            Path to generated PDF file or None on error
        """
        if not REPORTLAB_AVAILABLE:
            logger.warning("[WARN] ReportLab not available; PDF report generation disabled")
            return None
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = filename or f"report_{timestamp}.pdf"
            filepath = self.output_dir / filename

            doc = SimpleDocTemplate(str(filepath), pagesize=letter)
            story = []
            styles = getSampleStyleSheet()

            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1f4788'),
                spaceAfter=30,
                alignment=TA_CENTER,
            )
            story.append(Paragraph(title, title_style))
            story.append(Spacer(1, 0.3 * inch))

            meta_data = [
                ['Report Generated', datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
                ['Total Packets', str(len(packets))],
                ['Total Alerts', str(len(alerts))],
                ['Critical Alerts', str(len([a for a in alerts if a.get('severity') == 'critical']))],
            ]

            meta_table = Table(meta_data, colWidths=[2.5 * inch, 4 * inch])
            meta_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e8f0f8')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            story.append(meta_table)
            story.append(Spacer(1, 0.5 * inch))

            if alerts:
                story.append(Paragraph("Security Alerts Summary", styles['Heading2']))

                severity_counts = {
                    'critical': len([a for a in alerts if a.get('severity') == 'critical']),
                    'high': len([a for a in alerts if a.get('severity') == 'high']),
                    'medium': len([a for a in alerts if a.get('severity') == 'medium']),
                    'low': len([a for a in alerts if a.get('severity') == 'low']),
                }

                severity_data = [['Severity', 'Count']]
                for sev, count in severity_counts.items():
                    severity_data.append([sev.capitalize(), str(count)])

                sev_table = Table(severity_data, colWidths=[2 * inch, 2 * inch])
                sev_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')]),
                ]))
                story.append(sev_table)
                story.append(Spacer(1, 0.3 * inch))

                if MATPLOTLIB_AVAILABLE and any(severity_counts.values()):
                    buf = io.BytesIO()
                    fig, ax = plt.subplots(figsize=(4, 3))
                    labels = [s.capitalize() for s in severity_counts if severity_counts[s] > 0]
                    values = [severity_counts[s] for s in severity_counts if severity_counts[s] > 0]
                    sev_colors = {'Critical': '#dc2626', 'High': '#ea580c', 'Medium': '#ca8a04', 'Low': '#16a34a'}
                    chart_colors = [sev_colors.get(l, '#6b7280') for l in labels]
                    ax.pie(values, labels=labels, colors=chart_colors, autopct='%1.0f%%', startangle=90)
                    ax.set_title('Alert Severity Distribution', fontsize=10)
                    fig.savefig(buf, format='png', dpi=150, bbox_inches='tight')
                    buf.seek(0)
                    plt.close(fig)
                    story.append(Image(buf, width=3.5 * inch, height=2.6 * inch))
                    story.append(Spacer(1, 0.3 * inch))

                story.append(Paragraph("Top Alerts", styles['Heading3']))
                alert_rows = [['Time', 'Type', 'Source IP', 'Severity']]
                for alert in alerts[:10]:
                    alert_rows.append([
                        alert.get('timestamp', '')[:19],
                        alert.get('alert_type', 'Unknown')[:15],
                        alert.get('source_ip', 'N/A'),
                        alert.get('severity', 'Unknown'),
                    ])

                alert_table = Table(alert_rows, colWidths=[1.5 * inch, 1.5 * inch, 1.5 * inch, 1 * inch])
                alert_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')]),
                ]))
                story.append(alert_table)
                story.append(PageBreak())

            if packets:
                story.append(Paragraph("Packet Statistics", styles['Heading2']))

                protocols = {}
                for pkt in packets:
                    proto = pkt.get('protocol', 'Unknown')
                    protocols[proto] = protocols.get(proto, 0) + 1

                proto_data = [['Protocol', 'Count']]
                for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
                    proto_data.append([proto, str(count)])

                proto_table = Table(proto_data, colWidths=[2 * inch, 2 * inch])
                proto_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')]),
                ]))
                story.append(proto_table)

                if MATPLOTLIB_AVAILABLE and protocols:
                    buf = io.BytesIO()
                    fig, ax = plt.subplots(figsize=(4.5, 3))
                    sorted_protos = sorted(protocols.items(), key=lambda x: x[1], reverse=True)[:10]
                    proto_labels = [p[0] for p in sorted_protos]
                    proto_values = [p[1] for p in sorted_protos]
                    ax.bar(proto_labels, proto_values, color='#3b82f6')
                    ax.set_title('Protocol Distribution (Top 10)', fontsize=10)
                    ax.set_ylabel('Packet Count', fontsize=8)
                    ax.tick_params(axis='x', rotation=30, labelsize=7)
                    fig.savefig(buf, format='png', dpi=150, bbox_inches='tight')
                    buf.seek(0)
                    plt.close(fig)
                    story.append(Spacer(1, 0.3 * inch))
                    story.append(Image(buf, width=4 * inch, height=2.6 * inch))

                if MATPLOTLIB_AVAILABLE and packets:
                    bandwidth_by_proto = {}
                    for pkt in packets:
                        proto = pkt.get('protocol', 'Unknown')
                        bandwidth_by_proto[proto] = bandwidth_by_proto.get(proto, 0) + pkt.get('length', 0)
                    if any(bandwidth_by_proto.values()):
                        buf = io.BytesIO()
                        fig, ax = plt.subplots(figsize=(4.5, 3))
                        bw_sorted = sorted(bandwidth_by_proto.items(), key=lambda x: x[1], reverse=True)[:10]
                        bw_labels = [b[0] for b in bw_sorted]
                        bw_values = [b[1] for b in bw_sorted]
                        ax.barh(bw_labels, bw_values, color='#8b5cf6')
                        ax.set_title('Bandwidth by Protocol (Top 10)', fontsize=10)
                        ax.set_xlabel('Total Bytes', fontsize=8)
                        ax.tick_params(axis='y', labelsize=7)
                        fig.savefig(buf, format='png', dpi=150, bbox_inches='tight')
                        buf.seek(0)
                        plt.close(fig)
                        story.append(Spacer(1, 0.3 * inch))
                        story.append(Image(buf, width=4 * inch, height=2.6 * inch))

            doc.build(story)
            logger.info(f"[Report] PDF report generated: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"[ERROR] Error generating PDF report: {str(e)}")
            return None
    
    def generate_json_report(self,
                            packets: List[Dict],
                            alerts: List[Dict],
                            devices: Optional[List[Dict]] = None,
                            filename: Optional[str] = None) -> Optional[Path]:
        """
        Generate comprehensive JSON report.
        
        Args:
            packets: List of packet dictionaries
            alerts: List of alert dictionaries
            devices: Optional list of device dictionaries
            filename: Optional custom filename
            
        Returns:
            Path to generated JSON file or None on error
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = filename or f"report_{timestamp}.json"
            filepath = self.output_dir / filename
            
            report = {
                'metadata': {
                    'generated': datetime.now().isoformat(),
                    'version': '1.0',
                },
                'summary': {
                    'total_packets': len(packets),
                    'total_alerts': len(alerts),
                    'total_devices': len(devices) if devices else 0,
                    'critical_alerts': len([a for a in alerts if a.get('severity') == 'critical']),
                },
                'packets': packets[:1000],  # Limit to first 1000
                'alerts': alerts,
                'devices': devices or [],
            }
            
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            logger.info(f"[Report] JSON report generated: {filepath}")
            return filepath
        
        except Exception as e:
            logger.error(f"[ERROR] Error generating JSON report: {str(e)}")
            return None
    
    def generate_summary_report(self,
                               packets: List[Dict],
                               alerts: List[Dict],
                               devices: Optional[List[Dict]] = None) -> Dict:
        """
        Generate a summary report (dict) without file output.
        Useful for API responses.
        
        Args:
            packets: List of packet dictionaries
            alerts: List of alert dictionaries
            devices: Optional list of device dictionaries
            
        Returns:
            Dictionary containing report summary
        """
        return {
            'generated': datetime.now().isoformat(),
            'summary': {
                'total_packets': len(packets),
                'total_alerts': len(alerts),
                'total_devices': len(devices) if devices else 0,
                'critical_alerts': len([a for a in alerts if a.get('severity') == 'critical']),
                'high_alerts': len([a for a in alerts if a.get('severity') == 'high']),
            },
            'protocols': self._analyze_protocols(packets),
            'services': self._analyze_services(packets),
            'alert_types': self._analyze_alert_types(alerts),
        }
    
    @staticmethod
    def _analyze_protocols(packets: List[Dict]) -> Dict[str, int]:
        """Analyze protocol distribution"""
        protocols = {}
        for pkt in packets:
            proto = pkt.get('protocol', 'Unknown')
            protocols[proto] = protocols.get(proto, 0) + 1
        return protocols
    
    @staticmethod
    def _analyze_services(packets: List[Dict]) -> Dict[str, int]:
        """Analyze service distribution"""
        services = {}
        for pkt in packets:
            svc = pkt.get('service', 'Unknown')
            services[svc] = services.get(svc, 0) + 1
        return services
    
    @staticmethod
    def _analyze_alert_types(alerts: List[Dict]) -> Dict[str, int]:
        """Analyze alert type distribution"""
        types = {}
        for alert in alerts:
            atype = alert.get('alert_type', 'Unknown')
            types[atype] = types.get(atype, 0) + 1
        return types

# ============== SINGLETON INSTANCE ==============
_report_generator = None

def get_report_generator() -> ReportGenerator:
    """Get or create singleton report generator"""
    global _report_generator
    if _report_generator is None:
        _report_generator = ReportGenerator()
    return _report_generator