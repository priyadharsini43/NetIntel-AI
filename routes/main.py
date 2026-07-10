import os
import uuid
import logging
import hashlib
import time
import pandas as pd
from datetime import datetime
from io import BytesIO
from flask import Blueprint, request, jsonify, current_app, render_template, Response
from werkzeug.utils import secure_filename
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from core.pcap_parser import parse_pcap
from core.database import save_analysis, get_all_history, get_analysis_by_hash
from core.model_service import get_model_instance, get_model_status, retrain_model

logger = logging.getLogger('flask.app')
main_bp = Blueprint('main', __name__)



def allowed_file(filename):
    """Check if the file has a .pcap, .cap, or .pcapng extension."""
    ALLOWED_EXTENSIONS = {'pcap', 'cap', 'pcapng'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def _generate_recommendations(results, anomaly_percentage):
    """
    Feature 3: Generate AI security recommendations based on analysis results.
    """
    recommendations = []
    
    # Protocol distribution
    tcp_count = sum(1 for pkt in results if pkt.get('protocol') == 6)
    udp_count = sum(1 for pkt in results if pkt.get('protocol') == 17)
    icmp_count = sum(1 for pkt in results if pkt.get('protocol') == 1)
    
    total = len(results)
    tcp_pct = (tcp_count / total * 100) if total > 0 else 0
    udp_pct = (udp_count / total * 100) if total > 0 else 0
    icmp_pct = (icmp_count / total * 100) if total > 0 else 0
    
    # High threat level
    if anomaly_percentage > 20:
        recommendations.append({
            "priority": "CRITICAL",
            "title": "Isolate Suspicious Hosts",
            "description": "Immediate network isolation of detected anomalous traffic sources is recommended.",
            "actions": [
                "Identify source IPs of anomalous packets",
                "Implement firewall rules to block traffic from suspicious sources",
                "Enable continuous real-time monitoring on these hosts"
            ]
        })
        recommendations.append({
            "priority": "CRITICAL",
            "title": "Enable Firewall Blocking",
            "description": "Activate aggressive firewall policies to block identified threats.",
            "actions": [
                "Deploy DPI (Deep Packet Inspection) rules",
                "Enable intrusion prevention on network perimeter",
                "Configure automatic alerting for anomalous traffic patterns"
            ]
        })
        recommendations.append({
            "priority": "CRITICAL",
            "title": "Continuous Security Monitoring",
            "description": "Establish 24/7 monitoring for network anomalies.",
            "actions": [
                "Enable SIEM integration",
                "Set up real-time alerting thresholds",
                "Schedule incident response drills"
            ]
        })
    
    # TCP protocol analysis
    if tcp_pct > 50:
        recommendations.append({
            "priority": "HIGH" if anomaly_percentage > 10 else "MEDIUM",
            "title": "Review Firewall TCP Rules",
            "description": "TCP-dominant traffic detected. Review and audit firewall rules.",
            "actions": [
                "Audit TCP port allowlist/blocklist",
                "Inspect connections to non-standard ports (>1024)",
                "Monitor for port scanning activity"
            ]
        })
    
    # UDP protocol analysis
    if udp_pct > 30:
        recommendations.append({
            "priority": "MEDIUM",
            "title": "Monitor UDP Traffic",
            "description": "Significant UDP traffic detected. Check for amplification attacks.",
            "actions": [
                "Monitor for DNS amplification attacks",
                "Check NTP abuse patterns",
                "Verify DHCP configuration security"
            ]
        })
    
    # ICMP protocol analysis
    if icmp_pct > 20:
        recommendations.append({
            "priority": "MEDIUM",
            "title": "Investigate ICMP Activity",
            "description": "High ICMP traffic may indicate ping floods or reconnaissance.",
            "actions": [
                "Check for ICMP flood patterns",
                "Verify network discovery scans are authorized",
                "Consider rate-limiting ICMP at network edge"
            ]
        })
    
    # Low threat
    if anomaly_percentage <= 5:
        recommendations.append({
            "priority": "LOW",
            "title": "Network Status: Healthy",
            "description": "Traffic analysis shows normal network behavior with minimal anomalies.",
            "actions": [
                "Continue regular security monitoring",
                "Maintain current firewall policies",
                "Schedule periodic vulnerability assessments"
            ]
        })
    
    return recommendations

@main_bp.route('/')
def index():
    """Renders the upload homepage."""
    return render_template('index.html')

@main_bp.route('/results')
def results():
    """Renders the results dashboard."""
    return render_template('results.html')

@main_bp.route('/history')
def history():
    """Renders the analysis history."""
    history_data = get_all_history()
    return render_template('history.html', history=history_data)

@main_bp.route('/model')
def model_management():
    """Renders the model management page."""
    status = get_model_status()
    return render_template('model.html', status=status)

@main_bp.route('/model/retrain', methods=['POST'])
def model_retrain():
    """Endpoint to retrain the model."""
    try:
        new_status = retrain_model()
        return jsonify({"message": "Model retrained successfully", "status": new_status}), 200
    except Exception as e:
        logger.error(f"Error retraining model: {e}")
        return jsonify({"error": "Failed to retrain model"}), 500

@main_bp.route('/health')
def health_check():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "service": "NIDS Application"}), 200

@main_bp.route('/upload', methods=['POST'])
def upload_file():
    """
    Endpoint to upload a PCAP file.
    Validates file type, magic bytes, handles duplicates, and sanitizes filename.
    """
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
        
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
        
    if not allowed_file(file.filename):
        return jsonify({"error": "Invalid file type. Only .pcap, .cap, and .pcapng files are allowed."}), 400
        
    try:
        # Read file for validation and hashing
        file_content = file.read()
        file.seek(0)
        
        # Magic bytes check
        magic_bytes = file_content[:4]
        # Standard PCAP (little/big endian) and PCAPNG
        valid_magic_bytes = [b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x0a\x0d\x0d\x0a']
        if magic_bytes not in valid_magic_bytes:
             return jsonify({"error": "Invalid PCAP file signature."}), 400
             
        # Duplicate check via SHA-256
        file_hash = hashlib.sha256(file_content).hexdigest()
        existing_filename = get_analysis_by_hash(file_hash)
        if existing_filename:
             logger.info(f"Duplicate upload detected. Redirecting to existing: {existing_filename}")
             return jsonify({
                 "message": "File already analyzed.",
                 "filename": existing_filename
             }), 200
        
        original_filename = secure_filename(file.filename)
        # Further sanitize: remove any leading dots/slashes
        original_filename = original_filename.lstrip('.\\/')
        if not original_filename:
            original_filename = "upload.pcap"
            
        unique_id = str(uuid.uuid4())[:8]
        filename = f"{unique_id}_{original_filename}"
        
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Auto-purge old files
        retention_hours = current_app.config.get('UPLOAD_RETENTION_HOURS', 24)
        cleanup_old_uploads(current_app.config['UPLOAD_FOLDER'], retention_hours)
        
        logger.info(f"File uploaded successfully: {filename}")
        
        return jsonify({
            "message": "File uploaded successfully",
            "filename": filename
        }), 200
        
    except Exception as e:
        logger.error(f"Error during file upload: {e}")
        return jsonify({"error": f"Failed to upload file: {str(e)}"}), 500

def cleanup_old_uploads(upload_folder, retention_hours):
    """Deletes files older than the retention period."""
    try:
        now = time.time()
        for filename in os.listdir(upload_folder):
            filepath = os.path.join(upload_folder, filename)
            if os.path.isfile(filepath):
                # If older than retention hours
                if os.stat(filepath).st_mtime < now - (retention_hours * 3600):
                    os.remove(filepath)
                    logger.info(f"Purged old upload: {filename}")
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")

def _get_analysis_data(filename):
    """Helper to parse and analyze a PCAP file."""
    safe_filename = secure_filename(filename)
    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], safe_filename)
    
    if not os.path.exists(filepath):
        raise FileNotFoundError("File not found")
        
    packet_data = parse_pcap(filepath)
    if not packet_data:
        raise ValueError("No valid IP packets found in the PCAP file.")
        
    model = get_model_instance()
    results = model.predict(packet_data)
    
    total_packets = len(results)
    anomalous_count = sum(1 for pkt in results if pkt['is_anomalous'])
    normal_count = total_packets - anomalous_count
    
    # Calculate hash for DB storage
    with open(filepath, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
        
    # Feature 2: Threat Level Calculation
    anomaly_percentage = (anomalous_count / total_packets * 100) if total_packets > 0 else 0
    if anomaly_percentage <= 5:
        threat_level = "LOW"
    elif anomaly_percentage <= 20:
        threat_level = "MEDIUM"
    else:
        threat_level = "HIGH"
    
    # Feature 3: AI Security Recommendations
    recommendations = _generate_recommendations(results, anomaly_percentage)
        
    return {
        "summary": {
            "filename": safe_filename,
            "file_hash": file_hash,
            "timestamp": datetime.now().isoformat(),
            "total_packets": total_packets,
            "normal_packets": normal_count,
            "anomalous_packets": anomalous_count,
            "anomaly_percentage": round(anomaly_percentage, 2),
            "threat_level": threat_level
        },
        "recommendations": recommendations,
        "details": results
    }

@main_bp.route('/analyze/<filename>', methods=['GET'])
def analyze_file(filename):
    """
    Endpoint to analyze a previously uploaded PCAP file.
    """
    try:
        logger.info(f"Analyzing file: {filename}")
        data = _get_analysis_data(filename)
        
        # Save analysis to database
        save_analysis(data['summary']['filename'], data['summary']['file_hash'], data['summary']['total_packets'], data['summary']['normal_packets'], data['summary']['anomalous_packets'])
        
        logger.info(f"Analysis complete. Total: {data['summary']['total_packets']}, Anomalous: {data['summary']['anomalous_packets']}")
        return jsonify(data), 200
        
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Unexpected error during analysis: {e}")
        return jsonify({"error": "An internal error occurred during analysis."}), 500

@main_bp.route('/export/json/<filename>', methods=['GET'])
def export_json(filename):
    """Export analysis results as JSON."""
    try:
        data = _get_analysis_data(filename)
        return jsonify(data), 200, {
            'Content-Disposition': f'attachment; filename=NIDS_Report_{filename}.json'
        }
    except Exception as e:
        logger.error(f"Error exporting JSON: {e}")
        return jsonify({"error": "Failed to export JSON"}), 500

@main_bp.route('/export/csv/<filename>', methods=['GET'])
def export_csv(filename):
    """Export analysis results as CSV."""
    try:
        data = _get_analysis_data(filename)
        
        # Flatten data for CSV
        df = pd.DataFrame(data['details'])
        # Add summary info to each row or just return the details? 
        # The prompt says: "Each export must include: filename, timestamp, total packets, normal packets, anomalous packets, and full packet-level details."
        # For CSV, it's best to add summary as columns to the details, or return just details. We'll add them as columns.
        df['report_filename'] = data['summary']['filename']
        df['report_timestamp'] = data['summary']['timestamp']
        df['report_total_packets'] = data['summary']['total_packets']
        df['report_normal_packets'] = data['summary']['normal_packets']
        df['report_anomalous_packets'] = data['summary']['anomalous_packets']
        
        csv_data = df.to_csv(index=False)
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-disposition": f"attachment; filename=NIDS_Report_{filename}.csv"}
        )
    except Exception as e:
        logger.error(f"Error exporting CSV: {e}")
        return jsonify({"error": "Failed to export CSV"}), 500

@main_bp.route('/export/pdf/<filename>', methods=['GET'])
def export_pdf(filename):
    """
    Feature 4: Export analysis results as professional PDF report.
    Includes filename, timestamp, threat level, risk score, packet summary,
    protocol distribution, AI recommendations, and packet table.
    """
    try:
        data = _get_analysis_data(filename)
        summary = data['summary']
        details = data['details']
        recommendations = data.get('recommendations', [])
        
        # Create PDF in memory
        pdf_buffer = BytesIO()
        doc = SimpleDocTemplate(pdf_buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
        
        # Define custom styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1e40af'),
            spaceAfter=12,
            fontName='Helvetica-Bold'
        )
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#0f172a'),
            spaceAfter=10,
            fontName='Helvetica-Bold'
        )
        
        # Build PDF elements
        elements = []
        
        # Title Section
        elements.append(Paragraph("Net Intel AI - Security Analysis Report", title_style))
        elements.append(Spacer(1, 0.15*inch))
        
        # Summary Section
        summary_data = [
            ['Metric', 'Value'],
            ['Filename', f"{summary['filename'][:50]}..."],
            ['Timestamp', summary['timestamp']],
            ['Threat Level', f"<b>{summary['threat_level']}</b>"],
            ['Anomaly Score', f"{summary['anomaly_percentage']}%"],
        ]
        summary_table = Table(summary_data, colWidths=[2*inch, 3.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3b82f6')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e5e7eb')),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f3f4f6')])
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 0.25*inch))
        
        # Packet Statistics
        elements.append(Paragraph("Packet Analysis Summary", heading_style))
        stats_data = [
            ['Statistic', 'Count'],
            ['Total Packets', str(summary['total_packets'])],
            ['Normal Packets', str(summary['normal_packets'])],
            ['Anomalous Packets', str(summary['anomalous_packets'])],
        ]
        stats_table = Table(stats_data, colWidths=[3*inch, 2.5*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#10b981')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e5e7eb')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0fdf4')])
        ]))
        elements.append(stats_table)
        elements.append(Spacer(1, 0.25*inch))
        
        # Protocol Distribution
        elements.append(Paragraph("Protocol Distribution", heading_style))
        tcp_count = sum(1 for pkt in details if pkt.get('protocol') == 6)
        udp_count = sum(1 for pkt in details if pkt.get('protocol') == 17)
        icmp_count = sum(1 for pkt in details if pkt.get('protocol') == 1)
        
        proto_data = [
            ['Protocol', 'Count', 'Percentage'],
            ['TCP', str(tcp_count), f"{(tcp_count/summary['total_packets']*100):.1f}%" if summary['total_packets'] > 0 else "0%"],
            ['UDP', str(udp_count), f"{(udp_count/summary['total_packets']*100):.1f}%" if summary['total_packets'] > 0 else "0%"],
            ['ICMP', str(icmp_count), f"{(icmp_count/summary['total_packets']*100):.1f}%" if summary['total_packets'] > 0 else "0%"],
        ]
        proto_table = Table(proto_data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
        proto_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#6366f1')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e5e7eb')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f4f3ff')])
        ]))
        elements.append(proto_table)
        elements.append(Spacer(1, 0.25*inch))
        
        # AI Recommendations Section
        if recommendations:
            elements.append(PageBreak())
            elements.append(Paragraph("Security Recommendations", heading_style))
            
            for idx, rec in enumerate(recommendations, 1):
                priority_color = {
                    'CRITICAL': colors.HexColor('#dc2626'),
                    'HIGH': colors.HexColor('#f97316'),
                    'MEDIUM': colors.HexColor('#eab308'),
                    'LOW': colors.HexColor('#22c55e')
                }.get(rec.get('priority', 'MEDIUM'), colors.gray)
                
                rec_heading = ParagraphStyle(
                    'RecHeading',
                    parent=styles['Heading3'],
                    fontSize=11,
                    textColor=priority_color,
                    fontName='Helvetica-Bold'
                )
                
                elements.append(Paragraph(f"{idx}. {rec['title']} ({rec.get('priority', 'MEDIUM')})", rec_heading))
                elements.append(Paragraph(f"<i>{rec['description']}</i>", styles['Normal']))
                
                # Action items
                for action in rec.get('actions', []):
                    elements.append(Paragraph(f"• {action}", styles['Normal']))
                
                elements.append(Spacer(1, 0.1*inch))
        
        # Detailed Packet Table (sample - first 20 packets)
        elements.append(PageBreak())
        elements.append(Paragraph("Detailed Packet Sample (First 20 Packets)", heading_style))
        
        pkt_table_data = [['ID', 'Src IP', 'Dst IP', 'Proto', 'Status', 'Confidence']]
        for pkt in details[:20]:
            status = "Anomalous" if pkt['is_anomalous'] else "Normal"
            pkt_table_data.append([
                str(pkt['packet_id']),
                pkt['src_ip'][:15],
                pkt['dst_ip'][:15],
                'TCP' if pkt['protocol'] == 6 else 'UDP' if pkt['protocol'] == 17 else 'ICMP',
                status,
                f"{pkt['confidence']:.1f}%"
            ])
        
        pkt_table = Table(pkt_table_data, colWidths=[0.8*inch, 1.2*inch, 1.2*inch, 0.8*inch, 1*inch, 1*inch])
        pkt_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#ef4444')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fef2f2')])
        ]))
        elements.append(pkt_table)
        elements.append(Spacer(1, 0.25*inch))
        
        # Footer
        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=8,
            textColor=colors.grey,
            alignment=TA_CENTER
        )
        elements.append(Paragraph(f"Generated by Net Intel AI • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", footer_style))
        
        # Build PDF
        doc.build(elements)
        pdf_buffer.seek(0)
        
        return Response(
            pdf_buffer,
            mimetype="application/pdf",
            headers={"Content-disposition": f"attachment; filename=NIDS_Report_{filename}.pdf"}
        )
    except Exception as e:
        logger.error(f"Error exporting PDF: {e}")
        return jsonify({"error": f"Failed to export PDF: {str(e)}"}), 500
