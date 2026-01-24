"""
Packet Peeper - Flask Backend Application (Refactored)
Integrates database, async processing, and reporting services
"""

from flask import Flask, render_template, request, jsonify, send_file, send_from_directory
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import threading
import sys
import time
import json
import logging
import logging.handlers
import datetime
import os
from pathlib import Path

# Import config first (before anything else)
from config.config import (
    FLASK_ENV, FLASK_DEBUG, SECRET_KEY, HOST, PORT,
    LOG_LEVEL, LOG_FILE, LOG_FORMAT, LOG_MAX_BYTES, LOG_BACKUP_COUNT,
    SOCKETIO_PING_TIMEOUT, SOCKETIO_PING_INTERVAL, SOCKETIO_TRANSPORTS,
    ALERT_MAX_STORED, FEATURES, ASYNC_PROCESSING
)

# Import services
from services.database_services import get_database_service
from services.packet_processor import init_packet_processor, get_packet_processor
from services.report_generator import get_report_generator
from services.ai_assistant import get_ai_assistant, init_ai_assistant
from packet_sniffer import PacketSniffer
from network_security_monitor import NetworkSecurityMonitor

# ============== FLASK SETUP ==============
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['ENV'] = FLASK_ENV

# CORS configuration: Allow requests from all frontend dev server ports
CORS(app, 
    resources={r"/*": {"origins": "*"}},
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    expose_headers=["Content-Type", "Authorization"]
)

# Allow Socket.IO connections from frontend dev server
socketio_cors_allowed_origins = "*"

# ============== LOGGING SETUP ==============
log_dir = Path(LOG_FILE).parent
log_dir.mkdir(parents=True, exist_ok=True)

# Configure logging with rotation
logger = logging.getLogger('packet_peeper')
logger.setLevel(getattr(logging, LOG_LEVEL))

# File handler with rotation
file_handler = logging.handlers.RotatingFileHandler(
    LOG_FILE,
    maxBytes=LOG_MAX_BYTES,
    backupCount=LOG_BACKUP_COUNT
)
file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
logger.addHandler(file_handler)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
logger.addHandler(console_handler)

# ============== SOCKETIO SETUP ==============
socketio = SocketIO(
    app,
    cors_allowed_origins=socketio_cors_allowed_origins,
    async_mode='threading',
    logger=FLASK_DEBUG,
    engineio_logger=FLASK_DEBUG,
    ping_timeout=SOCKETIO_PING_TIMEOUT,
    ping_interval=SOCKETIO_PING_INTERVAL,
    max_http_buffer_size=1e8,
    allow_upgrades=True,
    http_compression=True,
    transports=SOCKETIO_TRANSPORTS,
    always_connect=True,
)

# ============== GLOBAL STATE ==============
alerts = []
logs = []
sniffer = None
db_service = None
start_time = time.time()  # Application start time

# ============== DATABASE INITIALIZATION ==============
try:
    db_service = get_database_service()
    logger.info("✅ Database service initialized")
except Exception as e:
    logger.warning(f"⚠️  Database initialization failed: {str(e)}")

# ============== PACKET PROCESSOR INITIALIZATION ==============
try:
    packet_processor = init_packet_processor()
    logger.info("✅ Packet processor initialized")
except Exception as e:
    logger.error(f"❌ Packet processor initialization failed: {str(e)}")

# ============== UTILITY FUNCTIONS ==============

def add_log(level: str, source: str, message: str):
    """Add log entry and broadcast to clients"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {
        'timestamp': timestamp,
        'level': level,
        'source': source,
        'message': message
    }
    
    logs.append(log_entry)
    if len(logs) > 1000:
        logs.pop(0)
    
    # Log to file
    log_method = getattr(logger, level.lower(), logger.info)
    log_method(f"[{source}] {message}")
    
    # Broadcast to clients
    socketio.emit('new_log', log_entry, namespace='/')

def broadcast_alert(alert_type: str, message: str, severity: str = 'medium',
                   source: str = 'System', additional_info: dict = None) -> bool:
    """Broadcast alert to all connected clients"""
    try:
        timestamp = datetime.datetime.now().isoformat()
        alert = {
            'id': len(alerts) + 1,
            'type': alert_type,
            'title': message[:50] + '...' if len(message) > 50 else message,
            'description': message,
            'timestamp': timestamp,
            'source': source,
            'severity': severity,
        }
        
        if additional_info:
            alert.update(additional_info)
        
        alerts.insert(0, alert)
        if len(alerts) > ALERT_MAX_STORED:
            alerts.pop()
        
        # Save to database if enabled
        if db_service and FEATURES['persistent_storage']:
            db_service.save_alert(alert)
        
        # Broadcast to clients
        socketio.emit('new_alert', alert, namespace='/')
        logger.info(f"[ALERT] {severity.upper()} - {message}")
        
        return True
    
    except Exception as e:
        logger.error(f"Error broadcasting alert: {str(e)}")
        return False

def security_alert_callback(alert: dict):
    """Callback for security alerts from NetworkSecurityMonitor"""
    global alerts
    try:
        if alert is None:
            return  # Alert was filtered by rate limiter
            
        # Check for duplicate alerts of same type (within last 20)
        alert_type = alert.get('type')
        existing_count = sum(1 for a in alerts[:20] if a.get('type') == alert_type)
        
        # Skip if we already have 3+ of this alert type in recent history
        if existing_count >= 3:
            logger.debug(f"Skipping duplicate alert type: {alert_type} (already {existing_count})")
            return
        
        # Add to alerts list
        alerts.insert(0, alert)
        if len(alerts) > ALERT_MAX_STORED:
            alerts.pop()
        
        # Save to database if enabled
        if db_service and FEATURES['persistent_storage']:
            try:
                db_service.save_alert(alert)
            except Exception as e:
                logger.error(f"Error saving alert to database: {e}")
        
        # Broadcast to all connected clients
        socketio.emit('new_alert', alert, namespace='/')
        
        # Also emit to security-specific channel
        socketio.emit('security_alert', alert, namespace='/')
        
        logger.warning(f"🚨 [{alert.get('severity', 'medium').upper()}] {alert.get('title')}: {alert.get('description')}")
        
    except Exception as e:
        logger.error(f"Error in security alert callback: {e}")

def packet_callback(packet_info: dict):
    """Callback for each processed packet"""
    try:
        # Check if this is a security alert passed through the packet callback
        if packet_info.get('alert_type') == 'security':
            security_alert_callback(packet_info)
            return
        
        # Emit packet via WebSocket
        socketio.emit('new_packet', packet_info, namespace='/')
        
        # Save to database if enabled
        if db_service and FEATURES['persistent_storage']:
            db_service.save_packet(packet_info)
        
        # Get updated statistics
        if sniffer:
            stats = sniffer.get_statistics()
            socketio.emit('update_statistics', stats, namespace='/')
        
        # Log (only for non-debug level to reduce noise)
        if LOG_LEVEL == 'DEBUG':
            add_log('debug', 'PacketSniffer', 
                   f"Captured {packet_info.get('protocol')} packet: "
                   f"{packet_info.get('src_ip')} -> {packet_info.get('dst_ip')}")
    
    except Exception as e:
        logger.error(f"Error in packet callback: {str(e)}")

def device_update_loop():
    """Periodically broadcast device updates"""
    while True:
        try:
            if sniffer:
                devices = sniffer.get_devices()
                active_devices = list(sniffer.active_devices.values())
                
                all_devices = []
                seen_ips = set()
                
                for device in devices:
                    if device.get('ipAddress'):
                        all_devices.append(device)
                        seen_ips.add(device['ipAddress'])
                
                for device in active_devices:
                    if device.get('ipAddress') and device['ipAddress'] not in seen_ips:
                        all_devices.append(device)
                
                socketio.emit('devices_update', {
                    'devices': all_devices,
                    'timestamp': time.time(),
                    'totalDevices': len(all_devices),
                }, namespace='/')
            
            time.sleep(2)
        
        except Exception as e:
            logger.error(f"Error in device update loop: {str(e)}")
            time.sleep(5)

def traffic_update_loop():
    """Periodically broadcast traffic statistics"""
    while True:
        try:
            if sniffer:
                stats = sniffer.get_statistics()
                protocols = {
                    'TCP': stats.get('tcpPackets', 0),
                    'UDP': stats.get('udpPackets', 0),
                    'ICMP': stats.get('icmpPackets', 0),
                }
                
                socketio.emit('traffic_update', {
                    'total_packets': stats.get('totalPackets', 0),
                    'bandwidth': {
                        'current': stats.get('currentBandwidth', 0),
                        'peak': stats.get('peakBandwidth', 0),
                        'average': stats.get('averageBandwidth', 0),
                    },
                    'protocols': protocols,
                }, namespace='/')
            
            time.sleep(1)
        
        except Exception as e:
            logger.error(f"Error in traffic update loop: {str(e)}")
            time.sleep(5)

# ============== FLASK ROUTES ==============

# Handle CORS preflight requests for all API endpoints
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = app.make_default_options_response()
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        return response

@app.after_request
def after_request(response):
    """Add CORS headers to all responses"""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
    return response

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_spa(path):
    """Serve React SPA - serves index.html for all non-API routes"""
    # API routes handled by Flask
    if path.startswith('api/'):
        return jsonify({'error': 'API endpoint not found'}), 404
    
    # Serve static files (JS, CSS, images, etc.)
    if path and ('.' in path or path.startswith('assets/')):
        try:
            return send_from_directory(app.static_folder, path)
        except:
            pass
    
    # Serve index.html for all other routes (SPA routing)
    try:
        return send_from_directory(app.static_folder, 'index.html')
    except:
        return jsonify({'error': 'Frontend not found'}), 404

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get alerts from database or memory"""
    try:
        if db_service and FEATURES['persistent_storage']:
            limit = request.args.get('limit', 100, type=int)
            db_alerts = db_service.get_alerts(limit=limit)
            return jsonify(db_alerts)
        else:
            return jsonify(alerts)
    except Exception as e:
        logger.error(f"Error retrieving alerts: {str(e)}")
        return jsonify(alerts), 200

@app.route('/api/security_alerts', methods=['GET'])
def get_security_alerts():
    """Get security-specific alerts"""
    try:
        security_alert_types = ['port_scan', 'ddos', 'brute_force', 'dns_tunneling']
        
        if db_service and FEATURES['persistent_storage']:
            limit = request.args.get('limit', 100, type=int)
            all_alerts = db_service.get_alerts(limit=limit)
            security_alerts = [a for a in all_alerts if a.get('type') in security_alert_types]
            return jsonify(security_alerts)
        else:
            security_alerts = [a for a in alerts if a.get('type') in security_alert_types]
            return jsonify(security_alerts)
    except Exception as e:
        logger.error(f"Error retrieving security alerts: {str(e)}")
        return jsonify([]), 200

@app.route('/api/packets', methods=['GET'])
def get_packets():
    """Get captured packets"""
    try:
        if db_service and FEATURES['persistent_storage']:
            limit = request.args.get('limit', 1000, type=int)
            db_packets = db_service.get_packets(limit=limit)
            return jsonify(db_packets)
        else:
            limit = request.args.get('limit', 1000, type=int)
            return jsonify(sniffer.captured_packets[-limit:] if sniffer else [])
    except Exception as e:
        logger.error(f"Error retrieving packets: {str(e)}")
        return jsonify([]), 200

@app.route('/api/devices', methods=['GET'])
def get_devices():
    """Get network devices"""
    try:
        if sniffer:
            devices = sniffer.get_devices()
            if db_service and FEATURES['persistent_storage']:
                db_devices = db_service.get_devices()
                return jsonify(db_devices)
            return jsonify(devices)
        return jsonify([])
    except Exception as e:
        logger.error(f"Error retrieving devices: {str(e)}")
        return jsonify([]), 200

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get network statistics"""
    try:
        if sniffer:
            return jsonify(sniffer.get_statistics())
        return jsonify({})
    except Exception as e:
        logger.error(f"Error retrieving stats: {str(e)}")
        return jsonify({}), 200

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Get application logs"""
    try:
        limit = request.args.get('limit', 100, type=int)
        return jsonify(logs[-limit:] if logs else [])
    except Exception as e:
        logger.error(f"Error retrieving logs: {str(e)}")
        return jsonify([]), 200

@app.route('/api/reports', methods=['POST'])
def generate_report():
    """Generate report in requested format"""
    try:
        data = request.get_json()
        report_type = data.get('type', 'json')  # pdf, csv, json
        
        if sniffer and db_service and FEATURES['persistent_storage']:
            packets = db_service.get_packets(limit=10000)
            alerts_list = db_service.get_alerts(limit=1000)
            devices = db_service.get_devices()
            
            generator = get_report_generator()
            
            if report_type == 'pdf':
                filepath = generator.generate_pdf_report(packets, alerts_list)
                if filepath:
                    return send_file(filepath, as_attachment=True,
                                   download_name=f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
            
            elif report_type == 'csv':
                filepath = generator.generate_csv_report(packets, alerts_list)
                if filepath:
                    return send_file(filepath, as_attachment=True,
                                   download_name=f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
            
            elif report_type == 'json':
                filepath = generator.generate_json_report(packets, alerts_list, devices)
                if filepath:
                    return send_file(filepath, as_attachment=True,
                                   download_name=f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        return jsonify({'error': 'Report generation failed'}), 500
    
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============== SNIFFING CONTROL API ==============

sniffing_state = {
    'is_running': False,
    'interface': None,
    'start_time': None,
    'thread': None
}

@app.route('/api/sniffing/start', methods=['POST'])
def api_start_sniffing():
    """Start packet sniffing via API"""
    global sniffer, sniffing_state
    
    try:
        data = request.get_json() or {}
        interface = data.get('interface', 'Wi-Fi')
        
        if sniffing_state['is_running']:
            return jsonify({'message': 'Sniffing already running', 'interface': sniffing_state['interface']}), 200
        
        # Start sniffing in background thread
        sniffing_thread = threading.Thread(
            target=start_sniffing,
            args=(interface,),
            daemon=True,
            name="PacketSnifferThread"
        )
        sniffing_thread.start()
        
        sniffing_state['is_running'] = True
        sniffing_state['interface'] = interface
        sniffing_state['start_time'] = datetime.datetime.now().isoformat()
        sniffing_state['thread'] = sniffing_thread
        
        add_log('info', 'API', f'Sniffing started on interface: {interface}')
        
        return jsonify({
            'message': 'Packet sniffing started',
            'interface': interface,
            'start_time': sniffing_state['start_time']
        })
    
    except Exception as e:
        logger.error(f"Error starting sniffing: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/sniffing/stop', methods=['POST'])
def api_stop_sniffing():
    """Stop packet sniffing via API"""
    global sniffer, sniffing_state
    
    try:
        if sniffer:
            sniffer.stop_sniffing()
            sniffing_state['is_running'] = False
            sniffing_state['interface'] = None
            add_log('info', 'API', 'Sniffing stopped')
            return jsonify({'message': 'Packet sniffing stopped'})
        else:
            return jsonify({'message': 'No active sniffing session'}), 200
    
    except Exception as e:
        logger.error(f"Error stopping sniffing: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/sniffing/status', methods=['GET'])
def api_sniffing_status():
    """Get sniffing status"""
    return jsonify({
        'is_running': sniffing_state['is_running'],
        'interface': sniffing_state['interface'],
        'start_time': sniffing_state['start_time']
    })

@app.route('/api/interfaces', methods=['GET'])
def api_get_interfaces():
    """Get available network interfaces"""
    try:
        import psutil
        interfaces = []
        for iface, addrs in psutil.net_if_addrs().items():
            # Filter out loopback and internal interfaces
            if iface != 'Loopback Pseudo-Interface 1' and not iface.startswith('vEthernet'):
                interface_info = {'name': iface, 'addresses': []}
                for addr in addrs:
                    if addr.family.name == 'AF_INET':
                        interface_info['addresses'].append(addr.address)
                interfaces.append(interface_info)
        return jsonify({'interfaces': interfaces})
    except Exception as e:
        logger.error(f"Error getting interfaces: {str(e)}")
        return jsonify({'interfaces': []}), 200

# ============== NETWORK SCANNING API ==============

@app.route('/api/network/scan', methods=['POST'])
def api_scan_network():
    """Trigger network device scan"""
    try:
        if sniffer:
            # Trigger device discovery
            devices = sniffer.get_devices()
            socketio.emit('devices_update', {'devices': devices}, namespace='/')
            add_log('info', 'API', 'Network scan initiated')
            return jsonify({'message': 'Network scan initiated', 'devices_found': len(devices)})
        return jsonify({'message': 'Sniffer not running'}), 400
    except Exception as e:
        logger.error(f"Error scanning network: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============== ALERTS API ==============

@app.route('/api/alerts/<int:alert_id>/dismiss', methods=['POST'])
def api_dismiss_alert(alert_id):
    """Dismiss a specific alert"""
    global alerts
    try:
        alerts = [a for a in alerts if a.get('id') != alert_id]
        if db_service:
            db_service.dismiss_alert(alert_id)
        return jsonify({'message': f'Alert {alert_id} dismissed'})
    except Exception as e:
        logger.error(f"Error dismissing alert: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/clear', methods=['POST'])
def api_clear_alerts():
    """Clear all alerts and reset security monitor counters"""
    global alerts, security_monitor
    try:
        alerts.clear()
        
        # Reset security monitor counters to prevent continued spam
        if security_monitor:
            security_monitor.reset_counters()
            
        add_log('info', 'API', 'All alerts cleared and security counters reset')
        socketio.emit('alerts_sync', [], namespace='/')
        return jsonify({'message': 'All alerts cleared'})
    except Exception as e:
        logger.error(f"Error clearing alerts: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============== LOGS API ==============

@app.route('/api/logs/clear', methods=['POST'])
def api_clear_logs():
    """Clear all logs"""
    global logs
    try:
        logs.clear()
        add_log('info', 'System', 'Logs cleared via API')
        socketio.emit('logs_list', logs, namespace='/')
        return jsonify({'message': 'Logs cleared'})
    except Exception as e:
        logger.error(f"Error clearing logs: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============== SETTINGS API ==============

app_settings = {
    'auto_blocking': True,
    'real_time_alerts': True,
    'desktop_notifications': True,
    'sound_alerts': False,
    'capture_filter': '',
    'max_packets': 10000,
    'alert_threshold': 5
}

@app.route('/api/settings', methods=['GET'])
def api_get_settings():
    """Get application settings"""
    return jsonify(app_settings)

@app.route('/api/settings', methods=['PUT'])
def api_update_settings():
    """Update application settings"""
    try:
        data = request.get_json()
        for key, value in data.items():
            if key in app_settings:
                app_settings[key] = value
        add_log('info', 'API', 'Settings updated')
        return jsonify({'message': 'Settings updated', 'settings': app_settings})
    except Exception as e:
        logger.error(f"Error updating settings: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============== AI ASSISTANT API ==============

@app.route('/api/ai/remediate', methods=['POST'])
def api_ai_remediate():
    """Get AI-powered remediation advice for an alert"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No alert data provided'}), 400
        
        ai_assistant = get_ai_assistant()
        response = ai_assistant.get_remediation(data)
        
        add_log('info', 'AI', f"Generated remediation for: {data.get('type', 'unknown')}")
        
        return jsonify(response.to_dict())
    
    except Exception as e:
        logger.error(f"Error getting AI remediation: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'explanation': 'Unable to generate AI response. Please try again.',
            'steps': ['Review the alert details manually.'],
            'severity_assessment': 'Unknown',
            'estimated_risk': 'Unable to assess'
        }), 500

@app.route('/api/ai/explain', methods=['POST'])
def api_ai_explain():
    """Get AI explanation for a technical term"""
    try:
        data = request.get_json()
        term = data.get('term', '')
        
        if not term:
            return jsonify({'error': 'No term provided'}), 400
        
        ai_assistant = get_ai_assistant()
        explanation = ai_assistant.explain_term(term)
        
        return jsonify(explanation)
    
    except Exception as e:
        logger.error(f"Error explaining term: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/ai/health-summary', methods=['GET'])
def api_ai_health_summary():
    """Get AI-generated network health summary"""
    try:
        # Gather stats
        critical_count = sum(1 for a in alerts if a.get('severity') == 'critical')
        high_count = sum(1 for a in alerts if a.get('severity') == 'high')
        medium_count = sum(1 for a in alerts if a.get('severity') == 'medium')
        
        stats = {
            'total_alerts': len(alerts),
            'critical_alerts': critical_count,
            'high_alerts': high_count,
            'medium_alerts': medium_count
        }
        
        ai_assistant = get_ai_assistant()
        summary = ai_assistant.get_network_health_summary(stats)
        
        return jsonify(summary)
    
    except Exception as e:
        logger.error(f"Error getting health summary: {str(e)}")
        return jsonify({
            'status': '⚠️ Unknown',
            'message': 'Unable to determine network health status.',
            'action': 'Check your alerts manually.'
        }), 500

@app.route('/api/ai/status', methods=['GET'])
def api_ai_status():
    """Get AI assistant status and configuration"""
    try:
        ai_assistant = get_ai_assistant()
        return jsonify({
            'provider': ai_assistant.provider.value,
            'model': ai_assistant.model,
            'available': True,
            'cache_size': len(ai_assistant.cache)
        })
    except Exception as e:
        return jsonify({
            'provider': 'fallback',
            'available': True,
            'error': str(e)
        })

# ============== SYSTEM INFO API ==============

@app.route('/api/system/info', methods=['GET'])
def api_system_info():
    """Get system information"""
    try:
        import psutil
        import platform
        
        return jsonify({
            'platform': platform.system(),
            'platform_version': platform.version(),
            'python_version': platform.python_version(),
            'cpu_percent': psutil.cpu_percent(),
            'memory': {
                'total': psutil.virtual_memory().total,
                'available': psutil.virtual_memory().available,
                'percent': psutil.virtual_memory().percent
            },
            'disk': {
                'total': psutil.disk_usage('/').total,
                'used': psutil.disk_usage('/').used,
                'percent': psutil.disk_usage('/').percent
            }
        })
    except Exception as e:
        logger.error(f"Error getting system info: {str(e)}")
        return jsonify({}), 200

@app.route('/api/health', methods=['GET'])
def api_health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'uptime': time.time() - start_time if 'start_time' in globals() else 0,
        'version': '2.0.0',
        'sniffing': sniffing_state['is_running'],
        'database': db_service is not None
    })

# ============== ANALYTICS API ==============

@app.route('/api/analytics', methods=['GET'])
def api_analytics():
    """Get analytics data"""
    try:
        time_range = request.args.get('range', '24h')
        
        if sniffer:
            stats = sniffer.get_statistics()
            return jsonify({
                'total_packets': stats.get('totalPackets', 0),
                'protocols': {
                    'TCP': stats.get('tcpPackets', 0),
                    'UDP': stats.get('udpPackets', 0),
                    'ICMP': stats.get('icmpPackets', 0),
                    'Other': stats.get('otherPackets', 0)
                },
                'bandwidth': {
                    'current': stats.get('currentBandwidth', 0),
                    'peak': stats.get('peakBandwidth', 0),
                    'average': stats.get('averageBandwidth', 0)
                },
                'time_range': time_range
            })
        return jsonify({})
    except Exception as e:
        logger.error(f"Error getting analytics: {str(e)}")
        return jsonify({}), 200

@app.route('/api/analytics/protocols', methods=['GET'])
def api_protocol_distribution():
    """Get protocol distribution"""
    try:
        if sniffer:
            stats = sniffer.get_statistics()
            total = stats.get('totalPackets', 1) or 1
            return jsonify({
                'distribution': [
                    {'name': 'TCP', 'value': stats.get('tcpPackets', 0), 'percentage': round(stats.get('tcpPackets', 0) / total * 100, 2)},
                    {'name': 'UDP', 'value': stats.get('udpPackets', 0), 'percentage': round(stats.get('udpPackets', 0) / total * 100, 2)},
                    {'name': 'ICMP', 'value': stats.get('icmpPackets', 0), 'percentage': round(stats.get('icmpPackets', 0) / total * 100, 2)},
                    {'name': 'Other', 'value': stats.get('otherPackets', 0), 'percentage': round(stats.get('otherPackets', 0) / total * 100, 2)},
                ]
            })
        return jsonify({'distribution': []})
    except Exception as e:
        logger.error(f"Error getting protocol distribution: {str(e)}")
        return jsonify({'distribution': []}), 200

@app.route('/api/analytics/top-talkers', methods=['GET'])
def api_top_talkers():
    """Get top talking devices"""
    try:
        limit = request.args.get('limit', 10, type=int)
        if sniffer:
            devices = sniffer.get_devices()
            # Sort by packet count
            sorted_devices = sorted(devices, key=lambda d: d.get('packets_in', 0) + d.get('packets_out', 0), reverse=True)
            return jsonify(sorted_devices[:limit])
        return jsonify([])
    except Exception as e:
        logger.error(f"Error getting top talkers: {str(e)}")
        return jsonify([]), 200

@app.route('/api/analytics/bandwidth', methods=['GET'])
def api_bandwidth_history():
    """Get bandwidth history (placeholder - would need historical data storage)"""
    try:
        hours = request.args.get('hours', 24, type=int)
        # Return current stats as a single data point for now
        if sniffer:
            stats = sniffer.get_statistics()
            return jsonify([{
                'timestamp': datetime.datetime.now().isoformat(),
                'bandwidth': stats.get('currentBandwidth', 0)
            }])
        return jsonify([])
    except Exception as e:
        logger.error(f"Error getting bandwidth history: {str(e)}")
        return jsonify([]), 200

@app.route('/api/traffic/stats', methods=['GET'])
def api_traffic_stats():
    """Get traffic statistics"""
    try:
        if sniffer:
            stats = sniffer.get_statistics()
            return jsonify({
                'total_packets': stats.get('totalPackets', 0),
                'tcp_packets': stats.get('tcpPackets', 0),
                'udp_packets': stats.get('udpPackets', 0),
                'icmp_packets': stats.get('icmpPackets', 0),
                'current_bandwidth': stats.get('currentBandwidth', 0),
                'peak_bandwidth': stats.get('peakBandwidth', 0),
                'average_bandwidth': stats.get('averageBandwidth', 0)
            })
        return jsonify({})
    except Exception as e:
        logger.error(f"Error getting traffic stats: {str(e)}")
        return jsonify({}), 200

# ============== SOCKETIO EVENTS ==============

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    try:
        logger.info("✅ Client connected")
        emit('connection_status', {'status': 'connected'})
        
        if alerts:
            emit('alerts_sync', alerts)
        
        if sniffer:
            emit('update_statistics', sniffer.get_statistics())
    
    except Exception as e:
        logger.error(f"Error in connect handler: {str(e)}")

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info("⛔ Client disconnected")

@socketio.on('get_logs')
def handle_get_logs():
    """Send logs to client"""
    emit('logs_list', logs)

@socketio.on('clear_logs')
def handle_clear_logs():
    """Clear logs"""
    logs.clear()
    add_log('info', 'System', 'Logs cleared')
    emit('logs_list', logs)

@socketio.on('get_processor_stats')
def handle_processor_stats():
    """Get packet processor statistics"""
    processor = get_packet_processor()
    emit('processor_stats', processor.get_stats())

@socketio.on('start_sniffing')
def handle_start_sniffing(data=None):
    """Handle start sniffing request from WebSocket"""
    global sniffer, sniffing_state
    
    try:
        interface = data.get('interface', 'Wi-Fi') if data else 'Wi-Fi'
        
        if sniffing_state.get('is_running'):
            emit('sniffing_status', {'status': 'already_running', 'interface': sniffing_state.get('interface')})
            return
        
        # Start sniffing in background thread
        sniffing_thread = threading.Thread(
            target=start_sniffing,
            args=(interface,),
            daemon=True,
            name="PacketSnifferThread"
        )
        sniffing_thread.start()
        
        sniffing_state['is_running'] = True
        sniffing_state['interface'] = interface
        sniffing_state['start_time'] = datetime.datetime.now().isoformat()
        
        add_log('info', 'WebSocket', f'Sniffing started on interface: {interface}')
        emit('sniffing_status', {'status': 'started', 'interface': interface})
        
    except Exception as e:
        logger.error(f"Error starting sniffing via WebSocket: {str(e)}")
        emit('sniffing_status', {'status': 'error', 'message': str(e)})

@socketio.on('stop_sniffing')
def handle_stop_sniffing():
    """Handle stop sniffing request from WebSocket"""
    global sniffer, sniffing_state
    
    try:
        if sniffer:
            sniffer.stop_sniffing()
            sniffing_state['is_running'] = False
            sniffing_state['interface'] = None
            add_log('info', 'WebSocket', 'Sniffing stopped')
            emit('sniffing_status', {'status': 'stopped'})
        else:
            emit('sniffing_status', {'status': 'not_running'})
    
    except Exception as e:
        logger.error(f"Error stopping sniffing via WebSocket: {str(e)}")
        emit('sniffing_status', {'status': 'error', 'message': str(e)})

@socketio.on('scan_devices')
def handle_scan_devices():
    """Handle device scan request from WebSocket"""
    try:
        if sniffer:
            devices = sniffer.get_devices()
            emit('devices_update', {'devices': devices, 'totalDevices': len(devices)})
            add_log('info', 'WebSocket', f'Device scan complete: {len(devices)} devices found')
        else:
            emit('devices_update', {'devices': [], 'totalDevices': 0, 'error': 'Sniffer not running'})
    except Exception as e:
        logger.error(f"Error scanning devices via WebSocket: {str(e)}")
        emit('devices_update', {'devices': [], 'error': str(e)})

# ============== SNIFFING SETUP ==============

def start_sniffing(interface: str):
    """Start packet sniffing on specified interface"""
    global sniffer
    
    try:
        logger.info(f"🔍 Starting packet capture on interface: {interface}")
        
        sniffer = PacketSniffer()
        sniffer.set_callback(packet_callback)
        
        # Register packet processor callback if async is enabled
        if ASYNC_PROCESSING:
            processor = get_packet_processor()
            processor.register_callback(packet_callback)
            processor.start()
            logger.info("⚙️  Async packet processor started")
        
        add_log('info', 'System', f"Starting packet capture on: {interface}")
        sniffer.start_sniffing(interface)
    
    except Exception as e:
        error_msg = f"Error starting sniffing: {str(e)}"
        logger.error(error_msg)
        add_log('error', 'System', error_msg)

# ============== MAIN ==============

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python app.py <interface>")
        print("Example: python app.py Wi-Fi")
        sys.exit(1)
    
    interface = sys.argv[1]
    logger.info(f"📡 Packet Peeper Backend Starting")
    logger.info(f"📡 Environment: {FLASK_ENV}")
    logger.info(f"📡 Database: {FEATURES['persistent_storage']}")
    logger.info(f"📡 Async Processing: {ASYNC_PROCESSING}")
    
    add_log('info', 'System', "Packet Peeper backend starting")
    
    # Start sniffing in background thread
    sniffing_thread = threading.Thread(
        target=start_sniffing,
        args=(interface,),
        daemon=True,
        name="PacketSnifferThread"
    )
    sniffing_thread.start()
    
    # Start device update thread
    device_thread = threading.Thread(
        target=device_update_loop,
        daemon=True,
        name="DeviceUpdateThread"
    )
    device_thread.start()
    
    # Start traffic update thread
    traffic_thread = threading.Thread(
        target=traffic_update_loop,
        daemon=True,
        name="TrafficUpdateThread"
    )
    traffic_thread.start()
    
    # Start Flask-SocketIO server
    logger.info(f"🚀 Starting Flask server on {HOST}:{PORT}")
    socketio.run(app, host=HOST, port=PORT, debug=FLASK_DEBUG, allow_unsafe_werkzeug=True)