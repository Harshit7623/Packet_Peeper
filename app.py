from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from packet_sniffer import PacketSniffer
import threading
import sys
import time
import json
import logging
import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
CORS(app, resources={r"/*": {"origins": "*"}})

# Configure Socket.IO with simpler settings
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='threading',
    logger=True,
    engineio_logger=True
)

sniffer = PacketSniffer()

# Configure logging
log_dir = 'logs'
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

log_file = os.path.join(log_dir, 'network_sniffer.log')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('network_sniffer')

# Store logs in memory for quick access
logs = []
MAX_LOGS = 1000

def add_log(level, source, message):
    """Add a log entry to the buffer and file"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {
        'timestamp': timestamp,
        'level': level,
        'source': source,
        'message': message
    }
    
    # Add to buffer
    logs.append(log_entry)
    if len(logs) > MAX_LOGS:
        logs.pop(0)
    
    # Log to file
    if level == 'info':
        logger.info(f"{source}: {message}")
    elif level == 'warning':
        logger.warning(f"{source}: {message}")
    elif level == 'error':
        logger.error(f"{source}: {message}")
    elif level == 'debug':
        logger.debug(f"{source}: {message}")
    
    # Emit to connected clients
    socketio.emit('new_log', log_entry, namespace='/')

def packet_callback(packet_info):
    try:
        # Emit packet data
        socketio.emit('new_packet', packet_info, namespace='/')
        
        # Get and emit updated statistics
        stats = sniffer.get_statistics()
        socketio.emit('update_statistics', stats, namespace='/')
        
        # Log packet
        add_log('info', 'PacketSniffer', 
                f"Captured {packet_info['protocol']} packet: {packet_info['src_ip']} -> {packet_info['dst_ip']}")
        
        print(f"Emitted packet: {packet_info['protocol']} {packet_info['src_ip']} -> {packet_info['dst_ip']}")
    except Exception as e:
        error_msg = f"Error in packet_callback: {str(e)}"
        print(error_msg)
        add_log('error', 'PacketSniffer', error_msg)

def device_update_loop():
    """Periodically send device updates to clients"""
    while True:
        try:
            devices = sniffer.get_devices()
            socketio.emit('devices_update', {'devices': devices}, namespace='/')
        except Exception as e:
            error_msg = f"Error in device update loop: {str(e)}"
            print(error_msg)
            add_log('error', 'DeviceManager', error_msg)
        time.sleep(1)  # Update every second

@app.route('/')
def index():
    return render_template('index.html')

def start_sniffing(interface):
    try:
        print(f"Setting up packet capture on interface: {interface}")
        sniffer.set_callback(packet_callback)
        print("Starting packet capture...")
        add_log('info', 'System', f"Starting packet capture on interface: {interface}")
        sniffer.start_sniffing(interface)
    except Exception as e:
        error_msg = f"Error in start_sniffing: {str(e)}"
        print(error_msg)
        add_log('error', 'System', error_msg)
        raise

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    add_log('info', 'System', 'New client connected')
    emit('connection_status', {'status': 'connected'}, namespace='/')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')
    add_log('info', 'System', 'Client disconnected')

@socketio.on('get_devices')
def handle_get_devices():
    """Handle request for device list"""
    try:
        devices = sniffer.get_devices()
        emit('devices_update', {'devices': devices}, namespace='/')
    except Exception as e:
        error_msg = f"Error getting devices: {str(e)}"
        print(error_msg)
        add_log('error', 'DeviceManager', error_msg)
        emit('error', {'message': error_msg}, namespace='/')

@socketio.on('start_capture')
def handle_start_capture(data):
    """Handle request to start packet capture"""
    try:
        if sniffer is None:
            interface = data.get('interface', 'eth0')
            sniffer = PacketSniffer(interface)
            sniffing_thread = threading.Thread(target=start_sniffing, args=(interface,))
            sniffing_thread.daemon = True
            sniffing_thread.start()
            add_log('info', 'Capture', f'Started packet capture on interface {interface}')
            emit('capture_status', {'status': 'started', 'interface': interface}, namespace='/')
        else:
            emit('capture_status', {'status': 'already_running'}, namespace='/')
    except Exception as e:
        error_msg = f'Failed to start capture: {str(e)}'
        add_log('error', 'Capture', error_msg)
        emit('capture_status', {'status': 'error', 'message': error_msg}, namespace='/')

@socketio.on('stop_capture')
def handle_stop_capture():
    """Handle request to stop packet capture"""
    try:
        if sniffer:
            sniffer.stop()
            sniffer = None
            add_log('info', 'Capture', 'Stopped packet capture')
            emit('capture_status', {'status': 'stopped'}, namespace='/')
        else:
            emit('capture_status', {'status': 'not_running'}, namespace='/')
    except Exception as e:
        error_msg = f'Failed to stop capture: {str(e)}'
        add_log('error', 'Capture', error_msg)
        emit('capture_status', {'status': 'error', 'message': error_msg}, namespace='/')

@socketio.on('get_logs')
def handle_get_logs():
    print('Sending logs to client')
    emit('logs_list', logs, namespace='/')

@socketio.on('clear_logs')
def handle_clear_logs():
    global logs
    logs = []
    add_log('info', 'System', 'Logs cleared')
    emit('logs_list', logs, namespace='/')

@socketio.on('generate_report')
def handle_generate_report(data):
    """Handle request to generate a report"""
    try:
        # Mock report generation
        report = {
            'id': len(data.get('reports', [])) + 1,
            'startDate': data.get('startDate'),
            'endDate': data.get('endDate'),
            'totalPackets': sniffer.get_statistics()['totalPackets'],
            'totalAlerts': 0,
            'bandwidthUsed': '1.2 GB',
            'topApplications': [
                {'name': 'Web Browsing', 'percentage': 35},
                {'name': 'Video Streaming', 'percentage': 25},
                {'name': 'File Transfer', 'percentage': 20},
                {'name': 'Gaming', 'percentage': 15},
                {'name': 'Other', 'percentage': 5}
            ],
            'alertSummary': [
                {'type': 'High Bandwidth', 'count': 3},
                {'type': 'Latency Spike', 'count': 1}
            ]
        }
        add_log('info', 'ReportGenerator', f"Generated report for period {report['startDate']} to {report['endDate']}")
        emit('report_generated', {'report': report}, namespace='/')
    except Exception as e:
        error_msg = f"Error generating report: {str(e)}"
        print(error_msg)
        add_log('error', 'ReportGenerator', error_msg)
        emit('report_error', {'message': error_msg}, namespace='/')

@socketio.on('get_reports')
def handle_get_reports():
    """Handle request to get reports list"""
    try:
        # Mock reports list
        reports = [
            {
                'id': 1,
                'startDate': '2023-01-01',
                'endDate': '2023-01-07',
                'totalPackets': 12500,
                'totalAlerts': 5
            },
            {
                'id': 2,
                'startDate': '2023-01-08',
                'endDate': '2023-01-14',
                'totalPackets': 18700,
                'totalAlerts': 3
            }
        ]
        emit('reports_list', {'reports': reports}, namespace='/')
    except Exception as e:
        error_msg = f"Error getting reports: {str(e)}"
        print(error_msg)
        add_log('error', 'ReportManager', error_msg)
        emit('error', {'message': error_msg}, namespace='/')

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python app.py <interface>")
        sys.exit(1)

    interface = sys.argv[1]
    print(f"Starting packet sniffing on {interface}...")
    
    # Add initial log
    add_log('info', 'System', f"Starting Network Sniffer application on interface: {interface}")
    
    # Start packet sniffing in a separate thread
    sniffing_thread = threading.Thread(target=start_sniffing, args=(interface,))
    sniffing_thread.daemon = True
    sniffing_thread.start()
    
    # Start device update loop in a separate thread
    threading.Thread(target=device_update_loop, daemon=True).start()
    
    # Start Flask application
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)

