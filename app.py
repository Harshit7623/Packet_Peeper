from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from packet_sniffer import PacketSniffer
import threading
import sys
import time
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', logger=True, engineio_logger=True)

sniffer = PacketSniffer()

def packet_callback(packet_info):
    try:
        # Emit packet data
        socketio.emit('new_packet', packet_info, namespace='/')
        
        # Get and emit updated statistics
        stats = sniffer.get_statistics()
        socketio.emit('update_statistics', stats, namespace='/')
        
        print(f"Emitted packet: {packet_info['protocol']} {packet_info['src_ip']} -> {packet_info['dst_ip']}")
    except Exception as e:
        print(f"Error in packet_callback: {str(e)}")

def device_update_loop():
    """Periodically send device updates to clients"""
    while True:
        try:
            devices = sniffer.get_devices()
            socketio.emit('devices_update', {'devices': devices}, namespace='/')
        except Exception as e:
            print(f"Error in device update loop: {str(e)}")
        time.sleep(1)  # Update every second

@app.route('/')
def index():
    return render_template('index.html')

def start_sniffing(interface):
    try:
        print(f"Setting up packet capture on interface: {interface}")
        sniffer.set_callback(packet_callback)
        print("Starting packet capture...")
        sniffer.start_sniffing(interface)
    except Exception as e:
        print(f"Error in start_sniffing: {str(e)}")
        raise

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    # Send initial statistics and devices data
    stats = sniffer.get_statistics()
    socketio.emit('update_statistics', stats, namespace='/')
    devices = sniffer.get_devices()
    emit('devices_update', {'devices': devices}, namespace='/')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('get_devices')
def handle_get_devices():
    """Handle request for device list"""
    try:
        devices = sniffer.get_devices()
        emit('devices_update', {'devices': devices}, namespace='/')
    except Exception as e:
        emit('error', {'message': str(e)}, namespace='/')

@socketio.on('start_capture')
def handle_start_capture(data):
    """Handle request to start packet capture"""
    try:
        interface = data.get('interface', 'Wi-Fi')
        sniffer.set_callback(packet_callback)
        # Start capture in a separate thread
        threading.Thread(target=sniffer.start_sniffing, args=(interface,)).start()
        emit('capture_started', {'interface': interface}, namespace='/')
    except Exception as e:
        emit('error', {'message': str(e)}, namespace='/')

@socketio.on('stop_capture')
def handle_stop_capture():
    """Handle request to stop packet capture"""
    try:
        # Implement stop capture functionality
        emit('capture_stopped', namespace='/')
    except Exception as e:
        emit('error', {'message': str(e)}, namespace='/')

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
        emit('report_generated', {'report': report}, namespace='/')
    except Exception as e:
        emit('report_error', {'message': str(e)}, namespace='/')

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
        emit('error', {'message': str(e)}, namespace='/')

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python app.py <interface>")
        sys.exit(1)

    interface = sys.argv[1]
    print(f"Starting packet sniffing on {interface}...")
    
    # Start packet sniffing in a separate thread
    sniffing_thread = threading.Thread(target=start_sniffing, args=(interface,))
    sniffing_thread.daemon = True
    sniffing_thread.start()
    
    # Start device update loop in a separate thread
    threading.Thread(target=device_update_loop, daemon=True).start()
    
    # Start Flask application
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)

