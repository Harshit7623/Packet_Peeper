from flask import Flask, render_template
from flask_socketio import SocketIO
from flask_cors import CORS
from packet_sniffer import PacketSniffer
import threading
import sys
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

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
    # Send initial statistics
    stats = sniffer.get_statistics()
    socketio.emit('update_statistics', stats)

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

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
    
    # Start Flask application
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)

