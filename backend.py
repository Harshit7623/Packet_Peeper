from flask import Flask, jsonify
import threading
from packet_sniffer import start_sniffing, captured_packets

app = Flask(__name__)

@app.route('/start_sniff', methods=['GET'])
def start_sniff():
    thread = threading.Thread(target=start_sniffing, args=("Wi-Fi",), daemon=True)
    thread.start()
    return jsonify({"message": "Packet sniffing started!"})

@app.route('/get_packets', methods=['GET'])
def get_packets():
    return jsonify(captured_packets)

if __name__ == '__main__':
    app.run(debug=True)
