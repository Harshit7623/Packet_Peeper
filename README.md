# Packet Peeper - Advanced Network Security Monitor

Packet Peeper is a comprehensive network security monitoring and packet analysis platform that provides real-time monitoring of network traffic, advanced threat detection, and device tracking. It combines powerful packet capture capabilities with intelligent security analysis and a beautiful, intuitive web interface.

## Features

### Core Packet Capture & Analysis
- **Real-time Packet Capture**: Monitor network traffic in real-time with detailed packet information
- **Protocol Analysis**: Automatically categorize packets by protocol (TCP, UDP, ICMP, HTTP, HTTPS, DNS)
- **Service Classification**: Identify services like WhatsApp, YouTube, Facebook, Instagram, Netflix, Telegram, Zoom, AWS, Cloudflare
- **DNS-based Classification**: Passive DNS query/response analysis for service identification
- **TLS SNI Parsing**: Extract hostnames from HTTPS connections for better classification
- **IP Range Matching**: Match traffic against known service IP ranges

### Network Security & Threat Detection
- **Real-time Security Monitoring**: Analyze packets for potential security threats
- **Attack Detection**:
  - Port Scan Detection: Identify suspicious port scanning attempts
  - DDoS Attack Detection: Detect distributed denial of service attacks
  - Brute Force Detection: Monitor for brute force login attempts on SSH, RDP, Telnet
  - DNS Tunneling Detection: Identify DNS-based data exfiltration attempts
- **Security Alerts**: Real-time notifications for detected threats with severity levels (Low, Medium, High, Critical)
- **Alert Cooldown Management**: Prevent alert spam with configurable cooldown periods
- **Detailed Evidence**: Comprehensive evidence collection for each detected threat

### Device & Network Management
- **Active Device Detection**: Real-time discovery and tracking of devices on the network
- **Device Information**: 
  - IP Address detection
  - MAC Address resolution
  - Device manufacturer identification using OUI (MAC address prefix lookup)
  - Hostname resolution
  - Device type classification
- **Device Traffic Monitoring**: Track incoming/outgoing packets and bytes per device
- **Network Interface Detection**: Automatic detection of network interfaces and CIDR calculation
- **Device Statistics**: Real-time packet and byte counters per device

### Traffic Analysis & Monitoring
- **Network Statistics**: Comprehensive bandwidth and traffic analysis
  - Current bandwidth usage
  - Peak bandwidth tracking
  - Average bandwidth calculation
  - Protocol-based traffic breakdown (TCP, UDP, ICMP, HTTP, HTTPS, DNS)
- **Active Connection Monitoring**: Track live connections with source, destination, and port information
- **Top Hosts Analysis**: Identify hosts with most network activity
- **Bandwidth History**: Time-series bandwidth data for trend analysis

### System & Performance Monitoring
- **System Resource Monitoring**:
  - CPU usage tracking
  - Memory usage monitoring
  - Disk space utilization
- **Network Performance Metrics**:
  - Latency measurement
  - Jitter calculation
  - Packet loss percentage tracking

### Web Interface & Visualization
- **Modern React Dashboard**: Clean, responsive UI with multiple views
- **Real-time Updates**: WebSocket-based live updates (200ms refresh rate)
- **Multiple Dashboard Pages**:
  - **Packet Monitor**: Detailed packet capture view
  - **Alerts**: Security alerts with severity indicators
  - **Devices**: Network device discovery and monitoring
  - **Network Traffic**: Real-time traffic analysis and top hosts
  - **Statistics**: System and network performance metrics
  - **Analytics**: Charts and graphs for traffic analysis
  - **Logs**: Application and system logs viewer
  - **Reports**: Network analysis reports generation
  - **Settings**: Application configuration
- **Interactive Charts**: Visual representations of network data using Chart.js
- **Connection Status Indicator**: Real-time WebSocket connection status

## Project Structure

```
NetworkSnifferr/
├── backend/                        # Flask + Socket.IO backend
│   ├── app.py
│   ├── packet_sniffer.py
│   ├── network_security_monitor.py
│   ├── config/
│   ├── services/
│   └── requirements.txt
├── frontend/                       # React + Vite frontend
│   ├── src/
│   ├── package.json
│   └── vite.config.ts
├── attack_tests/                   # Attack simulation toolkit
├── desktop/electron/               # Electron desktop wrapper
├── docker_compose.yml
├── start_backend.sh
├── start_frontend.sh
└── README.md
```

## Prerequisites

- Python 3.8+
- Node.js 14+
- Administrator/root privileges (required for packet capture on Windows/Linux)
- Network interface with packet capture capabilities
- Visual C++ Build Tools (for Windows, if compiling packages from source)

## Installation

### Backend Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/Harshit7623/Packet_Peeper.git
   cd Packet_Peeper
   ```

2. Create and activate a virtual environment:
   ```bash
   # Windows
   python -m venv venv
   venv\Scripts\activate
   
   # Linux/macOS
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install Python dependencies:
   ```bash
   pip install -r backend/requirements.txt
   ```

### Frontend Setup

1. Navigate to the React app directory:
   ```bash
   cd frontend
   ```

2. Install Node.js dependencies:
   ```bash
   npm install
   ```

3. Return to the root directory:
   ```bash
   cd ..
   ```

## Usage

### Starting the Backend

Run the Flask application with the network interface name as an argument:

```bash
# Windows
python backend/app.py auto

# Linux
python backend/app.py auto

# macOS
python backend/app.py auto
```

**Linux note (recommended):** grant packet capture capabilities once so you do not need sudo each run:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip "/path/to/NetworkSnifferr/.venv/bin/python"
"/path/to/NetworkSnifferr/.venv/bin/python" backend/app.py auto
```

If you prefer not to set capabilities, run with sudo using the virtualenv Python:

```bash
sudo "/path/to/NetworkSnifferr/.venv/bin/python" backend/app.py auto
```

To find your network interface names:
```bash
# Windows
python -c "from scapy.all import conf; print(conf.ifaces)"

# Linux/macOS
ip link show
```

The backend will start on `http://localhost:5000` and begin packet capture on the specified interface.

### Starting the Frontend

In a separate terminal, navigate to the frontend directory and start the development server:

```bash
cd frontend
npm run dev
```

The frontend will be available at `http://localhost:5173`.

### Attack Simulation (Testing Only)

To test the security detection capabilities:

```bash
python test_attacks.py
```

This simulates various attacks:
- Port scanning
- DDoS attempts
- Brute force login attempts
- DNS tunneling

**Note**: This is for testing/educational purposes only on networks you own or have permission to test.

## How It Works

### Packet Capture Pipeline
1. **Interface Selection**: User specifies network interface to monitor
2. **Packet Capture**: Scapy captures all packets on the interface using BPF filters
3. **Packet Processing**: Each packet is parsed and analyzed:
   - IP layer extraction (source/destination IPs)
   - Transport layer analysis (TCP, UDP, ICMP)
   - Port information extraction
   - Protocol identification
4. **Service Classification**: Packets are classified using multiple methods:
   - DNS-based classification (passive DNS cache)
   - TLS SNI hostname extraction
   - IP range matching against known service CIDR blocks
   - Port-based fallback classification
5. **Security Analysis**: Each packet is analyzed for threats:
   - Port scan detection (threshold: 5+ unique ports in 60 seconds)
   - DDoS detection (threshold: 100+ packets/second)
   - Brute force detection (threshold: 20+ attempts/minute on SSH/RDP/Telnet)
   - DNS tunneling detection (suspicious patterns in DNS queries)
6. **Device Tracking**: Active devices are discovered and monitored:
   - IP address tracking
   - MAC address resolution
   - Device manufacturer identification
   - Hostname resolution
   - Traffic statistics per device
7. **Real-time Broadcasting**: Data is sent to connected clients via WebSocket
8. **Frontend Display**: React dashboard displays packets, alerts, and statistics in real-time

### Security Detection Engine
The NetworkSecurityMonitor class implements multiple detection algorithms:
- **Stateful Analysis**: Tracks connections and patterns over time
- **Time-windowed Detection**: Uses configurable time windows for pattern analysis
- **Cooldown Management**: Prevents alert spam with per-source cooldown periods
- **Evidence Collection**: Gathers detailed evidence for each alert
- **Severity Classification**: Categorizes threats as Low, Medium, High, or Critical

### WebSocket Communication
- Backend sends updates every 200ms
- Frontend maintains persistent WebSocket connection
- Fallback to polling if WebSocket unavailable
- Automatic reconnection with exponential backoff

## Configuration

### Alert Thresholds (in network_security_monitor.py)
```python
# Port scan detection
threshold: 5 unique ports in 60 seconds

# DDoS detection
threshold: 100+ packets/second

# Brute force detection
threshold: 20+ attempts/minute

# Alert cooldown
Default: 10 seconds (reduced for testing)
```

### BPF Filter (in packet_sniffer.py)
```
(tcp or udp) and not arp and not (udp and (port 67 or 68 or 5353 or 1900 or 123))
```
Filters out noise from DHCP, mDNS, SSDP, NTP

### Service Map
Service classification is based on domains and IP ranges:
- Google, Facebook, WhatsApp, Instagram, Netflix, Microsoft, Telegram, Slack, Zoom, AWS, Cloudflare
- Extensible via service_map.json

## Architecture

### Backend Components

**app.py - Flask WebSocket Server**
- Initializes Flask application with Socket.IO support
- Manages WebSocket connections
- Broadcasts real-time updates to all connected clients
- Implements event handlers for client requests
- Manages alert broadcasting system

**packet_sniffer.py - Packet Capture Engine**
- Scapy-based packet capture on specified interface
- Real-time device discovery and tracking
- Packet classification and service identification
- Statistics aggregation (bandwidth, protocols, etc.)
- TCP stream reassembly for protocol analysis
- Callback system for packet processing

**network_security_monitor.py - Security Analysis Engine**
- Threat detection algorithms
- Packet statistics tracking
- Attack pattern recognition
- Alert generation with cooldown management
- Evidence collection for detected threats

### Frontend Components

**React Dashboard**
- Real-time packet monitoring
- Security alert visualization
- Device network mapping
- Network traffic analysis
- System statistics display
- Interactive reports generation

**Socket.IO Client**
- Maintains persistent connection to backend
- Receives and processes real-time updates
- Automatic reconnection handling
- Fallback to polling mode

## Development

### Backend Development

Key modules and their responsibilities:

- `app.py`: Flask application setup, WebSocket event handlers
- `packet_sniffer.py`: Packet capture, device detection, statistics
- `network_security_monitor.py`: Security analysis and threat detection
- `test_attacks.py`: Attack simulation for testing detection capabilities

To add new features:
1. Extend `PacketSniffer` class for new packet analysis
2. Add detection algorithms to `NetworkSecurityMonitor`
3. Create new WebSocket event handlers in `app.py`

### Frontend Development

The React application uses:
- **React Hooks**: State management with useState, useEffect
- **Socket.IO Client**: Real-time communication
- **Chart.js**: Data visualization
- **React Router**: Navigation between pages

To add new dashboard pages:
1. Create new component in `src/components/`
2. Add route in `App.js`
3. Add navigation link in `sidebar.js`

## Performance Considerations

- **Packet Capture**: Uses BPF filters to reduce kernel→user space data
- **Memory Management**: Circular buffer for captured packets (max 10,000 packets)
- **TCP Stream Assembly**: Automatic cleanup of old streams (5-minute timeout)
- **Device Tracking**: Efficient IP-based dictionary for O(1) lookups
- **Alert Cooldown**: Prevents alert spam while maintaining responsiveness

## Security Considerations

- **Administrator Required**: Packet capture requires elevated privileges
- **Local Network Only**: Device detection limited to configured network range
- **No Encryption**: Use on trusted networks only (WebSocket in development)
- **No Authentication**: Implement authentication for production deployment
- **Service Fingerprinting**: Based on public IP ranges and domain databases

## Troubleshooting

### Common Issues

**1. Permission Error: "No module named 'scapy'"**
```bash
pip install -r backend/requirements.txt
```

**2. Cannot capture packets**
- Ensure you're running with administrator/sudo privileges
- Verify correct network interface name
- Check if interface is active and has IP address

**3. WebSocket connection failed**
- Ensure backend is running on port 5000
- Check firewall settings
- Verify frontend is trying to connect to correct backend URL

**4. No devices detected**
- Wait 30+ seconds for devices to be discovered
- Ensure network has active devices
- Check that device traffic is flowing

**5. No alerts generated**
- Wait for attack simulation to run
- Check that attack traffic is on monitored interface
- Verify alert thresholds in network_security_monitor.py

**6. Low packet capture rate**
- Check interface MTU and packet size
- Verify no other tools are consuming packets
- Reduce BPF filter complexity if needed

## Dependencies

### Backend (Python)
- **scapy** (2.5.0): Network packet capture and analysis
- **flask** (3.0.2): Web framework
- **flask-socketio** (5.3.6): WebSocket support for Flask
- **flask-cors** (4.0.0): CORS headers for cross-origin requests
- **python-socketio** (5.11.1): Socket.IO server implementation
- **python-engineio** (4.8.0): Engine.IO transport layer
- **eventlet** (0.35.2): Async event handling
- **psutil** (5.10.0): System and process monitoring
- **tldextract** (5.1.2): TLD extraction for domain analysis
- **requests** (2.31.0): HTTP requests for device manufacturer lookup
- **pandas** (2.1.4): Data analysis and processing
- **reportlab** (4.1.0): PDF report generation
- **fpdf** (1.7.2): PDF creation utility

### Frontend (Node.js/React)
- **react** (18.2.0): UI framework
- **react-dom** (18.2.0): React DOM rendering
- **react-router-dom** (6.30.0): Client-side routing
- **socket.io-client** (4.7.2): WebSocket client
- **chart.js** (4.4.9): Chart and graph library
- **react-chartjs-2** (5.3.0): React wrapper for Chart.js

## API Endpoints & WebSocket Events

### WebSocket Events (from Backend)
- `connect`: Client connected
- `new_packet`: New packet captured
- `new_alert`: New security alert
- `devices_update`: Device list updated
- `update_statistics`: Statistics updated
- `traffic_update`: Traffic analysis updated
- `new_log`: New log entry

### WebSocket Events (to Backend)
- `get_alerts`: Request alert history
- `get_devices`: Request device list
- `get_logs`: Request logs
- `set_device_filter`: Filter packets by device
- `start_capture`: Start packet capture
- `stop_capture`: Stop packet capture

## Future Enhancements

- [ ] Database persistence (PostgreSQL integration)
- [ ] User authentication and authorization
- [ ] Multi-user support
- [ ] Advanced filtering and search
- [ ] Machine learning-based anomaly detection
- [ ] Mobile app support
- [ ] Cloud deployment support
- [ ] Advanced encryption for WebSocket
- [ ] Historical data analysis
- [ ] Custom alert rules builder
- [ ] Integration with SIEM systems
- [ ] Packet payload inspection (with encryption bypass for testing)
- [ ] Protocol dissection plugins
- [ ] GeoIP-based threat mapping

## Contributing

Contributions are welcome! Please follow these guidelines:
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is intended for educational and authorized security testing purposes only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before conducting security assessments.

## Acknowledgments

- [Scapy](https://scapy.net/) - Network packet manipulation library
- [Flask](https://flask.palletsprojects.com/) - Python web framework
- [React](https://reactjs.org/) - JavaScript UI library
- [Socket.IO](https://socket.io/) - Real-time communication library
- [Chart.js](https://www.chartjs.org/) - JavaScript charting library
- [TLDExtract](https://github.com/john-kurkowski/tldextract) - TLD extraction
- Open source community for inspiration and support

## Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check existing documentation
- Review troubleshooting section

## Author

**Harshit7623** - GitHub: https://github.com/Harshit7623/Packet_Peeper 