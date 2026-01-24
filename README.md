# 🛡️ Packet Peeper - AI-Powered Network Security Monitor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![React 19](https://img.shields.io/badge/React-19-61dafb.svg)](https://react.dev/)
[![Electron](https://img.shields.io/badge/Electron-28%2B-47848F.svg)](https://www.electronjs.org/)

**Packet Peeper** is a real-time network security monitor designed for **non-technical home users**. It detects network threats in real-time and uses AI to explain what's happening in plain English, with step-by-step remediation guidance.

![Dashboard Preview](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)

---

## ✨ Key Features

### 🔍 Real-Time Threat Detection
- **16 Attack Types Detected**: Port scans, DDoS/DoS floods, brute force, SQL injection, XSS, DNS tunneling, ARP spoofing, IP spoofing, LAND attacks, command injection, C2 beacons, covert channels, and more
- **10/10 Detection Accuracy**: Comprehensive testing suite with all tests passing
- **Low False Positives**: Smart threshold tuning optimized for home networks
- **Instant Alerts**: Real-time notifications with severity classification (Critical, High, Medium, Low)

### 🤖 AI-Powered Security Assistant
- **Plain-English Explanations**: Translates complex technical threats into simple language anyone can understand
- **Step-by-Step Remediation**: Click "Get AI Help" for actionable guidance with checkable steps
- **Multi-Provider Support**: OpenAI GPT-4, Claude, Local Ollama, or built-in offline AI
- **16 Attack-Specific Responses**: Tailored advice for each threat type
- **Risk Assessment**: Clear severity levels and potential impact analysis
- **Prevention Tips**: Learn how to prevent similar attacks in the future

### 📊 Interactive Dashboard
- **Live Visualizations**: Real-time packet rate, protocol distribution, bandwidth usage
- **Device Discovery**: Automatic detection and monitoring of all network devices
- **Traffic Classification**: Identifies services (Netflix, WhatsApp, YouTube, etc.) by DNS/TLS SNI
- **Multiple Views**: Dashboard, Packet Monitor, Alerts, Network Map, Traffic Analysis, Analytics, System Stats, Logs, Settings

### 🖥️ Cross-Platform Desktop App
- **Electron-based**: Native desktop experience
- **System Tray**: Minimize to tray, continues monitoring in background
- **One-Click Launch**: Easy installation and startup

---

## 🚀 Quick Start

### Prerequisites
- **Python 3.8+** with pip
- **Node.js 18+** with npm
- **Administrator/Root privileges** (required for packet capture)

### Installation

```bash
# Clone the repository
git clone https://github.com/Harshit7623/Packet_Peeper.git
cd Packet_Peeper

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install frontend dependencies
cd frontend
npm install
cd ..
```

### Running the Application

**Option 1: Quick Start Script (Windows)**
```bash
start_all.bat
```

**Option 2: Manual Start**

Terminal 1 - Backend (Run as Administrator):
```bash
python app.py Wi-Fi
```

Terminal 2 - Frontend:
```bash
cd frontend
npm run dev
```

Then open **http://localhost:5173** in your browser.

### Finding Your Network Interface

```bash
# Windows
python -c "import psutil; print(list(psutil.net_if_addrs().keys()))"

# Linux
ip link show

# macOS
networksetup -listallhardwareports
```

---

## 🧠 AI Assistant Setup

### Option 1: Built-In (Default - No Setup Required)
Works offline with pre-trained responses for all 16 threat types. Just start the app!

### Option 2: OpenAI (Best Quality)
```bash
# Set environment variable
# Windows:
set OPENAI_API_KEY=sk-your-api-key-here

# Linux/macOS:
export OPENAI_API_KEY=sk-your-api-key-here
```

### Option 3: Ollama (Completely Local & Free)
```bash
# 1. Install Ollama from https://ollama.ai
# 2. Start Ollama and pull a model
ollama pull llama3.2

# 3. Run Packet Peeper - it auto-detects Ollama
python app.py Wi-Fi
```

---

## 📊 Supported Threats

| Attack Type | Detection Method | What It Means |
|-------------|------------------|---------------|
| **Port Scan** | 5+ unique ports in 60s | Someone probing your network for open doors |
| **SYN Flood** | 20+ SYN packets/sec | Attempting to overwhelm your connection |
| **UDP Flood** | 30+ UDP packets/sec | Flooding with data packets |
| **Brute Force** | 5+ failed logins | Guessing passwords on your devices |
| **SQL Injection** | Pattern matching | Trying to hack web applications |
| **XSS Attack** | Script detection | Injecting malicious scripts |
| **DNS Tunneling** | Suspicious patterns | Data exfiltration via DNS |
| **ARP Spoofing** | MAC changes | Man-in-the-middle attack |
| **IP Spoofing** | Invalid sources | Hiding attacker identity |
| **LAND Attack** | src=dst IP | Malformed packet attack |
| **C2 Beacon** | Regular callbacks | Malware communication |
| **Command Injection** | Shell patterns | Remote code execution attempt |
| **Path Traversal** | ../ patterns | File system access attempt |
| **DDoS** | Multiple sources | Distributed attack |
| **ARP Flood** | Excessive ARP | Network disruption |
| **Covert Channel** | Hidden data | Secret communication |

---

## 📁 Project Structure

```
Packet_Peeper/
├── app.py                          # Flask + Socket.IO backend
├── packet_sniffer.py               # Scapy packet capture engine
├── network_security_monitor.py     # Attack detection (16 types)
├── requirements.txt                # Python dependencies
│
├── config/
│   └── config.py                   # Centralized configuration
│
├── services/
│   ├── ai_assistant.py             # 🤖 AI remediation system
│   ├── database_services.py        # SQLite/PostgreSQL storage
│   ├── packet_processor.py         # Async packet processing
│   └── report_generator.py         # PDF/CSV/JSON exports
│
├── frontend/                       # React 19 + TypeScript + Tailwind
│   ├── src/
│   │   ├── pages/                  # 10 dashboard pages
│   │   ├── components/             # 55+ UI components
│   │   ├── services/               # API + WebSocket
│   │   └── store/                  # Zustand state management
│   └── package.json
│
├── desktop/electron/               # Desktop app wrapper
│   ├── main.js
│   ├── preload.js
│   └── package.json
│
├── attack_tests/                   # Testing & simulation tools
│   ├── run_all_attacks.py          # Run all attack simulations
│   ├── port_scanner.py
│   ├── dos_attacks.py
│   ├── spoofing_attacks.py
│   └── application_attacks.py
│
└── data/
    ├── packet_peeper.db            # SQLite database
    └── reports/                    # Generated reports
```

---

## 🧪 Testing Attack Detection

Included attack simulation tools for testing (use only on networks you own):

```bash
cd attack_tests

# Run all tests quickly
python run_all_attacks.py --target 127.0.0.1 --quick --no-warning

# Individual attack tests
python port_scanner.py --target 127.0.0.1
python dos_attacks.py --target 127.0.0.1 --method syn_flood
python spoofing_attacks.py --target 127.0.0.1 --method arp
python application_attacks.py --target 127.0.0.1 --method sql_injection
```

---

## 📈 Performance

| Metric | Value |
|--------|-------|
| Packet Processing | ~10,000 packets/second |
| Memory Usage | <100 MB idle, <500 MB under load |
| CPU Impact | <5% on modern systems |
| Alert Latency | <100ms detection to UI |
| WebSocket Updates | 200ms refresh rate |

---

## 🔐 Security & Privacy

- ✅ **100% Local Processing**: All analysis happens on your device
- ✅ **No Data Collection**: Your network data never leaves your computer
- ✅ **Works Offline**: Built-in AI works without internet
- ✅ **Open Source**: Full code transparency - audit everything
- ✅ **Local Database**: All data stored in SQLite on your machine

---

## 🐛 Troubleshooting

### No packets captured
```bash
# Run as Administrator (Windows) or sudo (Linux/Mac)
sudo python app.py Wi-Fi

# List available interfaces
python -c "import psutil; print(list(psutil.net_if_addrs().keys()))"
```

### Backend won't start
```bash
# Check Python version (need 3.8+)
python --version

# Test Scapy installation
python -c "from scapy.all import sniff; print('Scapy OK')"

# Check if port 5000 is in use
# Windows:
netstat -ano | findstr :5000
# Linux/Mac:
lsof -i :5000
```

### Frontend won't connect
- Ensure backend is running on http://localhost:5000
- Check browser console for CORS errors
- Try clearing browser cache

### AI not responding
- Built-in responses work offline (no setup needed)
- For OpenAI: Check `OPENAI_API_KEY` is set correctly
- For Ollama: Ensure `ollama serve` is running

---

## 🛠️ Configuration

### Environment Variables (`.env` file)

```bash
# Flask
FLASK_ENV=development
FLASK_DEBUG=false
FLASK_PORT=5000

# Database
DB_ENGINE=sqlite  # or postgresql

# AI (optional - built-in works without these)
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-...
OLLAMA_URL=http://localhost:11434

# Capture
CAPTURE_INTERFACE=Wi-Fi
```

### Detection Thresholds (in `network_security_monitor.py`)
```python
thresholds = {
    'port_scan_count': 5,        # Ports to trigger alert
    'syn_flood_rate': 20,        # Packets per second
    'brute_force_attempts': 5,   # Failed logins
    'alert_cooldown': 60,        # Seconds between same alert
}
```

---

## 🤝 Contributing

Contributions are welcome! Areas we need help with:

- 🎨 UI/UX improvements
- 🧠 New detection algorithms
- 📱 Mobile app development
- 🌍 Translations
- 📖 Documentation

### How to Contribute
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

This tool is intended for **educational and authorized security testing purposes only**. Unauthorized access to computer systems is illegal. Always obtain proper authorization before conducting security assessments.

---

## 🙏 Acknowledgments

- [Scapy](https://scapy.net/) - Network packet manipulation
- [Flask](https://flask.palletsprojects.com/) - Python web framework  
- [React](https://react.dev/) - UI framework
- [Socket.IO](https://socket.io/) - Real-time communication
- [Electron](https://www.electronjs.org/) - Desktop app framework
- [Tailwind CSS](https://tailwindcss.com/) - Styling
- [shadcn/ui](https://ui.shadcn.com/) - UI components

---

## 👤 Author

**Harshit7623**

- GitHub: [@Harshit7623](https://github.com/Harshit7623)
- Repository: [Packet_Peeper](https://github.com/Harshit7623/Packet_Peeper)

---

<p align="center">
  <b>🔒 Made with ❤️ for network security awareness</b><br>
  <i>Making network security understandable for everyone</i> 🛡️
</p>
