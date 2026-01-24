# 📜 Development History

> This document explains the development timeline and repository migration.

## ⚠️ Why No Commit History?

This repository was **migrated** from a local development environment on **January 25, 2026**. During migration, the git history was consolidated into a single commit to:

- Remove references to an accidentally cloned external repository
- Clean up the folder structure and remove unnecessary files
- Start fresh with a properly organized repository

**This is NOT copied code.** Below is a detailed breakdown of the development process.

---

## 🗓️ Development Timeline

### Phase 1: Core Infrastructure (Week 1-2)
- Set up Flask backend with Socket.IO for real-time communication
- Implemented Scapy-based packet capture engine (`packet_sniffer.py` - 941 lines)
- Created basic React frontend with Vite + TypeScript
- Established WebSocket communication between frontend and backend
- Built database layer with SQLite support (`database_services.py` - 429 lines)

### Phase 2: Threat Detection Engine (Week 3-4)
- Built `NetworkSecurityMonitor` class (`network_security_monitor.py` - 945 lines)
- Implemented detection for **16 attack types**:
  - **Port Scanning**: SYN, FIN, XMAS, NULL, ACK scan detection
  - **DoS/DDoS Floods**: SYN flood, UDP flood, ICMP flood
  - **Brute Force**: SSH, FTP, RDP login attempt detection
  - **Application Layer**: SQL injection, XSS, command injection, path traversal
  - **Network Layer**: ARP spoofing, IP spoofing, LAND attack
  - **Advanced Threats**: DNS tunneling, C2 beacons, covert channels
- Created attack simulation test suite with **10/10 passing tests**
- Implemented rate limiting and alert cooldown to prevent alert spam

### Phase 3: AI Integration (Week 5)
- Developed `ai_assistant.py` (792 lines)
- Implemented multi-provider support:
  - OpenAI GPT-4 for best quality
  - Anthropic Claude as alternative
  - Local Ollama for privacy-focused users
  - Built-in fallback for offline operation
- Created **16 attack-specific remediation responses** with:
  - Plain-English explanations
  - Step-by-step remediation guides
  - Risk assessment
  - Prevention tips
- Integrated AI help button into alert system with portal rendering

### Phase 4: Frontend Development (Week 6)
- Built **10 dashboard pages** with React 19:
  - Dashboard (main overview)
  - Packet Monitor (real-time capture)
  - Alerts (threat notifications)
  - Network (device discovery)
  - Traffic (application classification)
  - Analytics (historical data)
  - System (resource usage)
  - Logs (event history)
  - Settings (configuration)
- Created **55+ UI components** using shadcn/ui
- Implemented real-time charts with Recharts
- Built Zustand store for state management (`monitorStore.ts`)
- Added traffic classification with DNS/TLS SNI parsing

### Phase 5: Desktop App & Polish (Week 7)
- Created Electron wrapper (`desktop/electron/`)
- Implemented system tray integration
- Set up NSIS Windows installer configuration
- Fixed various bugs:
  - Device packet count NaN issue (camelCase to snake_case fix)
  - AI assistant infinite loop
  - Alert spam with rate limiting
  - Z-index issues with AI modal

---

## 📊 Code Metrics

| Component | Lines of Code | Files |
|-----------|---------------|-------|
| Backend Core (`app.py`, `packet_sniffer.py`, `network_security_monitor.py`) | ~2,900 | 3 |
| Services (`ai_assistant.py`, `database_services.py`, etc.) | ~1,400 | 4 |
| Frontend (React/TypeScript) | ~8,000 | 65+ |
| Attack Test Suite | ~2,000 | 8 |
| Desktop App (Electron) | ~500 | 4 |
| Configuration & Scripts | ~500 | 10+ |
| **Total** | **~15,000+** | **95+** |

---

## 🔍 Proof of Original Work

### Unique Implementation Details

1. **Custom Detection Thresholds**: Tuned specifically for home networks, not enterprise defaults
   - Port scan: 5 unique ports in 60 seconds
   - SYN flood: 20 packets/second
   - Brute force: 5 failed attempts

2. **AI Fallback System**: 16 pre-written responses that work completely offline without any API keys

3. **Smart Rate Limiting**: Custom alert throttling
   - Maximum 3 alerts per attack type
   - 60-second cooldown between same alert types
   - Prevents alert fatigue for users

4. **Traffic Classification**: DNS + TLS SNI parsing for identifying applications (Netflix, YouTube, WhatsApp, etc.)

5. **Device Discovery**: Automatic detection and tracking of all devices on the network with packet counts

### Technologies Learned & Applied

- **Scapy**: Raw packet capture and manipulation
- **Flask-SocketIO**: Real-time bidirectional WebSocket communication
- **React 19**: Latest React features and patterns
- **Zustand**: Lightweight state management
- **Tailwind CSS v4**: Modern utility-first CSS
- **Electron**: Desktop application packaging
- **Multi-provider LLM Integration**: OpenAI, Claude, Ollama APIs

### Problem-Solving Examples

1. **Alert Spam Issue**: Users were getting flooded with alerts during attacks. Implemented per-attack-type rate limiting with cooldowns.

2. **AI Modal Z-Index**: AI assistant was appearing behind other elements. Fixed with React Portal rendering.

3. **Device NaN Bug**: Device packet counts showed "NaN". Root cause was camelCase/snake_case mismatch between Python backend and TypeScript frontend.

4. **Infinite Loop**: AI assistant was causing page reloads. Fixed event handling and state management.

---

## 📂 Key Files I Wrote

| File | Purpose | Complexity |
|------|---------|------------|
| `backend/network_security_monitor.py` | 16 attack detection algorithms | High |
| `backend/services/ai_assistant.py` | Multi-provider AI with fallbacks | High |
| `backend/packet_sniffer.py` | Scapy packet capture engine | High |
| `backend/app.py` | Flask + Socket.IO backend | Medium |
| `frontend/src/store/monitorStore.ts` | Zustand state management | Medium |
| `frontend/src/components/AIAssistant.tsx` | AI help UI component | Medium |
| `attack_tests/run_all_attacks.py` | Test suite for detection | Medium |

---

## 🎯 What This Project Demonstrates

- **Network Security Knowledge**: Understanding of attack vectors, detection methods, and mitigation
- **Full-Stack Development**: Python backend + React frontend + Desktop app
- **Real-Time Systems**: WebSocket communication, live data streaming
- **AI/LLM Integration**: Multi-provider support with graceful fallbacks
- **Software Engineering**: Clean architecture, error handling, testing
- **User Experience**: Making complex security data understandable for non-technical users

---

## 📬 Contact

If you have questions about the development process or want to discuss technical details:

- **GitHub**: [@Harshit7623](https://github.com/Harshit7623)

I'm happy to walk through any part of the codebase, explain design decisions, or demonstrate the application live!

---

<p align="center">
<i>This project represents genuine learning and development work.</i><br>
<b>Feel free to verify by reviewing the code quality and architecture.</b>
</p>
