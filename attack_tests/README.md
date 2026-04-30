# Network Attack Simulation Toolkit

## ⚠️ WARNING
**These scripts are for EDUCATIONAL and TESTING purposes only!**
**Only use on networks you own or have explicit permission to test.**
**Unauthorized use is ILLEGAL and may result in criminal prosecution.**

## ⚠️ IMPORTANT: Target Selection
**DO NOT use 127.0.0.1 (localhost)!** Loopback traffic doesn't go through your network interface and won't be captured by PacketPeeper.

### Correct Targets:
- **Your router:** `192.168.1.1` (or your gateway IP)
- **Another device on your LAN:** Your phone's IP, another computer, etc.
- **Your own machine's LAN IP:** e.g., `192.168.1.100` (NOT 127.0.0.1)

To find your gateway IP:
```powershell
# Windows
ipconfig | findstr "Default Gateway"

# Linux/Mac
ip route | grep default
```

## Overview
This toolkit simulates various network attacks to test your PacketPeeper detection capabilities.

## Attack Categories

### 1. Reconnaissance Attacks
- Port Scanning (SYN, FIN, XMAS, NULL scans)
- Network Discovery
- OS Fingerprinting

### 2. Denial of Service (DoS)
- SYN Flood
- UDP Flood
- ICMP Flood
- Slowloris (HTTP slow attack)
- LAND Attack

### 3. Spoofing Attacks
- ARP Spoofing/Poisoning
- DNS Spoofing
- IP Spoofing

### 4. Application Layer Attacks
- SQL Injection patterns
- XSS payloads
- HTTP smuggling
- Brute Force simulation

### 5. Advanced Attacks
- Man-in-the-Middle simulation
- Session Hijacking patterns
- Covert Channel detection

## Requirements
```bash
pip install scapy requests
```

## Usage
```bash
# IMPORTANT: Replace with your router/gateway IP or another device on your LAN!
# DO NOT use 127.0.0.1 - loopback traffic is not captured!

# Run all tests against your router
python run_all_attacks.py --target 192.168.1.1

# Run specific attack against your router
python port_scanner.py --target 192.168.1.1 --type syn
python dos_attacks.py --target 192.168.1.1 --type synflood --duration 10
python application_attacks.py --target 192.168.1.1 --type all
```

## Detection Expected
Your PacketPeeper should detect:
- [HIGH] Port scan detection
- [CRITICAL] DDoS/Flood attacks
- [HIGH] ARP spoofing attempts
- [MEDIUM] Suspicious HTTP payloads
- [HIGH] Brute force patterns
