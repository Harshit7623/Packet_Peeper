# Network Attack Simulation Toolkit

## ⚠️ WARNING
**These scripts are for EDUCATIONAL and TESTING purposes only!**
**Only use on networks you own or have explicit permission to test.**
**Unauthorized use is ILLEGAL and may result in criminal prosecution.**

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
# Run all tests
python run_all_attacks.py --target 127.0.0.1

# Run specific attack
python port_scanner.py --target 127.0.0.1 --type syn
python dos_attacks.py --target 127.0.0.1 --type synflood --duration 10
python spoofing_attacks.py --target 127.0.0.1 --type arp
```

## Detection Expected
Your PacketPeeper should detect:
- [HIGH] Port scan detection
- [CRITICAL] DDoS/Flood attacks
- [HIGH] ARP spoofing attempts
- [MEDIUM] Suspicious HTTP payloads
- [HIGH] Brute force patterns
