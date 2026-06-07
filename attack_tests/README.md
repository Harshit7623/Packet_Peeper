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
*(Last Updated: June 2026, v1.0.0)*

This toolkit simulates various network attacks to test your PacketPeeper detection capabilities.

### ⚠️ Prerequisite
**The Packet Peeper Backend MUST be running and actively monitoring the correct network interface before executing these scripts.** Otherwise, the attacks will occur, but no alerts will be generated.

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

# Display help and available arguments for any script
python run_all_attacks.py --help
python port_scanner.py --help

# 1. Run all tests against your router
python run_all_attacks.py --target 192.168.1.1

# 2. Port Scanning
python port_scanner.py --target 192.168.1.1 --type syn

# 3. Denial of Service (DoS)
python dos_attacks.py --target 192.168.1.1 --type synflood --duration 10

# 4. Application Layer Attacks (SQLi, XSS, Brute Force)
python application_attacks.py --target 192.168.1.1 --type all

# 5. Spoofing Attacks
python spoofing_attacks.py --target 192.168.1.1 --type arp

# 6. Advanced Attacks (DNS Tunneling, Beaconing, Exfiltration)
python advanced_attacks.py --target 192.168.1.1 --type all
```

## Detection Expected
Your PacketPeeper should detect and categorize the following alerts based on the active profile:
- `[HIGH] SYN Port Scan Detected` (from `port_scanner.py`)
- `[CRITICAL] SYN Flood Attack Detected` (from `dos_attacks.py`)
- `[CRITICAL] ARP Spoofing Detected` (from `spoofing_attacks.py`)
- `[CRITICAL] SQL Injection Attempt` (from `application_attacks.py`)
- `[HIGH] XSS Attack Attempt` (from `application_attacks.py`)
- `[HIGH] Brute Force Attack Detected` (from `application_attacks.py`)
- `[HIGH] DNS Tunneling Detected` (from `advanced_attacks.py`)
- `[HIGH] Data Exfiltration Detected` (from `advanced_attacks.py`)
- `[HIGH] Session Hijacking Attempt` (from `advanced_attacks.py`)
