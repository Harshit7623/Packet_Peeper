#!/usr/bin/env python3
"""
Port Scanner Simulation - Tests detection of various port scanning techniques
For EDUCATIONAL and AUTHORIZED TESTING purposes only!
"""

import argparse
import time
import random
import socket
import struct
import sys
from typing import List, Tuple

# Try to import scapy, provide fallback
try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy not installed. Some features will use raw sockets.")
    print("[!] Install with: pip install scapy")


class PortScanner:
    """Simulates various port scanning techniques for detection testing"""
    
    def __init__(self, target: str, ports: List[int] = None):
        self.target = target
        self.ports = ports or list(range(1, 1025))  # Common ports
        self.delay = 0.01  # Delay between packets (seconds)
        
    def syn_scan(self, port_range: Tuple[int, int] = None) -> None:
        """
        SYN Scan (Half-open scan) - Most common and stealthy
        Sends SYN packets without completing handshake
        Detection: Multiple SYN packets to different ports from same source
        """
        print(f"\n[*] Starting SYN Scan on {self.target}")
        print("[*] This should trigger: PORT_SCAN detection")
        
        ports = range(port_range[0], port_range[1]) if port_range else self.ports
        
        if SCAPY_AVAILABLE:
            for port in ports:
                try:
                    pkt = IP(dst=self.target)/TCP(dport=port, flags="S")
                    send(pkt, verbose=0)
                    print(f"    [SYN] -> {self.target}:{port}")
                    time.sleep(self.delay)
                except Exception as e:
                    print(f"    [!] Error scanning port {port}: {e}")
        else:
            self._raw_syn_scan(ports)
            
        print(f"[+] SYN Scan complete - Scanned {len(list(ports))} ports")
    
    def _raw_syn_scan(self, ports):
        """Fallback SYN scan using raw sockets"""
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    print(f"    [OPEN] {self.target}:{port}")
                sock.close()
                time.sleep(self.delay)
            except:
                pass

    def fin_scan(self, port_range: Tuple[int, int] = None) -> None:
        """
        FIN Scan - Stealthier than SYN
        Sends FIN packets - closed ports respond with RST, open ports don't respond
        Detection: FIN packets without prior connection
        """
        print(f"\n[*] Starting FIN Scan on {self.target}")
        print("[*] This should trigger: STEALTH_SCAN detection")
        
        if not SCAPY_AVAILABLE:
            print("[!] FIN scan requires Scapy")
            return
            
        ports = range(port_range[0], port_range[1]) if port_range else self.ports[:100]
        
        for port in ports:
            try:
                pkt = IP(dst=self.target)/TCP(dport=port, flags="F")
                send(pkt, verbose=0)
                print(f"    [FIN] -> {self.target}:{port}")
                time.sleep(self.delay)
            except Exception as e:
                print(f"    [!] Error: {e}")
                
        print(f"[+] FIN Scan complete")

    def xmas_scan(self, port_range: Tuple[int, int] = None) -> None:
        """
        XMAS Scan - Sets FIN, PSH, URG flags (lit up like a Christmas tree)
        Detection: Unusual TCP flag combinations
        """
        print(f"\n[*] Starting XMAS Scan on {self.target}")
        print("[*] This should trigger: XMAS_SCAN / ANOMALOUS_FLAGS detection")
        
        if not SCAPY_AVAILABLE:
            print("[!] XMAS scan requires Scapy")
            return
            
        ports = range(port_range[0], port_range[1]) if port_range else self.ports[:100]
        
        for port in ports:
            try:
                # FIN + PSH + URG = "FPU"
                pkt = IP(dst=self.target)/TCP(dport=port, flags="FPU")
                send(pkt, verbose=0)
                print(f"    [XMAS] -> {self.target}:{port}")
                time.sleep(self.delay)
            except Exception as e:
                print(f"    [!] Error: {e}")
                
        print(f"[+] XMAS Scan complete")

    def null_scan(self, port_range: Tuple[int, int] = None) -> None:
        """
        NULL Scan - No flags set at all
        Detection: TCP packets with no flags (invalid)
        """
        print(f"\n[*] Starting NULL Scan on {self.target}")
        print("[*] This should trigger: NULL_SCAN / INVALID_TCP detection")
        
        if not SCAPY_AVAILABLE:
            print("[!] NULL scan requires Scapy")
            return
            
        ports = range(port_range[0], port_range[1]) if port_range else self.ports[:100]
        
        for port in ports:
            try:
                pkt = IP(dst=self.target)/TCP(dport=port, flags="")
                send(pkt, verbose=0)
                print(f"    [NULL] -> {self.target}:{port}")
                time.sleep(self.delay)
            except Exception as e:
                print(f"    [!] Error: {e}")
                
        print(f"[+] NULL Scan complete")

    def ack_scan(self, port_range: Tuple[int, int] = None) -> None:
        """
        ACK Scan - Used to map firewall rules
        Detection: ACK packets without prior SYN-ACK
        """
        print(f"\n[*] Starting ACK Scan on {self.target}")
        print("[*] This should trigger: ACK_SCAN / FIREWALL_PROBE detection")
        
        if not SCAPY_AVAILABLE:
            print("[!] ACK scan requires Scapy")
            return
            
        ports = range(port_range[0], port_range[1]) if port_range else self.ports[:100]
        
        for port in ports:
            try:
                pkt = IP(dst=self.target)/TCP(dport=port, flags="A")
                send(pkt, verbose=0)
                print(f"    [ACK] -> {self.target}:{port}")
                time.sleep(self.delay)
            except Exception as e:
                print(f"    [!] Error: {e}")
                
        print(f"[+] ACK Scan complete")

    def udp_scan(self, port_range: Tuple[int, int] = None) -> None:
        """
        UDP Scan - Scans UDP ports
        Detection: Multiple UDP probes to different ports
        """
        print(f"\n[*] Starting UDP Scan on {self.target}")
        print("[*] This should trigger: UDP_SCAN detection")
        
        ports = range(port_range[0], port_range[1]) if port_range else [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1900]
        
        if SCAPY_AVAILABLE:
            for port in ports:
                try:
                    pkt = IP(dst=self.target)/UDP(dport=port)/Raw(load="probe")
                    send(pkt, verbose=0)
                    print(f"    [UDP] -> {self.target}:{port}")
                    time.sleep(self.delay)
                except Exception as e:
                    print(f"    [!] Error: {e}")
        else:
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.sendto(b"probe", (self.target, port))
                    sock.close()
                    print(f"    [UDP] -> {self.target}:{port}")
                    time.sleep(self.delay)
                except:
                    pass
                    
        print(f"[+] UDP Scan complete")

    def aggressive_scan(self) -> None:
        """
        Aggressive/Noisy Scan - Rapid scanning of many ports
        Detection: High packet rate from single source
        """
        print(f"\n[*] Starting AGGRESSIVE Scan on {self.target}")
        print("[*] This should trigger: AGGRESSIVE_SCAN / HIGH_RATE detection")
        
        self.delay = 0.001  # Very fast
        
        for port in range(1, 1001):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                sock.connect_ex((self.target, port))
                sock.close()
            except:
                pass
                
        print(f"[+] Aggressive Scan complete - 1000 ports in rapid succession")


def main():
    parser = argparse.ArgumentParser(description="Port Scanner for Detection Testing")
    parser.add_argument("--target", "-t", default=None, help="Target IP address (NOT 127.0.0.1! Use router IP)")
    parser.add_argument("--type", "-T", default="syn", 
                        choices=["syn", "fin", "xmas", "null", "ack", "udp", "aggressive", "all"],
                        help="Scan type")
    parser.add_argument("--ports", "-p", default="1-100", help="Port range (e.g., 1-1000)")
    parser.add_argument("--delay", "-d", type=float, default=0.01, help="Delay between packets")
    
    args = parser.parse_args()
    
    # Check target
    if args.target is None:
        print("\n" + "=" * 60)
        print("  ⚠️  ERROR: You must specify a target!")
        print("  DO NOT use 127.0.0.1 - loopback traffic won't be captured!")
        print("  Use: python port_scanner.py --target 192.168.1.1")
        print("=" * 60)
        return
    
    if args.target in ["127.0.0.1", "localhost"]:
        print("\n⚠️  WARNING: 127.0.0.1 won't be captured by PacketPeeper!")
        print("Use your router IP instead (check: ipconfig | findstr Gateway)")
        if input("Continue anyway? (y/N): ").lower() != 'y':
            return
    
    # Parse port range
    if "-" in args.ports:
        start, end = map(int, args.ports.split("-"))
        port_range = (start, end + 1)
    else:
        port_range = (int(args.ports), int(args.ports) + 1)
    
    print("=" * 60)
    print("  PORT SCANNER - Detection Testing Tool")
    print("  WARNING: For authorized testing only!")
    print("=" * 60)
    print(f"  Target: {args.target}")
    print(f"  Scan Type: {args.type}")
    print(f"  Port Range: {args.ports}")
    print("=" * 60)
    
    scanner = PortScanner(args.target)
    scanner.delay = args.delay
    
    if args.type == "syn" or args.type == "all":
        scanner.syn_scan(port_range)
    if args.type == "fin" or args.type == "all":
        scanner.fin_scan(port_range)
    if args.type == "xmas" or args.type == "all":
        scanner.xmas_scan(port_range)
    if args.type == "null" or args.type == "all":
        scanner.null_scan(port_range)
    if args.type == "ack" or args.type == "all":
        scanner.ack_scan(port_range)
    if args.type == "udp" or args.type == "all":
        scanner.udp_scan(port_range)
    if args.type == "aggressive" or args.type == "all":
        scanner.aggressive_scan()
    
    print("\n[*] Scan complete. Check PacketPeeper for detections!")


if __name__ == "__main__":
    main()
