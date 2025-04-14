import sys
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
from datetime import datetime
import json
import os

class PacketSniffer:
    def __init__(self):
        self.captured_packets = []
        self.categories = {
            'http': [],
            'https': [],
            'dns': [],
            'other': []
        }
        self.callback = None
        print("PacketSniffer initialized")
        
        # Check if running with admin privileges
        if os.name == 'nt':  # Windows
            try:
                is_admin = os.getuid() == 0
            except AttributeError:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Linux/Unix
            is_admin = os.getuid() == 0
            
        if not is_admin:
            print("WARNING: This program requires administrator privileges to capture packets.")
            print("Please run the program as administrator.")
            print("On Windows: Right-click and select 'Run as administrator'")
            print("On Linux: Use 'sudo' before the command")

    def set_callback(self, callback):
        self.callback = callback
        print("Callback set successfully")

    def categorize_packet(self, packet_info):
        try:
            # Categorize packets based on ports and protocols
            if packet_info['protocol'] == 'TCP':
                if packet_info['dst_port'] == 80 or packet_info['src_port'] == 80:
                    self.categories['http'].append(packet_info)
                    print(f"HTTP packet captured: {packet_info['src_ip']}:{packet_info['src_port']} -> {packet_info['dst_ip']}:{packet_info['dst_port']}")
                elif packet_info['dst_port'] == 443 or packet_info['src_port'] == 443:
                    self.categories['https'].append(packet_info)
                    print(f"HTTPS packet captured: {packet_info['src_ip']}:{packet_info['src_port']} -> {packet_info['dst_ip']}:{packet_info['dst_port']}")
                elif packet_info['dst_port'] == 53 or packet_info['src_port'] == 53:
                    self.categories['dns'].append(packet_info)
                    print(f"DNS packet captured: {packet_info['src_ip']}:{packet_info['src_port']} -> {packet_info['dst_ip']}:{packet_info['dst_port']}")
                else:
                    self.categories['other'].append(packet_info)
                    print(f"Other TCP packet captured: {packet_info['src_ip']}:{packet_info['src_port']} -> {packet_info['dst_ip']}:{packet_info['dst_port']}")
            else:
                self.categories['other'].append(packet_info)
                print(f"Non-TCP packet captured: {packet_info['protocol']} {packet_info['src_ip']} -> {packet_info['dst_ip']}")
        except Exception as e:
            print(f"Error categorizing packet: {str(e)}")

    def handle_packet(self, packet):
        try:
            packet_info = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'protocol': None,
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None,
                'length': len(packet)
            }

            if packet.haslayer(IP):
                packet_info['src_ip'] = packet[IP].src
                packet_info['dst_ip'] = packet[IP].dst

            if packet.haslayer(TCP):
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
            elif packet.haslayer(UDP):
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
            elif packet.haslayer(ICMP):
                packet_info['protocol'] = 'ICMP'

            self.captured_packets.append(packet_info)
            self.categorize_packet(packet_info)

            if self.callback:
                self.callback(packet_info)
        except Exception as e:
            print(f"Error handling packet: {str(e)}")

    def start_sniffing(self, interface="Wi-Fi"):
        print(f"Starting packet sniffing on interface: {interface}")
        try:
            # Print available interfaces
            print("\nAvailable network interfaces:")
            for iface in conf.ifaces.data.values():
                print(f"- {iface.name} ({iface.description})")
            
            # Try to start sniffing
            sniff(iface=interface, prn=self.handle_packet, store=0)
        except Exception as e:
            print(f"Error starting packet capture: {str(e)}")
            print("\nTroubleshooting steps:")
            print("1. Make sure you're running as administrator")
            print("2. Check if the interface name is correct")
            print("3. Try using the interface name from the list above")
            print("4. Make sure no other program is using the interface")
            raise

    def get_statistics(self):
        stats = {
            'totalPackets': len(self.captured_packets),
            'httpPackets': len(self.categories['http']),
            'httpsPackets': len(self.categories['https']),
            'dnsPackets': len(self.categories['dns']),
            'otherPackets': len(self.categories['other'])
        }
        print(f"Current statistics: {stats}")
        return stats

    def get_categorized_packets(self):
        return self.categories

# If script is run directly, execute main function
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python packet_sniffer.py <interface>")
        sys.exit(1)

    interface = sys.argv[1]
    print(f"Starting packet sniffing on {interface}...")
    sniffer = PacketSniffer()
    sniffer.start_sniffing(interface)
