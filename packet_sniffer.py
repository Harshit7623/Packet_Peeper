import sys
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf, get_if_list, get_if_addr, get_if_hwaddr
from datetime import datetime
import json
import os
import time

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
        self.devices = {}
        self.device_stats = {}
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

        # Initialize device discovery
        self.discover_devices()

    def discover_devices(self):
        """Discover network interfaces and their details"""
        try:
            interfaces = get_if_list()
            for iface in interfaces:
                try:
                    ip_addr = get_if_addr(iface)
                    mac_addr = get_if_hwaddr(iface)
                    
                    self.devices[iface] = {
                        'id': len(self.devices) + 1,
                        'name': iface,
                        'type': 'Wireless' if 'wlan' in iface.lower() or 'wi-fi' in iface.lower() else 'Wired',
                        'status': 'Active',
                        'ipAddress': ip_addr,
                        'macAddress': mac_addr,
                        'packetsCaptured': 0,
                        'lastActive': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
                    
                    self.device_stats[iface] = {
                        'packets': 0,
                        'bytes': 0,
                        'last_seen': time.time()
                    }
                except Exception as e:
                    print(f"Error getting details for interface {iface}: {str(e)}")
        except Exception as e:
            print(f"Error discovering devices: {str(e)}")

    def update_device_stats(self, iface, packet):
        """Update statistics for a device"""
        if iface in self.device_stats:
            self.device_stats[iface]['packets'] += 1
            self.device_stats[iface]['bytes'] += len(packet)
            self.device_stats[iface]['last_seen'] = time.time()
            
            # Update device info
            self.devices[iface]['packetsCaptured'] = self.device_stats[iface]['packets']
            self.devices[iface]['lastActive'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def get_devices(self):
        """Return the current list of devices"""
        return list(self.devices.values())

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
            
            # Update device statistics
            if packet_info['src_ip']:
                for iface in self.devices:
                    if self.devices[iface]['ipAddress'] == packet_info['src_ip']:
                        self.update_device_stats(iface, packet)

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
