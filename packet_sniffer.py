"""
Packet Peeper - Enhanced Packet Sniffer Module
----------------------------------------------
This module captures network packets in real time from a given network interface,
classifies them by protocol and inferred service (WhatsApp, YouTube, etc.),
and provides categorized statistics.

Enhancements in this version:
- DNS-based classification (queries + responses → passive IP→domain cache)
- TLS SNI parsing (for HTTPS hostnames)
- Port-based fallback classification
- Configurable service map (service_map.json)
- BPF filter to reduce noise
- Metrics tracking
- PostgreSQL database integration for persistent storage
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, conf, get_if_list, get_if_addr, get_if_hwaddr
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.tls.all import TLSClientHello
from datetime import datetime
import os
import time
import logging
import json
import socket
import ipaddress
import tldextract
import psutil
from network_security_monitor import NetworkSecurityMonitor

# ---------------- Default BPF Filter ---------------- #
DEFAULT_BPF = (
    "(tcp or udp)"
    " and not arp"
    " and not (udp and (port 67 or port 68 or port 5353 or port 1900 or port 123))"
)

# ---------------- Logging ---------------- #
if not os.path.exists("logs"):
    os.makedirs("logs")

log_file = os.path.join("logs", "classification.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
)

# ---------------- Service Map Loader ---------------- #
def load_service_map(path="service_map.json"):
    try:
        with open(path, "r") as f:
            data = json.load(f)
            if isinstance(data, dict) and data:
                return {k.lower(): [d.lower() for d in v] for k, v in data.items()}
    except Exception:
        pass
    return {
        "Whatsapp": ["whatsapp.com", "whatsapp.net"],
        "Youtube": ["youtube.com", "ytimg.com", "googlevideo.com"],
        "Facebook": ["facebook.com", "fbcdn.net"],
        "Instagram": ["instagram.com", "cdninstagram.com"],
        "Google": ["google.com", "gstatic.com", "googleapis.com"],
        "Netflix": ["netflix.com", "nflxvideo.net"],
    }




SERVICE_MAP = load_service_map()

# ---------------- Passive DNS Cache ---------------- #
DNS_TTL_DEFAULT = 300  # seconds

class ServiceCache:
    def __init__(self):
        self.ip_map = {}

    def put(self, ip, hostname, service, ttl=DNS_TTL_DEFAULT):
        self.ip_map[ip] = {
            "hostname": hostname,
            "service": service,
            "expires": time.time() + max(30, ttl),
        }

    def get(self, ip):
        meta = self.ip_map.get(ip)
        if not meta:
            return None
        if meta["expires"] < time.time():
            self.ip_map.pop(ip, None)
            return None
        return meta

service_cache = ServiceCache()

# ---------------- Classifier ---------------- #
def _match_service_from_hostname(hostname: str) -> str:
    host = hostname.lower()
    for srv, patterns in SERVICE_MAP.items():
        if any(p in host for p in patterns):
            return srv
    return "Unknown"

def _update_cache_from_dns(pkt):
    if not (pkt.haslayer(DNS) and pkt[DNS].qr == 1):
        return
    dns = pkt[DNS]
    ancount = dns.ancount or 0
    if ancount == 0:
        return
    answers = [dns.an] if ancount == 1 else dns.an
    for rr in answers:
        if isinstance(rr, DNSRR):
            if rr.type in (1, 28) and rr.rdata:  # A/AAAA only
                ip = rr.rdata if isinstance(rr.rdata, str) else None
                host = rr.rrname.decode().rstrip(".") if rr.rrname else None
                if ip and host:
                    srv = _match_service_from_hostname(host)
                    ttl = getattr(rr, "ttl", DNS_TTL_DEFAULT) or DNS_TTL_DEFAULT
                    service_cache.put(ip, host, srv, ttl)

SERVICE_MAP.update({
    "Microsoft": ["outlook.com", "office.com", "office365.com", "live.com", "skype.com"],
    "Telegram": ["telegram.org", "t.me"],
    "Slack": ["slack.com"],
    "Zoom": ["zoom.us"],
    "Aws": ["amazonaws.com"],
    "Cloudflare": ["cloudflare.com", "cf-ipfs.com"],
})

# Expanded IP ranges (example; can be extended)
IP_NETS = {
    "Google": ["142.250.0.0/15", "172.217.0.0/16", "74.125.0.0/16"],
    "Facebook": ["157.240.0.0/16", "31.13.0.0/16"],
    "Whatsapp": ["157.240.0.0/16", "31.13.0.0/16"],
    "Microsoft": ["40.0.0.0/8"],
    "Netflix": ["52.89.0.0/16", "52.88.0.0/15"],
}

def match_ip_service(ip):
    """Match IP against known CIDR ranges."""
    try:
        ip_addr = ipaddress.ip_address(ip)
        for srv, nets in IP_NETS.items():
            for net in nets:
                if ip_addr in ipaddress.ip_network(net):
                    logging.info(f"Classified service '{srv}' from IP range {net}")
                    return srv
    except Exception:
        pass
    return None
# IP_SERVICE_MAP = {
#     "Youtube": ["172.217.", "142.250.", "74.125."],   # Google video ranges
#     "Whatsapp": ["157.240.", "31.13."],               # Meta/WhatsApp
#     "Facebook": ["157.240.", "31.13."],               # Meta
#     "Instagram": ["157.240.", "31.13."],              # Meta/Instagram
#     "Google": ["142.250.", "8.8.8.", "8.34."]         # Google infra
# }

# def match_ip_service(ip):
#     """Match IP against known service prefixes."""
#     for srv, prefixes in IP_SERVICE_MAP.items():
#         if any(ip.startswith(prefix) for prefix in prefixes):
#             logging.info(f"Classified service '{srv}' based on IP prefix: {ip}")
#             return srv
#     return None


# def classify_packet_service(packet):
#     """Classify packet by DNS hostname, TLS SNI, cache, or IP prefix."""
#     hostname = None
#     service = "Unknown"

#     src_ip, dst_ip = None, None
#     if packet.haslayer(IP):
#         src_ip = packet[IP].src
#         dst_ip = packet[IP].dst

#         # 🔹 Check cache first (if we saw DNS/TLS earlier)
#         for ip in [src_ip, dst_ip]:
#             cached = service_cache.get(ip)
#             if cached:
#                 return cached["service"]

#     # DNS classification
#     if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
#         try:
#             qname = packet[DNSQR].qname.decode().rstrip('.')
#             hostname = qname
#             for srv, domains in SERVICE_MAP.items():
#                 if any(d in hostname for d in domains):
#                     # cache the mapping for future packets
#                     if dst_ip:
#                         service_cache.put(dst_ip, hostname, srv)
#                     logging.info(f"Classified service '{srv}' via DNS: {hostname}")
#                     return srv
#         except Exception:
#             pass

#     # TLS SNI classification
#     elif packet.haslayer(TLSClientHello):
#         try:
#             hostname = packet[TLSClientHello].ext_servername.decode()
#             for srv, domains in SERVICE_MAP.items():
#                 if any(d in hostname for d in domains):
#                     if dst_ip:
#                         service_cache.put(dst_ip, hostname, srv)
#                     logging.info(f"Classified service '{srv}' via TLS SNI: {hostname}")
#                     return srv
#         except Exception:
#             pass

#     # Fallback: IP prefix matching
#     for ip in [src_ip, dst_ip]:
#         if ip:
#             match = match_ip_service(ip)
#             if match:
#                 return match

#     # Fallback: Port-based classification
#     if packet.haslayer(TCP):
#         sport, dport = packet[TCP].sport, packet[TCP].dport
#         if sport in [80, 8080] or dport in [80, 8080]:
#             return "HTTP"
#         elif sport == 443 or dport == 443:
#             return "HTTPS"
#         elif sport == 53 or dport == 53:
#             return "DNS"

#     return service

def classify_packet_service(packet):
    """Classify packet by DNS hostname, TLS SNI, cache, IP range, or port."""
    hostname = None
    service = "Unknown"

    src_ip, dst_ip = None, None
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Check passive cache
        for ip in [src_ip, dst_ip]:
            cached = service_cache.get(ip)
            if cached:
                return cached["service"]

    # DNS classification
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        try:
            qname = packet[DNSQR].qname.decode().rstrip('.')
            hostname = qname
            for srv, domains in SERVICE_MAP.items():
                if any(d in hostname for d in domains):
                    if dst_ip:
                        service_cache.put(dst_ip, hostname, srv)
                    logging.info(f"Classified '{srv}' via DNS: {hostname}")
                    return srv
        except Exception:
            pass

    # TLS SNI
    elif packet.haslayer(TLSClientHello):
        try:
            hostname = packet[TLSClientHello].ext_servername.decode()
            for srv, domains in SERVICE_MAP.items():
                if any(d in hostname for d in domains):
                    if dst_ip:
                        service_cache.put(dst_ip, hostname, srv)
                    logging.info(f"Classified '{srv}' via TLS SNI: {hostname}")
                    return srv
        except Exception:
            pass

    # IP range check
    for ip in [src_ip, dst_ip]:
        if ip:
            match = match_ip_service(ip)
            if match:
                return match

    # Root-domain fallback
    if hostname:
        root = tldextract.extract(hostname)
        root_domain = f"{root.domain}.{root.suffix}"
        logging.info(f"Classified by root domain: {root_domain}")
        return root_domain

    # Port-based fallback
    if packet.haslayer(TCP):
        sport, dport = packet[TCP].sport, packet[TCP].dport
        if sport in [80, 8080] or dport in [80, 8080]:
            return "HTTP"
        elif sport == 443 or dport == 443:
            return "HTTPS"
        elif sport == 53 or dport == 53:
            return "DNS"

    return service


# ---------------- Packet Sniffer Class ---------------- #
class PacketSniffer:
    """Captures and categorizes packets from a given network interface."""

    def __init__(self):
        self.captured_packets = []
        self.categories = {}
        self.callback = None
        self.devices = {}  # Stores interface information
        self.active_devices = {}  # Stores active network devices
        self.device_stats = {}
        self.active_device_filter = None
        self.tcp_streams = {}
        self.fragmented_packets = {}
        self.max_stream_size = 10 * 1024 * 1024
        self.stream_timeout = 300
        self.metrics = {"total": 0, "classified": 0, "unknown": 0, "by_service": {}}
        self.security_monitor = NetworkSecurityMonitor()  # Initialize security monitor
        self.security_alerts = []  # Store detected cyberattack events
        self.local_network = None  # Will store the local network CIDR
        # --- Bandwidth and protocol tracking ---
        self.bandwidth_history = []  # [(timestamp, bytes)]
        self.peak_bandwidth = 0
        self.last_bandwidth_calc = time.time()
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.packet_loss_count = 0
        self.latency_samples = []
        self.jitter_samples = []
        print("PacketSniffer initialized with classification & metrics")
        self.discover_devices()

    # --- device discovery & stats omitted for brevity (keep your original code) ---
    def discover_devices(self):
        """Discover network interfaces and determine local network."""
        try:
            import subprocess
            import re
            
            # Get host's primary IP
            host_ip = self.get_host_ip()
            if host_ip:
                print(f"Host IP detected: {host_ip}")
            
            # Use ipconfig to get Windows network interface information
            try:
                output = subprocess.check_output("ipconfig /all", text=True, errors='ignore')
                
                # Parse ipconfig output for interfaces
                adapter_sections = output.split('\n\n')
                
                for section in adapter_sections:
                    if not section.strip():
                        continue
                    
                    # Extract adapter info
                    lines = section.split('\n')
                    adapter_name = None
                    ip_addr = None
                    mac_addr = None
                    netmask = None
                    
                    for line in lines:
                        if 'Ethernet adapter' in line or 'Wireless LAN' in line or 'Wi-Fi' in line:
                            adapter_name = line.split(':')[0].strip()
                        
                        if 'IPv4 Address' in line and 'Preferred' not in line:
                            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                            if ip_match:
                                ip_addr = ip_match.group(1)
                        
                        if 'Physical Address' in line or 'MAC Address' in line:
                            mac_match = re.search(r'([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})', line)
                            if mac_match:
                                mac_addr = mac_match.group(1)
                        
                        if 'Subnet Mask' in line:
                            mask_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                            if mask_match:
                                netmask = mask_match.group(1)
                    
                    # If we found an IP, process it
                    if ip_addr and adapter_name:
                        print(f"Found adapter: {adapter_name} - IP: {ip_addr} - MAC: {mac_addr}")
                        
                        # Determine local network CIDR
                        try:
                            import socket
                            import struct
                            if netmask:
                                netmask_bits = bin(struct.unpack('!I', socket.inet_aton(netmask))[0]).count('1')
                                
                                # Calculate network address
                                ip_int = struct.unpack('!I', socket.inet_aton(ip_addr))[0]
                                mask_int = struct.unpack('!I', socket.inet_aton(netmask))[0]
                                network = ip_int & mask_int
                                network_addr = socket.inet_ntoa(struct.pack('!I', network))
                                self.local_network = f"{network_addr}/{netmask_bits}"
                                print(f"Local network detected: {self.local_network}")
                        except Exception as e:
                            print(f"Error calculating network CIDR: {e}")
                            # Fallback to common home network CIDR
                            if ip_addr.startswith('192.168.'):
                                self.local_network = '192.168.0.0/16'
                            elif ip_addr.startswith('10.'):
                                self.local_network = '10.0.0.0/8'
                            elif ip_addr.startswith('172.'):
                                self.local_network = '172.16.0.0/12'
                        
                        # Add interface to devices
                        self.devices[adapter_name] = {
                            'id': len(self.devices) + 1,
                            'name': adapter_name,
                            'type': 'Wireless' if 'Wi-Fi' in adapter_name or 'Wireless' in adapter_name else 'Wired',
                            'status': 'Active',
                            'ipAddress': ip_addr,
                            'macAddress': mac_addr,
                            'packetsCaptured': 0,
                            'lastActive': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'isLocal': True
                        }
                        
                        self.device_stats[adapter_name] = {
                            'packets': 0,
                            'bytes': 0,
                            'last_seen': time.time()
                        }
                        
                        # Add the interface itself as an active device
                        self.active_devices[ip_addr] = {
                            'ipAddress': ip_addr,
                            'macAddress': mac_addr,
                            'hostname': adapter_name,
                            'type': 'Interface',
                            'firstSeen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'lastSeen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'packetsIn': 0,
                            'packetsOut': 0,
                            'bytesIn': 0,
                            'bytesOut': 0,
                            'status': 'Active'
                        }

            except Exception as e:
                logging.warning(f"Error parsing adapter section: {e}")
        
        except Exception as e:
            logging.exception(f"Error discovering devices: {e}")

    def is_local_ip(self, ip):
        """Check if an IP is in the local network range."""
        if not ip or ip == '0.0.0.0':
            return False
        try:
            if not self.local_network:
                return False
            return ipaddress.ip_address(ip) in ipaddress.ip_network(self.local_network)
        except:
            return False

    def update_active_device(self, ip, mac=None, is_source=True, packet_len=0):
        """Update active device information based on packet data."""
        if not ip or ip == '0.0.0.0':
            return

        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if ip not in self.active_devices:
            from scapy.layers.l2 import getmacbyip, ARP, Ether
            from scapy.sendrecv import srp

            # Try to get MAC address if not provided
            if not mac:
                try:
                    # First try getmacbyip
                    mac = getmacbyip(ip)
                    if not mac:
                        # If that fails, try ARP
                        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0)
                        if ans:
                            mac = ans[0][1].hwsrc
                except Exception as e:
                    print(f"Could not get MAC for {ip}: {str(e)}")
            
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception as e:
                # More graceful handling of hostname resolution failure
                if ip == self.get_host_ip():
                    hostname = "This Device"
                elif self.is_local_ip(ip):
                    hostname = f"Local Device {len(self.active_devices) + 1}"
                else:
                    hostname = f"Remote Device {len(self.active_devices) + 1}"
                print(f"Could not resolve hostname for {ip}: {str(e)}")

            device_type = 'Unknown'
            if mac:
                # Check OUI (first 6 chars of MAC) to determine manufacturer
                try:
                    import requests
                    oui = mac.replace(':', '').upper()[:6]
                    response = requests.get(f'https://api.macvendors.com/{oui}', timeout=2)
                    if response.status_code == 200:
                        device_type = response.text
                except Exception:
                    pass

            self.active_devices[ip] = {
                'ipAddress': ip,
                'macAddress': mac,
                'hostname': hostname,
                'type': device_type,
                'firstSeen': current_time,
                'lastSeen': current_time,
                'packetsIn': 0,
                'packetsOut': 0,
                'bytesIn': 0,
                'bytesOut': 0,
                'status': 'Active'
            }
            print(f"New device detected: IP={ip}, MAC={mac}, Type={device_type}")
        
        device = self.active_devices[ip]
        device['lastSeen'] = current_time
        if is_source:
            device['packetsOut'] += 1
            device['bytesOut'] += packet_len
        else:
            device['packetsIn'] += 1
            device['bytesIn'] += packet_len

    def update_device_stats(self, iface, packet):
        """Increment packet and byte counters for a given interface."""
        if iface in self.device_stats:
            self.device_stats[iface]['packets'] += 1
            self.device_stats[iface]['bytes'] += len(packet)
            self.device_stats[iface]['last_seen'] = time.time()
            if iface in self.devices:
                self.devices[iface]['packetsCaptured'] = self.device_stats[iface]['packets']
                self.devices[iface]['lastActive'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def set_callback(self, callback):
        """Register a callback for packet capture events."""
        self.callback = callback

    def categorize_packet(self, packet_info):
        """Add packet_info to the category list based on its service."""
        service = packet_info.get('service', 'Unknown').lower()
        if service not in self.categories:
            self.categories[service] = []
        self.categories[service].append(packet_info)

    def get_devices(self):
        """Return the current list of discovered devices."""
        return list(self.devices.values())

    def set_device_filter(self, device_ip):
        """Filter packets to only show traffic for a specific device."""
        if device_ip is None:
            self.active_device_filter = None
            return True
        for dev in self.devices.values():
            if dev['ipAddress'] == device_ip:
                self.active_device_filter = device_ip
                return True
        return False

    def get_device_filter(self):
        """Return the currently active device filter, or None."""
        return self.active_device_filter

    def _get_stream_key(self, packet_info):
        """Generate a unique key for a TCP stream (bidirectional)."""
        if packet_info.get('protocol') != 'TCP':
            return None
        ips = sorted([packet_info['src_ip'], packet_info['dst_ip']])
        ports = sorted([packet_info['src_port'], packet_info['dst_port']])
        return f"{ips[0]}:{ports[0]}-{ips[1]}:{ports[1]}"

    def _reassemble_tcp_stream(self, packet_info, raw_data):
        """Reassemble TCP streams from fragments."""
        stream_key = self._get_stream_key(packet_info)
        if not stream_key:
            return None, False

        current_time = time.time()
        if stream_key not in self.tcp_streams:
            self.tcp_streams[stream_key] = {
                'packets': [],
                'last_seen': current_time,
                'size': 0,
                'complete': False,
                'service': packet_info.get('service', 'Unknown')
            }

        stream = self.tcp_streams[stream_key]
        if current_time - stream['last_seen'] > self.stream_timeout:
            stream['complete'] = True
            return None, False

        stream['last_seen'] = current_time
        stream['packets'].append({
            'timestamp': packet_info['timestamp'],
            'data': raw_data,
            'src_ip': packet_info['src_ip'],
            'dst_ip': packet_info['dst_ip'],
            'src_port': packet_info['src_port'],
            'dst_port': packet_info['dst_port']
        })
        stream['size'] += len(raw_data)

        if packet_info.get('tcp_flags', 0) & 0x01 or packet_info.get('tcp_flags', 0) & 0x04:
            stream['complete'] = True
        if stream['size'] > self.max_stream_size:
            stream['complete'] = True

        return stream_key, stream['complete']

    def get_complete_streams(self):
        """Return completed or timed-out streams and remove them from memory."""
        current_time = time.time()
        complete_streams = {}
        for stream_key, stream in list(self.tcp_streams.items()):
            if stream['complete'] or (current_time - stream['last_seen'] > self.stream_timeout):
                complete_streams[stream_key] = stream
                del self.tcp_streams[stream_key]
        return complete_streams


    def handle_packet(self, packet):
        try:
            # Initialize packet info with defaults
            packet_info = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                "protocol": None,
                "src_ip": None,
                "dst_ip": None,
                "src_port": None,
                "dst_port": None,
                "length": len(packet),
                "service": None,
                "tcp_flags": 0,
            }
            
            # Track the current time for rate limiting
            now = time.time()

            # Enhanced IP layer handling
            if IP in packet:
                ip_layer = packet[IP]
                packet_info["src_ip"] = ip_layer.src
                packet_info["dst_ip"] = ip_layer.dst
                print(f"Captured packet with IPs: {ip_layer.src} -> {ip_layer.dst}")
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                packet_info["src_ip"] = ip_layer.src
                packet_info["dst_ip"] = ip_layer.dst
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                packet_info["protocol"] = "TCP"
                packet_info["src_port"] = tcp.sport
                packet_info["dst_port"] = tcp.dport
                packet_info["tcp_flags"] = tcp.flags
                self.tcp_count += 1
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                packet_info["protocol"] = "UDP"
                packet_info["src_port"] = udp.sport
                packet_info["dst_port"] = udp.dport
                self.udp_count += 1
            elif packet.haslayer(ICMP):
                packet_info["protocol"] = "ICMP"
                self.icmp_count += 1
            # Bandwidth tracking
            now = time.time()
            self.bandwidth_history.append((now, len(packet)))
            # Remove old samples (>60s)
            self.bandwidth_history = [(t, b) for t, b in self.bandwidth_history if now - t <= 60]
            # Device filter
            if self.active_device_filter:
                if (packet_info["src_ip"] != self.active_device_filter
                        and packet_info["dst_ip"] != self.active_device_filter):
                    return
            # Classification
            packet_info["service"] = classify_packet_service(packet)
            srv = packet_info["service"]
            # Metrics
            self.metrics["total"] += 1
            if srv != "Unknown":
                self.metrics["classified"] += 1
            else:
                self.metrics["unknown"] += 1
            self.metrics["by_service"][srv] = self.metrics["by_service"].get(srv, 0) + 1
            # Store & categorize
            self.captured_packets.append(packet_info)
            if len(self.captured_packets) > 10000:
                self.captured_packets = self.captured_packets[-5000:]
            self.categories.setdefault(srv, []).append(packet_info)
            
            # Update active devices
            if packet.haslayer(IP):
                # Get MAC addresses from Ethernet layer if available
                src_mac = None
                dst_mac = None
                
                # Try to get MAC addresses from different layers
                if hasattr(packet, 'src'):
                    src_mac = packet.src
                elif 'Ether' in packet:
                    src_mac = packet[Ether].src
                
                if hasattr(packet, 'dst'):
                    dst_mac = packet.dst
                elif 'Ether' in packet:
                    dst_mac = packet[Ether].dst
                
                # Update both source and destination devices
                self.update_active_device(packet_info["src_ip"], src_mac, True, len(packet))
                self.update_active_device(packet_info["dst_ip"], dst_mac, False, len(packet))
                
                # Log current active devices with enhanced details
                print(f"\nActive devices ({len(self.active_devices)}):")
                for ip, device in self.active_devices.items():
                    print(f"Device: {device['hostname']} ({ip})")
                    print(f"  MAC: {device['macAddress']}")
                    print(f"  Type: {device['type']}")
                    print(f"  Traffic: {device['packetsIn']} in, {device['packetsOut']} out")
                    print(f"  Last seen: {device['lastSeen']}")
            
            # Security Analysis
            print(f"\nAnalyzing packet for security: {packet_info['protocol']} {packet_info['src_ip']} -> {packet_info['dst_ip']}")
            alerts = self.security_monitor.analyze_packet(packet_info)
            
            if alerts:
                print(f"Found {len(alerts)} security alerts!")
                for alert in alerts:
                    alert_hash = f"{alert['title']}-{alert['source']}-{time.time() // 300}"  # 5-minute window
                    
                    # Check if this exact alert was recently issued
                    if alert_hash not in [a.get('hash', '') for a in self.security_alerts[-10:]]:
                        self.security_alerts.append({**alert, 'hash': alert_hash})
                        
                        print(f"\n[ALERT] {alert['title']}")
                        print(f"Description: {alert['description']}")
                        print(f"Severity: {alert['severity']}")
                        print(f"Source: {alert['source']}")
                        print(f"Timestamp: {alert['timestamp']}")
                        
                        # Pass alert through callback to ensure it reaches the frontend
                        if self.callback:
                            alert_copy = alert.copy()
                            alert_copy['alert_type'] = 'security'  # Mark as security alert
                            alert_copy['packet_info'] = packet_info  # Include triggering packet
                            print("Sending alert to frontend via callback")
                            self.callback(alert_copy)
            # Signature-based detection (simple TCP flags)
            if packet_info["protocol"] == "TCP":
                # Ensure tcp_flags is JSON serializable
                tcp_flags = packet_info.get("tcp_flags")
                if tcp_flags is not None and not isinstance(tcp_flags, (int, str)):
                    packet_info["tcp_flags"] = str(tcp_flags)
                if packet_info["tcp_flags"] == 2:  # SYN only
                    current_src_ip = packet_info["src_ip"]
                    syn_count = sum(1 for pkt in self.captured_packets[-100:] 
                                  if pkt["protocol"] == "TCP" 
                                  and pkt["src_ip"] == current_src_ip 
                                  and pkt["tcp_flags"] == 2)
                    if syn_count > 50:
                        alert = {
                            "type": "SYN Flood",
                            "source": current_src_ip,
                            "description": "Excessive SYN packets detected.",
                            "timestamp": packet_info["timestamp"],
                            "severity": "high"
                        }
                        if alert not in self.security_alerts:
                            self.security_alerts.append(alert)
            # Callback
            if self.callback:
                self.callback(packet_info)
        except Exception as e:
            print(f"Error handling packet: {e}")

    def start_sniffing(self, interface="Wi-Fi", bpf=None):
        try:
            bpf = bpf or DEFAULT_BPF
            print(f"Starting sniffing on {interface} with filter: {bpf}")
            
            # Set Scapy configurations for better packet capture
            conf.sniff_promisc = True  # Enable promiscuous mode
            conf.use_pcap = True       # Use libpcap for better packet capture
            
            # Try to find the correct interface name
            if interface in conf.ifaces:
                actual_interface = interface
            else:
                # Try to find the interface by description or name
                for iface in conf.ifaces.values():
                    if interface.lower() in str(iface.description).lower() or interface.lower() in str(iface.name).lower():
                        actual_interface = iface.name
                        print(f"Found matching interface: {actual_interface}")
                        break
                else:
                    print(f"Warning: Interface {interface} not found exactly, using as-is")
                    actual_interface = interface
            
            print(f"Starting capture on interface: {actual_interface}")
            print("Waiting for packets...")
            
            # Start the actual sniffing
            sniff(iface=actual_interface, 
                  prn=self.handle_packet, 
                  store=0, 
                  filter=bpf)
        except Exception as e:
            print(f"Error starting packet capture: {str(e)}")
            raise

    def get_metrics(self):
        return self.metrics

    def get_statistics(self):
        now = time.time()
        # Bandwidth calculations
        bytes_last_sec = sum(b for t, b in self.bandwidth_history if now - t <= 1)
        bytes_last_min = sum(b for t, b in self.bandwidth_history if now - t <= 60)
        current_bandwidth = bytes_last_sec
        average_bandwidth = bytes_last_min // 60 if bytes_last_min else 0
        self.peak_bandwidth = max(self.peak_bandwidth, current_bandwidth)
        # Network performance (mocked for now)
        latency = self._calculate_latency()
        jitter = self._calculate_jitter()
        packet_loss = self._calculate_packet_loss()
        # System resource usage (fix: ensure percent is 0-100, smooth CPU)
        cpu_usage = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        memory_usage = min(max(mem.percent, 0), 100)
        disk = psutil.disk_usage('/')
        disk_usage = min(max(disk.percent, 0), 100)
        # Get packet statistics from security monitor
        monitor_stats = self.security_monitor.get_packet_stats()
        
        stats = {
            "currentBandwidth": current_bandwidth,
            "peakBandwidth": self.peak_bandwidth,
            "averageBandwidth": average_bandwidth,
            "totalPackets": len(self.captured_packets),
            "tcpPackets": self.tcp_count,
            "udpPackets": self.udp_count,
            "icmpPackets": self.icmp_count,
            "httpPackets": monitor_stats['http'],
            "httpsPackets": monitor_stats['https'],
            "dnsPackets": monitor_stats['dns'],
            "latency": latency,
            "jitter": jitter,
            "packetLoss": packet_loss,
            "cpuUsage": cpu_usage,
            "memoryUsage": memory_usage,
            "diskUsage": disk_usage
        }
        # Add service breakdown
        stats.update({srv: len(pkts) for srv, pkts in self.categories.items()})
        return stats

    def _calculate_latency(self):
        # Placeholder: simulate latency in ms
        if self.latency_samples:
            return sum(self.latency_samples) // len(self.latency_samples)
        return 10

    def _calculate_jitter(self):
        # Placeholder: simulate jitter in ms
        if self.jitter_samples:
            return sum(self.jitter_samples) // len(self.jitter_samples)
        return 2

    def _calculate_packet_loss(self):
        # Placeholder: simulate packet loss percentage
        total = self.metrics["total"]
        lost = self.packet_loss_count
        if total:
            return round((lost / total) * 100, 2)
        return 0

    def get_categorized_packets(self):
        return self.categories

    def get_host_ip(self):
        """Get the host machine's IP address"""
        try:
            # Create a dummy socket to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Use a public DNS server as target (doesn't actually send packets)
            s.connect(("8.8.8.8", 80))
            host_ip = s.getsockname()[0]
            s.close()
            return host_ip
        except Exception as e:
            print(f"Error getting host IP: {str(e)}")
            return None

    def get_packets_by_service(self, service=None, since_seconds=None):
        """
        Filter captured packets by service and/or time.
        service: e.g. 'whatsapp'
        since_seconds: e.g. 3600 for last hour
        """
        now = time.time()
        results = []
        for pkt in self.captured_packets:
            # Service match
            if service and pkt['service'].lower() != service.lower():
                continue

            # Time match
            if since_seconds:
                try:
                    ts = datetime.strptime(pkt['timestamp'], "%Y-%m-%d %H:%M:%S.%f")
                except ValueError:
                    ts = datetime.strptime(pkt['timestamp'], "%Y-%m-%d %H:%M:%S")
                if (now - ts.timestamp()) > since_seconds:
                    continue

            results.append(pkt)
        return results

# ---------------- Main ---------------- #
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python packet_sniffer.py <interface>")
        sys.exit(1)
    iface = sys.argv[1]
    sniffer = PacketSniffer()
    sniffer.start_sniffing(iface)
