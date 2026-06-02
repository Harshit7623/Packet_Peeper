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
try:
    from scapy.layers.tls.all import TLSClientHello
except (ImportError, ModuleNotFoundError):
    TLSClientHello = None
from datetime import datetime
import os
import platform
import time
import logging
import json
import socket
import ipaddress
import tldextract
import psutil
import hashlib
from network_security_monitor import NetworkSecurityMonitor
from config.config import (
    CAPTURE_DEBUG,
    CAPTURE_MODE,
    MAX_PACKET_HISTORY,
    MAX_CATEGORY_HISTORY,
    MAX_SECURITY_ALERTS,
    SERVICE_CACHE_MAX,
    PACKET_HASH_MAX_BYTES,
    ENABLE_VENDOR_LOOKUP,
    BPF_FILTER,
    LOGS_DIR,
)

# ---------------- Default BPF Filter ---------------- #
# Include TCP, UDP, ICMP, and ARP for comprehensive attack detection
DEFAULT_BPF = BPF_FILTER or (
    "(tcp or udp or icmp or arp)"
    " and not (udp and (port 67 or port 68 or port 5353 or port 1900 or port 123))"
)

# ---------------- Logging ---------------- #
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR, exist_ok=True)

log_file = os.path.join(LOGS_DIR, "classification.log")
logging.basicConfig(
    level=logging.DEBUG if CAPTURE_DEBUG else logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
)

logger = logging.getLogger("packet_peeper.capture")


def _debug_log(message: str):
    if CAPTURE_DEBUG:
        logger.debug(message)

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
    def __init__(self, max_entries: int):
        self.ip_map = {}
        self.max_entries = max_entries

    def _prune_expired(self):
        now = time.time()
        expired = [
            ip for ip, meta in self.ip_map.items()
            if meta.get("expires", 0) < now
        ]
        for ip in expired:
            self.ip_map.pop(ip, None)

    def _enforce_limit(self):
        if len(self.ip_map) <= self.max_entries:
            return

        overflow = len(self.ip_map) - self.max_entries
        oldest = sorted(self.ip_map.items(), key=lambda item: item[1].get("expires", 0))
        for ip, _ in oldest[:overflow]:
            self.ip_map.pop(ip, None)

    def put(self, ip, hostname, service, ttl=DNS_TTL_DEFAULT):
        self._prune_expired()
        self.ip_map[ip] = {
            "hostname": hostname,
            "service": service,
            "expires": time.time() + max(30, ttl),
        }
        self._enforce_limit()

    def get(self, ip):
        self._prune_expired()
        meta = self.ip_map.get(ip)
        if not meta:
            return None
        if meta["expires"] < time.time():
            self.ip_map.pop(ip, None)
            return None
        return meta

service_cache = ServiceCache(max_entries=SERVICE_CACHE_MAX)
vendor_cache = {}

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
    capture_mode = CAPTURE_MODE or "full"

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
    elif capture_mode != "lite" and TLSClientHello and packet.haslayer(TLSClientHello):
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
        self._running = False  # Flag used by stop_sniffing() to gracefully end capture
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
        logger.info("PacketSniffer initialized with classification & metrics")
        self.discover_devices()

    # --- device discovery & stats omitted for brevity (keep your original code) ---
    def discover_devices(self):
        """Discover network interfaces and determine local network."""
        try:
            system_name = platform.system().lower()
            host_ip = self.get_host_ip()
            if host_ip:
                _debug_log(f"Host IP detected: {host_ip}")

            if system_name == 'windows':
                self._discover_devices_windows()
            else:
                self._discover_devices_psutil()

        except Exception as e:
            logging.exception(f"Error discovering devices: {e}")

    def _discover_devices_windows(self):
        """Discover network interfaces using Windows ipconfig output."""
        import subprocess
        import re
        import struct

        output = subprocess.check_output("ipconfig /all", text=True, errors='ignore')
        adapter_sections = output.split('\n\n')

        for section in adapter_sections:
            if not section.strip():
                continue

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

            if not (ip_addr and adapter_name):
                continue

            _debug_log(f"Found adapter: {adapter_name} - IP: {ip_addr} - MAC: {mac_addr}")

            if netmask:
                try:
                    netmask_bits = bin(struct.unpack('!I', socket.inet_aton(netmask))[0]).count('1')
                    ip_int = struct.unpack('!I', socket.inet_aton(ip_addr))[0]
                    mask_int = struct.unpack('!I', socket.inet_aton(netmask))[0]
                    network = ip_int & mask_int
                    network_addr = socket.inet_ntoa(struct.pack('!I', network))
                    self.local_network = f"{network_addr}/{netmask_bits}"
                except Exception as e:
                    logging.warning(f"Failed to compute local network from netmask: {e}")

            self._register_interface_device(adapter_name, ip_addr, mac_addr)

    def _discover_devices_psutil(self):
        """Discover network interfaces on Linux/macOS using psutil data."""
        net_if_addrs = psutil.net_if_addrs()

        for adapter_name, addrs in net_if_addrs.items():
            adapter_name_lower = adapter_name.lower()
            if adapter_name_lower.startswith('lo') or adapter_name_lower.startswith('loopback'):
                continue

            ip_addr = None
            mac_addr = None

            for addr in addrs:
                family = getattr(addr, 'family', None)
                if family == socket.AF_INET:
                    ip_addr = addr.address
                elif str(family).lower().endswith('af_link') or str(family) == '17':
                    mac_addr = addr.address

            if not ip_addr:
                continue

            self._register_interface_device(adapter_name, ip_addr, mac_addr)

            if not self.local_network:
                try:
                    ip_obj = ipaddress.ip_interface(f"{ip_addr}/24")
                    self.local_network = str(ip_obj.network)
                except Exception:
                    pass

    def _register_interface_device(self, adapter_name, ip_addr, mac_addr):
        """Store interface metadata and seed it as an active device."""
        if not adapter_name or not ip_addr:
            return

        self.devices[adapter_name] = {
            'id': len(self.devices) + 1,
            'name': adapter_name,
            'type': 'Wireless' if 'wi-fi' in adapter_name.lower() or 'wireless' in adapter_name.lower() else 'Wired',
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

    def is_local_ip(self, ip):
        """Check if an IP is in the local network range or any private IP range."""
        if not ip or ip == '0.0.0.0':
            return False
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Always allow private IP ranges (RFC 1918)
            private_networks = [
                ipaddress.ip_network('10.0.0.0/8'),
                ipaddress.ip_network('172.16.0.0/12'),
                ipaddress.ip_network('192.168.0.0/16'),
                ipaddress.ip_network('127.0.0.0/8'),  # Loopback
            ]
            
            for network in private_networks:
                if ip_obj in network:
                    return True
            
            # Also check specific local_network if detected
            if self.local_network:
                if ip_obj in ipaddress.ip_network(self.local_network):
                    return True
            
            return False
        except Exception as e:
            logging.debug(f"is_local_ip error for {ip}: {e}")
            return False

    def update_active_device(self, ip, mac=None, is_source=True, packet_len=0):
        """Update active device information based on packet data."""
        if not ip or ip == '0.0.0.0':
            return
        
        # Only track LOCAL network devices, not remote internet hosts
        if not self.is_local_ip(ip):
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
                    _debug_log(f"Could not get MAC for {ip}: {str(e)}")
            
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
                _debug_log(f"Could not resolve hostname for {ip}: {str(e)}")

            device_type = 'Unknown'
            if mac and ENABLE_VENDOR_LOOKUP:
                try:
                    oui = mac.replace(':', '').upper()[:6]
                    if oui in vendor_cache:
                        device_type = vendor_cache[oui]
                    else:
                        import requests
                        response = requests.get(f'https://api.macvendors.com/{oui}', timeout=2)
                        if response.status_code == 200:
                            device_type = response.text
                        vendor_cache[oui] = device_type
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
            _debug_log(f"New device detected: IP={ip}, MAC={mac}, Type={device_type}")
        
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

    def stop_sniffing(self):
        """Stop packet capture gracefully by setting the _running flag to False."""
        self._running = False
        logger.info("[Capture] Stop requested – capture will end after current packet")

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

            if packet.haslayer('IP'):
                ip_layer = packet['IP']
                packet_info["src_ip"] = ip_layer.src
                packet_info["dst_ip"] = ip_layer.dst
            elif packet.haslayer('IPv6'):
                ipv6_layer = packet['IPv6']
                packet_info["src_ip"] = ipv6_layer.src
                packet_info["dst_ip"] = ipv6_layer.dst
            elif packet.haslayer('Ether'):
                ether = packet['Ether']
                packet_info["src_ip"] = ether.src
                packet_info["dst_ip"] = ether.dst
                
            if packet.haslayer('TCP'):
                tcp = packet[TCP]
                packet_info["protocol"] = "TCP"
                packet_info["src_port"] = tcp.sport
                packet_info["dst_port"] = tcp.dport
                # Convert TCP flags to integer (Scapy returns FlagValue object)
                try:
                    packet_info["tcp_flags"] = int(tcp.flags)
                except:
                    packet_info["tcp_flags"] = 0
                _debug_log(
                    f"[TCP FLAGS] {packet_info['src_ip']}:{tcp.sport} -> "
                    f"{packet_info['dst_ip']}:{tcp.dport} flags={packet_info['tcp_flags']} ({tcp.flags})"
                )
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
            
            # Handle ARP packets for spoofing detection
            try:
                from scapy.layers.l2 import ARP as ARP_Layer
                if packet.haslayer(ARP_Layer):
                    arp = packet[ARP_Layer]
                    packet_info["protocol"] = "ARP"
                    packet_info["arp_op"] = arp.op  # 1=request, 2=reply
                    packet_info["arp_src_ip"] = arp.psrc
                    packet_info["arp_dst_ip"] = arp.pdst
                    packet_info["arp_src_mac"] = arp.hwsrc
                    packet_info["arp_dst_mac"] = arp.hwdst
                    packet_info["src_ip"] = arp.psrc
                    packet_info["dst_ip"] = arp.pdst
                    _debug_log(f"[ARP] op={arp.op} {arp.psrc} ({arp.hwsrc}) -> {arp.pdst} ({arp.hwdst})")
            except:
                pass
            
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
            if PACKET_HASH_MAX_BYTES > 0 and CAPTURE_MODE != "lite":
                try:
                    raw_bytes = bytes(packet)
                    packet_info["payload_hash"] = hashlib.sha256(raw_bytes[:PACKET_HASH_MAX_BYTES]).hexdigest()
                except Exception as e:
                    _debug_log(f"Failed to hash packet payload: {e}")
            # Metrics
            self.metrics["total"] += 1
            if srv != "Unknown":
                self.metrics["classified"] += 1
            else:
                self.metrics["unknown"] += 1
            self.metrics["by_service"][srv] = self.metrics["by_service"].get(srv, 0) + 1
            # Store & categorize
            self.captured_packets.append(packet_info)
            if len(self.captured_packets) > MAX_PACKET_HISTORY:
                self.captured_packets = self.captured_packets[-MAX_PACKET_HISTORY:]

            self.categories.setdefault(srv, []).append(packet_info)
            if len(self.categories[srv]) > MAX_CATEGORY_HISTORY:
                self.categories[srv] = self.categories[srv][-MAX_CATEGORY_HISTORY:]
            
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
                _debug_log(f"Active devices ({len(self.active_devices)}):")
                for ip, device in self.active_devices.items():
                    _debug_log(f"Device: {device['hostname']} ({ip})")
                    _debug_log(f"  MAC: {device['macAddress']}")
                    _debug_log(f"  Type: {device['type']}")
                    _debug_log(f"  Traffic: {device['packetsIn']} in, {device['packetsOut']} out")
                    _debug_log(f"  Last seen: {device['lastSeen']}")
            
            # Security Analysis
            _debug_log(
                f"Analyzing packet for security: {packet_info['protocol']} "
                f"{packet_info['src_ip']} -> {packet_info['dst_ip']}"
            )
            alerts = self.security_monitor.analyze_packet(packet_info)
            
            if alerts:
                _debug_log(f"Found {len(alerts)} security alerts!")
                for alert in alerts:
                    alert_hash = f"{alert['title']}-{alert['source']}-{time.time() // 300}"  # 5-minute window
                    
                    # Check if this exact alert was recently issued
                    if alert_hash not in [a.get('hash', '') for a in self.security_alerts[-10:]]:
                        self.security_alerts.append({**alert, 'hash': alert_hash})
                        if len(self.security_alerts) > MAX_SECURITY_ALERTS:
                            self.security_alerts = self.security_alerts[-MAX_SECURITY_ALERTS:]
                        
                        _debug_log(f"[ALERT] {alert['title']}")
                        _debug_log(f"Description: {alert['description']}")
                        _debug_log(f"Severity: {alert['severity']}")
                        _debug_log(f"Source: {alert['source']}")
                        _debug_log(f"Timestamp: {alert['timestamp']}")
                        
                        # Pass alert through callback to ensure it reaches the frontend
                        if self.callback:
                            alert_copy = alert.copy()
                            alert_copy['alert_type'] = 'security'  # Mark as security alert
                            alert_copy['packet_info'] = packet_info  # Include triggering packet
                            _debug_log("Sending alert to frontend via callback")
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
                            if len(self.security_alerts) > MAX_SECURITY_ALERTS:
                                self.security_alerts = self.security_alerts[-MAX_SECURITY_ALERTS:]
            # Callback
            if self.callback:
                self.callback(packet_info)
        except Exception as e:
            logger.error(f"Error handling packet: {e}")

    def start_sniffing(self, interface="auto", bpf=None):
        import traceback
        bpf = bpf or DEFAULT_BPF
        self._running = True
        logger.info(f"Starting sniffing on {interface} with filter: {bpf}")
        
        # Set Scapy configurations for better packet capture
        conf.sniff_promisc = True  # Enable promiscuous mode
        conf.use_pcap = True       # Use libpcap for better packet capture
        
        available_interfaces = get_if_list()

        # Auto-select interface if requested.
        if not interface or str(interface).lower() == 'auto':
            preferred = [i for i in available_interfaces if not i.lower().startswith('lo')]
            if preferred:
                actual_interface = preferred[0]
            elif available_interfaces:
                actual_interface = available_interfaces[0]
            else:
                raise RuntimeError("No network interfaces found for packet capture")
            logger.info(f"Auto-selected interface: {actual_interface}")
        elif interface in conf.ifaces:
            actual_interface = interface
        else:
            # Try to find the interface by description or name
            interface_lower = str(interface).lower()
            actual_interface = None
            for iface in conf.ifaces.values():
                iface_name = str(getattr(iface, 'name', ''))
                iface_desc = str(getattr(iface, 'description', ''))
                if interface_lower in iface_desc.lower() or interface_lower in iface_name.lower():
                    actual_interface = iface_name
                    logger.info(f"Found matching interface: {actual_interface}")
                    break

            if not actual_interface:
                preferred = [i for i in available_interfaces if not i.lower().startswith('lo')]
                if preferred:
                    actual_interface = preferred[0]
                elif available_interfaces:
                    actual_interface = available_interfaces[0]
                else:
                    raise RuntimeError("No network interfaces found for packet capture")
                logger.warning(
                    f"Interface {interface} not found; falling back to {actual_interface}"
                )
        
            logger.info(f"Starting capture on interface: {actual_interface}")
            logger.info("Waiting for packets...")
        
        # Start the actual sniffing with auto-restart on failure
        retry_count = 0
        max_retries = 5
        while retry_count < max_retries and self._running:
            try:
                sniff(iface=actual_interface, 
                      prn=self.handle_packet, 
                      store=0, 
                      filter=bpf,
                      stop_filter=lambda _pkt: not self._running)
                # If sniff() returns because _running became False, exit cleanly
                if not self._running:
                    logger.info("Sniffing stopped gracefully via stop_sniffing()")
                    break
                # If sniff() returns normally, log and restart
                logger.warning("Sniff loop exited normally, restarting...")
                retry_count += 1
                time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Sniffing stopped by user")
                self._running = False
                break
            except PermissionError as e:
                logger.error(f"Packet capture permission error on {actual_interface}: {str(e)}")
                self._running = False
                raise
            except Exception as e:
                logger.error(f"Packet capture error: {str(e)}")
                traceback.print_exc()
                retry_count += 1
                logger.warning(f"Restarting capture (attempt {retry_count}/{max_retries})...")
                time.sleep(2)
        
        error_msg = f"Sniffing stopped after {max_retries} retries"
        logger.error(error_msg)
        raise RuntimeError(error_msg)

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
            logger.error(f"Error getting host IP: {str(e)}")
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
