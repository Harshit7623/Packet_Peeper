"""
Network Security Monitor - Advanced Real-Time Attack Detection
=============================================================
Detects intermediate to advanced network attacks including:
- Port Scans (SYN, FIN, XMAS, NULL, ACK)
- DDoS Attacks (SYN Flood, UDP Flood, ICMP Flood)
- Spoofing (ARP, DNS, IP)
- Application Attacks (SQL Injection patterns, XSS, Command Injection)
- Advanced Attacks (DNS Tunneling, Covert Channels, Beaconing)
"""

from collections import defaultdict
import time
import re
import base64
import logging
from datetime import datetime
from typing import Dict, List, Optional, Callable, Any

from config.config import DETECTION_PROFILE, DETECTION_DEBUG

logger = logging.getLogger(__name__)

PROFILE_THRESHOLDS = {
    "strict": {
        "port_scan_count": 15,
        "port_scan_window": 90,
        "stealth_scan_count": 8,
        "syn_flood_rate": 100,
        "udp_flood_rate": 150,
        "icmp_flood_rate": 60,
        "flood_window": 5,
        "ddos_sources": 20,
        "ddos_window": 20,
        "dns_query_length": 80,
        "dns_subdomain_count": 8,
        "dns_query_rate": 80,
        "brute_force_attempts": 12,
        "brute_force_window": 180,
        "beacon_regularity": 0.1,
        "beacon_min_callbacks": 8,
        "session_injection_count": 6,
        "session_injection_window": 60,
        "exfil_size_bytes": 2 * 1024 * 1024,
        "exfil_window": 300,
        "alert_cooldown": 120,
        "max_alerts_per_type": 3,
        "max_total_alerts": 30,
    },
    "balanced": {
        "port_scan_count": 10,
        "port_scan_window": 60,
        "stealth_scan_count": 6,
        "syn_flood_rate": 50,
        "udp_flood_rate": 80,
        "icmp_flood_rate": 30,
        "flood_window": 5,
        "ddos_sources": 15,
        "ddos_window": 15,
        "dns_query_length": 70,
        "dns_subdomain_count": 7,
        "dns_query_rate": 40,
        "brute_force_attempts": 7,
        "brute_force_window": 120,
        "beacon_regularity": 0.2,
        "beacon_min_callbacks": 6,
        "session_injection_count": 4,
        "session_injection_window": 30,
        "exfil_size_bytes": 1024 * 1024,
        "exfil_window": 120,
        "alert_cooldown": 60,
        "max_alerts_per_type": 4,
        "max_total_alerts": 50,
    },
    "sensitive": {
        "port_scan_count": 6,
        "port_scan_window": 30,
        "stealth_scan_count": 3,
        "syn_flood_rate": 20,
        "udp_flood_rate": 40,
        "icmp_flood_rate": 15,
        "flood_window": 5,
        "ddos_sources": 8,
        "ddos_window": 10,
        "dns_query_length": 60,
        "dns_subdomain_count": 6,
        "dns_query_rate": 30,
        "brute_force_attempts": 5,
        "brute_force_window": 60,
        "beacon_regularity": 0.15,
        "beacon_min_callbacks": 5,
        "session_injection_count": 3,
        "session_injection_window": 30,
        "exfil_size_bytes": 500 * 1024,
        "exfil_window": 60,
        "alert_cooldown": 30,
        "max_alerts_per_type": 6,
        "max_total_alerts": 75,
    },
    "test": {
        "port_scan_count": 5,
        "port_scan_window": 30,
        "stealth_scan_count": 3,
        "syn_flood_rate": 10,
        "udp_flood_rate": 20,
        "icmp_flood_rate": 10,
        "flood_window": 5,
        "ddos_sources": 5,
        "ddos_window": 10,
        "dns_query_length": 50,
        "dns_subdomain_count": 5,
        "dns_query_rate": 20,
        "brute_force_attempts": 4,
        "brute_force_window": 60,
        "beacon_regularity": 0.25,
        "beacon_min_callbacks": 4,
        "session_injection_count": 2,
        "session_injection_window": 20,
        "exfil_size_bytes": 200 * 1024,
        "exfil_window": 60,
        "alert_cooldown": 10,
        "max_alerts_per_type": 10,
        "max_total_alerts": 100,
    },
}


class NetworkSecurityMonitor:
    """Real-time network attack detection engine"""
    
    def __init__(self, alert_callback: Optional[Callable] = None):
        self.alert_callback = alert_callback
        self.debug = DETECTION_DEBUG
        self.default_profile = self._normalize_profile(DETECTION_PROFILE)
        self.profile = self.default_profile
        
        # ========== TRACKING DATA STRUCTURES ==========
        # Port scan detection
        self.port_scan_tracker = defaultdict(lambda: {'ports': set(), 'timestamps': [], 'flags': defaultdict(int)})
        
        # Flood detection (per source IP)
        self.packet_rate = defaultdict(lambda: {'timestamps': [], 'bytes': 0})
        
        # Per-destination flood detection
        self.dst_packet_rate = defaultdict(lambda: {'sources': set(), 'timestamps': [], 'bytes': 0})
        
        # DNS tracking
        self.dns_queries = defaultdict(list)
        self.dns_query_lengths = defaultdict(list)
        
        # Connection tracking
        self.tcp_connections = defaultdict(lambda: {'syn': 0, 'syn_ack': 0, 'ack': 0, 'rst': 0, 'fin': 0})
        
        # ARP tracking
        self.arp_table = {}  # IP -> MAC mapping
        self.arp_requests = defaultdict(list)  # Track ARP request patterns
        
        # Application layer patterns
        self.http_requests = defaultdict(list)
        self.failed_logins = defaultdict(lambda: {'count': 0, 'timestamps': []})
        
        # Beacon detection
        self.beacon_tracker = defaultdict(list)  # Track periodic connections
        
        # Session hijacking detection
        self.established_sessions = {}  # Track established TCP sessions (key: src:sport-dst:dport)
        self.injection_attempts = defaultdict(lambda: {'count': 0, 'timestamps': []})
        
        # Data exfiltration tracking
        self.outbound_transfers = defaultdict(lambda: {'bytes': 0, 'timestamps': [], 'first_seen': 0})
        
        # Alert history (prevent duplicates)
        self.alert_history = {}
        self.alert_counts = defaultdict(int)
        
        # Packet statistics
        self.packet_stats = {
            'total': 0, 'tcp': 0, 'udp': 0, 'icmp': 0, 'dns': 0, 
            'http': 0, 'https': 0, 'arp': 0, 'other': 0,
            'malicious': 0, 'suspicious': 0
        }
        
        # Attack logs
        self.attack_logs = []
        
        # ========== DETECTION THRESHOLDS (profile-based) ==========
        self.thresholds = self._get_profile_thresholds(self.profile)
        
        logger.info("[Security] NetworkSecurityMonitor initialized with advanced detection")
        if self.debug:
            logger.debug("[Security] NetworkSecurityMonitor initialized - Ready to detect attacks!")

    def _normalize_profile(self, profile: Optional[str]) -> str:
        if not profile:
            return "balanced"

        normalized = str(profile).strip().lower()
        return normalized if normalized in PROFILE_THRESHOLDS else "balanced"

    def _get_profile_thresholds(self, profile: str) -> Dict[str, Any]:
        base = PROFILE_THRESHOLDS.get(profile, PROFILE_THRESHOLDS["balanced"])
        return dict(base)

    def set_profile(self, profile: str) -> str:
        """Apply a predefined detection profile."""
        normalized = self._normalize_profile(profile)
        self.profile = normalized
        self.thresholds = self._get_profile_thresholds(normalized)
        logger.info(f"[Security] Detection profile set to {normalized}")
        return normalized

    def get_profile(self) -> str:
        return self.profile

    def get_thresholds(self) -> Dict[str, Any]:
        return dict(self.thresholds)

    def _debug_log(self, message: str):
        if self.debug:
            logger.debug(message)

    def update_thresholds(self, overrides: Dict[str, Any]) -> Dict[str, Any]:
        """Update thresholds with validated overrides."""
        if not overrides:
            return self.get_thresholds()

        for key, value in overrides.items():
            if key in self.thresholds and isinstance(value, (int, float)):
                self.thresholds[key] = value

        logger.info("[Security] Detection thresholds updated")
        return self.get_thresholds()

    def reset_counters(self):
        """Reset all alert counters and history - call when clearing alerts"""
        self.alert_history = {}
        self.alert_counts = defaultdict(int)
        self.connection_tracker = {}
        self.port_scan_tracker = {}
        self.syn_tracker = {}
        self.login_attempts = {}
        self.beacon_tracker = {}
        self.packet_stats = {
            'total': 0, 'tcp': 0, 'udp': 0, 'icmp': 0, 'dns': 0, 
            'http': 0, 'https': 0, 'arp': 0, 'other': 0,
            'malicious': 0, 'suspicious': 0
        }
        logger.info("[Security] NetworkSecurityMonitor counters reset")
    
    def enable_test_mode(self):
        """Enable test mode with lower thresholds for easier attack detection during testing"""
        self.set_profile("test")
        logger.info("[TEST] Detection profile set to test")
    
    def disable_test_mode(self):
        """Disable test mode and restore production thresholds"""
        self.set_profile(self.default_profile)
        logger.info("[Security] Detection profile restored to default")

    def set_alert_callback(self, callback: Callable):
        """Set callback function for real-time alerts"""
        self.alert_callback = callback
        
    def analyze_packet(self, packet: Dict) -> List[Dict]:
        """
        Main analysis entry point - analyzes packet and returns any detected threats
        """
        alerts = []
        
        try:
            # Update statistics
            self._update_stats(packet)
            
            src_ip = packet.get('src_ip')
            dst_ip = packet.get('dst_ip')
            src_port = packet.get('src_port', 0)
            dst_port = packet.get('dst_port', 0)
            protocol = packet.get('protocol', '').upper()
            payload = packet.get('payload', '') or packet.get('raw_data', '')
            payload_size = len(str(payload)) if payload else 0
            timestamp = time.time()
            tcp_flags = packet.get('tcp_flags', 0)
            
            # DEBUG: Log all TCP packets with their flags
            if protocol == 'TCP':
                self._debug_log(f"[Security] TCP: {src_ip}:{src_port} -> {dst_ip}:{dst_port} flags={tcp_flags}")
            
            # Convert tcp_flags to int if string
            if isinstance(tcp_flags, str):
                try:
                    tcp_flags = int(tcp_flags)
                except:
                    tcp_flags = 0
            
            # Skip if no source IP
            if not src_ip:
                return alerts
            
            # Track if a SPECIFIC attack was detected (to prevent flood overlap)
            specific_attack_found = False
            
            # ========== SESSION HIJACKING DETECTION (HIGH PRIORITY) ==========
            if protocol == 'TCP' and payload:
                hijack_alert = self._detect_session_hijacking(src_ip, dst_ip, src_port, dst_port, tcp_flags, payload, timestamp)
                if hijack_alert:
                    alerts.append(hijack_alert)
                    specific_attack_found = True
            
            # ========== DATA EXFILTRATION DETECTION (HIGH PRIORITY) ==========
            if payload_size > 100:
                exfil_alert = self._detect_data_exfiltration(src_ip, dst_ip, payload_size, timestamp)
                if exfil_alert:
                    alerts.append(exfil_alert)
                    specific_attack_found = True
            
            # ========== PORT SCAN DETECTION ==========
            if protocol == 'TCP':
                scan_alert = self._detect_port_scan(src_ip, dst_ip, dst_port, tcp_flags, timestamp)
                if scan_alert:
                    alerts.append(scan_alert)
                    specific_attack_found = True
            
            # ========== DNS TUNNELING DETECTION ==========
            if protocol == 'DNS' or dst_port == 53:
                dns_alert = self._detect_dns_tunneling(src_ip, payload, timestamp)
                if dns_alert:
                    alerts.append(dns_alert)
                    specific_attack_found = True
            
            # ========== ARP SPOOFING DETECTION ==========
            if protocol == 'ARP' or packet.get('arp_op'):
                arp_alert = self._detect_arp_spoofing(packet)
                if arp_alert:
                    alerts.append(arp_alert)
                    specific_attack_found = True
            
            # ========== BRUTE FORCE DETECTION ==========
            if dst_port in [22, 23, 3389, 21, 25, 110, 143, 445, 3306, 5432]:
                bf_alert = self._detect_brute_force(src_ip, dst_ip, dst_port, timestamp)
                if bf_alert:
                    alerts.append(bf_alert)
                    specific_attack_found = True
            
            # ========== APPLICATION LAYER ATTACK DETECTION ==========
            if dst_port in [80, 443, 8080, 8443] or protocol in ['HTTP', 'HTTPS']:
                app_alerts = self._detect_application_attacks(src_ip, payload, dst_port, timestamp)
                if app_alerts:
                    alerts.extend(app_alerts)
                    specific_attack_found = True
            
            # ========== COVERT CHANNEL / BEACON DETECTION ==========
            if protocol == 'ICMP' or (protocol == 'TCP' and dst_port in [80, 443]):
                covert_alert = self._detect_covert_channel(src_ip, dst_ip, protocol, payload, timestamp)
                if covert_alert:
                    alerts.append(covert_alert)
                    specific_attack_found = True
            
            # ========== MALFORMED PACKET DETECTION ==========
            malformed_alert = self._detect_malformed_packets(packet, tcp_flags)
            if malformed_alert:
                alerts.append(malformed_alert)
                specific_attack_found = True
            
            # ========== IP SPOOFING DETECTION ==========
            spoof_alert = self._detect_ip_spoofing(src_ip, packet)
            if spoof_alert:
                alerts.append(spoof_alert)
                specific_attack_found = True
            
            # ========== FLOOD/DOS DETECTION (only if no specific attack found) ==========
            # This prevents generic flood alerts from overlapping with specific attacks
            if not specific_attack_found:
                flood_alert = self._detect_flood(src_ip, dst_ip, protocol, payload_size, timestamp)
                if flood_alert:
                    alerts.append(flood_alert)
                
                # ========== DDOS DETECTION (Distributed) ==========
                ddos_alert = self._detect_ddos(src_ip, dst_ip, timestamp)
                if ddos_alert:
                    alerts.append(ddos_alert)
            
            # Process and broadcast alerts
            for alert in alerts:
                if alert:
                    self._process_alert(alert, packet)
            
        except Exception as e:
            logger.error(f"Error analyzing packet: {type(e).__name__}: {str(e)}", exc_info=True)
        
        return [a for a in alerts if a is not None]
    
    # ========== DETECTION METHODS ==========
    
    def _detect_port_scan(self, src_ip: str, dst_ip: str, dst_port: int, tcp_flags: int, timestamp: float) -> Optional[Dict]:
        """Detect various port scanning techniques"""
        
        if not dst_port:
            return None
        
        tracker = self.port_scan_tracker[src_ip]
        window = self.thresholds['port_scan_window']
        
        # Clean old entries
        tracker['timestamps'] = [t for t in tracker['timestamps'] if timestamp - t < window]
        
        # Track this connection
        tracker['ports'].add(dst_port)
        tracker['timestamps'].append(timestamp)
        
        # Track flag patterns
        flag_name = self._get_flag_name(tcp_flags)
        tracker['flags'][flag_name] += 1
        
        # Count unique ports in window
        port_count = len(tracker['ports'])
        
        # Debug output - show progress toward detection
        self._debug_log(
            f"[Security] Scan tracker {src_ip}: {port_count}/{self.thresholds['port_scan_count']} ports, flags={dict(tracker['flags'])}"
        )
        
        # Detect different scan types
        scan_type = None
        severity = 'medium'
        
        # NULL Scan (no flags)
        if tcp_flags == 0 and tracker['flags']['NULL'] >= 3:
            scan_type = 'NULL Scan'
            severity = 'high'
            
        # XMAS Scan (FIN + PSH + URG = 41)
        elif tcp_flags == 41 or (tcp_flags & 41) == 41:
            if tracker['flags'].get('XMAS', 0) >= 3 or tracker['flags'].get(f'FLAGS-{tcp_flags}', 0) >= 3:
                scan_type = 'XMAS Scan'
                severity = 'high'
        
        # FIN Scan (just FIN = 1)
        elif tcp_flags == 1 and tracker['flags']['FIN'] >= 3:
            scan_type = 'FIN Scan'
            severity = 'high'
            
        # ACK Scan (just ACK = 16) - firewall mapping
        elif tcp_flags == 16 and tracker['flags']['ACK'] >= self.thresholds['stealth_scan_count'] and port_count >= 5:
            scan_type = 'ACK Scan (Firewall Probe)'
            severity = 'medium'
        
        # SYN Scan (most common) - SYN flag is 2
        elif port_count >= self.thresholds['port_scan_count']:
            scan_type = 'SYN Port Scan'
            severity = 'high'
        
        if scan_type:
            logger.warning(f"[ALERT] {scan_type} detected from {src_ip}")
            
            # Reset tracker after detection
            self.port_scan_tracker[src_ip] = {'ports': set(), 'timestamps': [], 'flags': defaultdict(int)}
            
            return self._create_alert(
                title=f'{scan_type} Detected',
                severity=severity,
                description=f'Detected {scan_type.lower()} from {src_ip}. Scanned {port_count} unique ports.',
                source=src_ip,
                attack_type='port_scan',
                evidence={
                    'ports_scanned': port_count,
                    'scan_type': scan_type,
                    'flag_distribution': dict(tracker['flags'])
                }
            )
        
        return None
    
    def _detect_flood(self, src_ip: str, dst_ip: str, protocol: str, packet_size: int, timestamp: float) -> Optional[Dict]:
        """Detect flood-based DoS attacks"""
        
        tracker = self.packet_rate[src_ip]
        window = self.thresholds['flood_window']
        
        # Clean old entries
        tracker['timestamps'] = [t for t in tracker['timestamps'] if timestamp - t < window]
        tracker['timestamps'].append(timestamp)
        tracker['bytes'] += packet_size
        
        rate = len(tracker['timestamps']) / window if window > 0 else 0  # packets per second
        
        # Debug output for high rates
        if rate > 10:
            self._debug_log(f"[Security] Flood rate {src_ip} -> {dst_ip}: {rate:.1f} pps ({protocol})")
        
        flood_type = None
        severity = 'critical'
        
        if protocol == 'TCP' and rate > self.thresholds['syn_flood_rate']:
            flood_type = 'SYN Flood'
        elif protocol == 'UDP' and rate > self.thresholds['udp_flood_rate']:
            flood_type = 'UDP Flood'
        elif protocol == 'ICMP' and rate > self.thresholds['icmp_flood_rate']:
            flood_type = 'ICMP Flood (Ping Flood)'
            severity = 'high'
        
        if flood_type:
            logger.warning(f"[ALERT] {flood_type} detected from {src_ip}")
            
            return self._create_alert(
                title=f'{flood_type} Attack Detected',
                severity=severity,
                description=f'Detected {flood_type} from {src_ip} targeting {dst_ip}. Rate: {rate:.1f} pps',
                source=src_ip,
                attack_type='dos_flood',
                evidence={
                    'packets_per_second': round(rate, 2),
                    'total_bytes': tracker['bytes'],
                    'target': dst_ip,
                    'protocol': protocol
                }
            )
        
        return None
    
    def _detect_ddos(self, src_ip: str, dst_ip: str, timestamp: float) -> Optional[Dict]:
        """Detect distributed denial of service (multiple sources)"""
        
        if not dst_ip:
            return None
            
        tracker = self.dst_packet_rate[dst_ip]
        window = self.thresholds['ddos_window']
        
        # Clean old entries
        tracker['timestamps'] = [t for t in tracker['timestamps'] if timestamp - t < window]
        tracker['timestamps'].append(timestamp)
        tracker['sources'].add(src_ip)
        
        # Check for DDoS pattern
        unique_sources = len(tracker['sources'])
        
        if unique_sources >= self.thresholds['ddos_sources']:
            logger.warning(f"[ALERT] DDoS detected on {dst_ip} from {unique_sources} sources")
            
            # Reset tracker
            sources_list = list(tracker['sources'])[:10]
            self.dst_packet_rate[dst_ip] = {'sources': set(), 'timestamps': [], 'bytes': 0}
            
            return self._create_alert(
                title='DDoS Attack Detected',
                severity='critical',
                description=f'Distributed attack on {dst_ip} from {unique_sources} unique sources',
                source=f'Multiple ({unique_sources} sources)',
                attack_type='ddos',
                evidence={
                    'target': dst_ip,
                    'unique_sources': unique_sources,
                    'sources_sample': sources_list
                }
            )
        
        return None
    
    def _detect_dns_tunneling(self, src_ip: str, payload: str, timestamp: float) -> Optional[Dict]:
        """Detect DNS tunneling and exfiltration"""
        
        if not payload:
            return None
        
        payload_str = str(payload)
        suspicious_score = 0
        evidence = {}
        
        # Check query length
        if len(payload_str) > self.thresholds['dns_query_length']:
            suspicious_score += 2
            evidence['long_query'] = len(payload_str)
        
        # Check subdomain count
        subdomain_count = payload_str.count('.')
        if subdomain_count > self.thresholds['dns_subdomain_count']:
            suspicious_score += 2
            evidence['subdomain_count'] = subdomain_count
        
        # Check for encoded data patterns
        if re.search(r'[a-zA-Z0-9+/]{20,}', payload_str):
            suspicious_score += 2
            evidence['base64_pattern'] = True
        
        # Check for hex-encoded data
        if re.search(r'[0-9a-fA-F]{32,}', payload_str):
            suspicious_score += 2
            evidence['hex_pattern'] = True
        
        # Track query rate
        self.dns_queries[src_ip].append(timestamp)
        recent_queries = [t for t in self.dns_queries[src_ip] if timestamp - t < 60]
        self.dns_queries[src_ip] = recent_queries
        
        if len(recent_queries) > self.thresholds['dns_query_rate']:
            suspicious_score += 1
            evidence['high_query_rate'] = len(recent_queries)
        
        if suspicious_score >= 3:
            logger.warning(f"[ALERT] DNS tunneling detected from {src_ip}")
            
            return self._create_alert(
                title='DNS Tunneling Detected',
                severity='high',
                description=f'Suspicious DNS activity from {src_ip}. Possible data exfiltration.',
                source=src_ip,
                attack_type='dns_tunneling',
                evidence=evidence
            )
        
        return None
    
    def _detect_arp_spoofing(self, packet: Dict) -> Optional[Dict]:
        """Detect ARP spoofing/poisoning attempts"""
        
        arp_src_ip = packet.get('arp_src_ip') or packet.get('src_ip')
        arp_src_mac = packet.get('arp_src_mac') or packet.get('src_mac')
        arp_op = packet.get('arp_op', 0)
        
        if not arp_src_ip or not arp_src_mac:
            return None
        
        # Track ARP requests for gratuitous ARP detection
        if arp_op == 1:  # ARP Request
            self.arp_requests[arp_src_ip].append(time.time())
            recent = [t for t in self.arp_requests[arp_src_ip] if time.time() - t < 60]
            self.arp_requests[arp_src_ip] = recent
            
            # Detect ARP request flood
            if len(recent) > 30:  # Lowered threshold
                return self._create_alert(
                    title='ARP Request Flood',
                    severity='medium',
                    description=f'Excessive ARP requests from {arp_src_ip} ({arp_src_mac})',
                    source=arp_src_ip,
                    attack_type='arp_flood',
                    evidence={'request_count': len(recent)}
                )
        
        # Detect MAC change for same IP
        if arp_src_ip in self.arp_table:
            old_mac = self.arp_table[arp_src_ip]
            if old_mac != arp_src_mac:
                self.arp_table[arp_src_ip] = arp_src_mac
                logger.warning(f"[ALERT] ARP spoofing detected: {arp_src_ip}: {old_mac} -> {arp_src_mac}")
                
                return self._create_alert(
                    title='ARP Spoofing Detected',
                    severity='critical',
                    description=f'MAC address change for {arp_src_ip}: {old_mac} -> {arp_src_mac}',
                    source=arp_src_ip,
                    attack_type='arp_spoofing',
                    evidence={
                        'ip': arp_src_ip,
                        'old_mac': old_mac,
                        'new_mac': arp_src_mac
                    }
                )
        else:
            self.arp_table[arp_src_ip] = arp_src_mac
        
        return None
    
    def _detect_brute_force(self, src_ip: str, dst_ip: str, dst_port: int, timestamp: float) -> Optional[Dict]:
        """Detect brute force login attempts"""
        
        key = f"{src_ip}->{dst_ip}:{dst_port}"
        tracker = self.failed_logins[key]
        window = self.thresholds['brute_force_window']
        
        # Clean old entries
        tracker['timestamps'] = [t for t in tracker['timestamps'] if timestamp - t < window]
        tracker['timestamps'].append(timestamp)
        tracker['count'] = len(tracker['timestamps'])
        
        # Debug output
        if tracker['count'] >= 3:
            self._debug_log(f"[Security] Brute force {src_ip} -> {dst_ip}:{dst_port}: {tracker['count']} attempts")
        
        if tracker['count'] >= self.thresholds['brute_force_attempts']:
            service_map = {
                22: 'SSH', 23: 'Telnet', 21: 'FTP', 3389: 'RDP',
                25: 'SMTP', 110: 'POP3', 143: 'IMAP', 445: 'SMB',
                3306: 'MySQL', 5432: 'PostgreSQL'
            }
            service = service_map.get(dst_port, f'Port {dst_port}')
            
            logger.warning(f"[ALERT] Brute force on {service} detected from {src_ip}")
            
            # Reset tracker
            attempt_count = tracker['count']
            self.failed_logins[key] = {'count': 0, 'timestamps': []}
            
            return self._create_alert(
                title='Brute Force Attack Detected',
                severity='high',
                description=f'Multiple {service} connection attempts from {src_ip} to {dst_ip}',
                source=src_ip,
                attack_type='brute_force',
                evidence={
                    'service': service,
                    'target': dst_ip,
                    'port': dst_port,
                    'attempts': attempt_count
                }
            )
        
        return None
    
    def _detect_application_attacks(self, src_ip: str, payload: str, dst_port: int, timestamp: float) -> List[Dict]:
        """Detect application layer attacks (SQLi, XSS, Command Injection)"""
        
        alerts = []
        if not payload:
            return alerts
        
        payload_lower = str(payload).lower()
        
        # SQL Injection patterns
        sqli_patterns = [
            r"('|\")?\s*(or|and)\s+\d+\s*=\s*\d+",  # ' OR 1=1
            r"('\s*or\s*'[^']*'\s*=\s*'[^']*')",     # ' OR '1'='1'
            r"('|\")\s*(or|and)\s+.*\s*--",          # ' OR ... --
            r"(union\s+select|select\s+.*\s+from)",
            r"(insert\s+into|update\s+.*\s+set|delete\s+from)",
            r"(drop\s+table|drop\s+database)",
            r"(exec\s*\(|execute\s*\()",
            r"(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)",
            r"(extractvalue|updatexml|load_file)",
            r"(having\s+\d+\s*=\s*\d+)",             # HAVING 1=1
            r"(order\s+by\s+\d+)",                   # ORDER BY 1
            r"('\s*;\s*--)",                         # '; --
        ]
        
        for pattern in sqli_patterns:
            if re.search(pattern, payload_lower):
                logger.warning(f"[ALERT] SQL injection detected from {src_ip}")
                alerts.append(self._create_alert(
                    title='SQL Injection Attempt',
                    severity='critical',
                    description=f'SQL injection pattern detected from {src_ip}',
                    source=src_ip,
                    attack_type='sql_injection',
                    evidence={'pattern': pattern, 'port': dst_port}
                ))
                break
        
        # XSS patterns
        xss_patterns = [
            r"<script[^>]*>",
            r"javascript\s*:",
            r"on(load|error|click|mouseover|focus)\s*=",
            r"<(img|svg|body|iframe)[^>]+(onerror|onload|src)\s*=",
            r"document\.(cookie|location|write)",
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, payload_lower):
                logger.warning(f"[ALERT] XSS attack detected from {src_ip}")
                alerts.append(self._create_alert(
                    title='XSS Attack Attempt',
                    severity='high',
                    description=f'Cross-site scripting pattern detected from {src_ip}',
                    source=src_ip,
                    attack_type='xss',
                    evidence={'pattern': pattern, 'port': dst_port}
                ))
                break
        
        # Command Injection patterns
        cmd_patterns = [
            r"[;&|]\s*(cat|ls|whoami|id|pwd|uname)",
            r"\$\((cat|ls|whoami|id)",
            r"`(cat|ls|whoami|id|nc|wget|curl)`",
            r"(;|&&|\|\|)\s*(rm|shutdown|reboot|wget|curl|nc)",
            r"/etc/(passwd|shadow|hosts)",
            r"(powershell|cmd\.exe|/bin/(sh|bash))",
        ]
        
        for pattern in cmd_patterns:
            if re.search(pattern, payload_lower):
                logger.warning(f"[ALERT] Command injection detected from {src_ip}")
                alerts.append(self._create_alert(
                    title='Command Injection Attempt',
                    severity='critical',
                    description=f'Command injection pattern detected from {src_ip}',
                    source=src_ip,
                    attack_type='command_injection',
                    evidence={'pattern': pattern, 'port': dst_port}
                ))
                break
        
        # Path Traversal patterns
        traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e[%/\\]",
            r"(etc/passwd|etc/shadow|windows/system32)",
        ]
        
        for pattern in traversal_patterns:
            if re.search(pattern, payload_lower):
                logger.warning(f"[ALERT] Path traversal detected from {src_ip}")
                alerts.append(self._create_alert(
                    title='Path Traversal Attempt',
                    severity='high',
                    description=f'Path traversal pattern detected from {src_ip}',
                    source=src_ip,
                    attack_type='path_traversal',
                    evidence={'pattern': pattern, 'port': dst_port}
                ))
                break
        
        return alerts
    
    def _detect_malformed_packets(self, packet: Dict, tcp_flags: int) -> Optional[Dict]:
        """Detect malformed or suspicious packet structures"""
        
        # Check for invalid TCP flag combinations
        if packet.get('protocol', '').upper() == 'TCP':
            # SYN + FIN (invalid)
            if tcp_flags & 3 == 3:  # SYN=2, FIN=1
                return self._create_alert(
                    title='Malformed Packet (SYN+FIN)',
                    severity='medium',
                    description=f'Invalid TCP flags from {packet.get("src_ip")}',
                    source=packet.get('src_ip'),
                    attack_type='malformed_packet',
                    evidence={'flags': tcp_flags, 'issue': 'SYN and FIN both set'}
                )
            
            # All flags set (XMAS-like)
            if tcp_flags == 255 or tcp_flags == 63:
                return self._create_alert(
                    title='Suspicious TCP Flags',
                    severity='medium',
                    description=f'Unusual TCP flag combination from {packet.get("src_ip")}',
                    source=packet.get('src_ip'),
                    attack_type='malformed_packet',
                    evidence={'flags': tcp_flags, 'issue': 'All flags set'}
                )
        
        # Check for LAND attack (src == dst)
        if packet.get('src_ip') == packet.get('dst_ip') and packet.get('src_ip'):
            # Skip localhost
            if not packet.get('src_ip', '').startswith('127.'):
                logger.warning(f"[ALERT] LAND attack detected from {packet.get('src_ip')}")
                return self._create_alert(
                    title='LAND Attack Detected',
                    severity='high',
                    description=f'Packet with identical source and destination: {packet.get("src_ip")}',
                    source=packet.get('src_ip'),
                    attack_type='land_attack',
                    evidence={'ip': packet.get('src_ip')}
                )
        
        return None
    
    def _detect_covert_channel(self, src_ip: str, dst_ip: str, protocol: str, payload: str, timestamp: float) -> Optional[Dict]:
        """Detect covert channels and C2 beaconing"""
        
        key = f"{src_ip}->{dst_ip}"
        self.beacon_tracker[key].append(timestamp)
        
        # Keep last 20 connection times
        if len(self.beacon_tracker[key]) > 20:
            self.beacon_tracker[key] = self.beacon_tracker[key][-20:]
        
        timestamps = self.beacon_tracker[key]
        
        if len(timestamps) >= self.thresholds['beacon_min_callbacks']:
            # Calculate intervals
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            
            if intervals:
                mean_interval = sum(intervals) / len(intervals)
                
                if mean_interval > 0:
                    # Calculate standard deviation
                    variance = sum((i - mean_interval) ** 2 for i in intervals) / len(intervals)
                    std_dev = variance ** 0.5
                    
                    # Check for regular beaconing (low variance)
                    regularity = std_dev / mean_interval if mean_interval > 0 else 1
                    
                    if regularity < self.thresholds['beacon_regularity'] and mean_interval > 1:
                        logger.warning(f"[ALERT] C2 beacon detected: {src_ip} -> {dst_ip}")
                        self.beacon_tracker[key] = []  # Reset
                        
                        return self._create_alert(
                            title='C2 Beacon Pattern Detected',
                            severity='critical',
                            description=f'Regular callback pattern from {src_ip} to {dst_ip} (interval: {mean_interval:.1f}s)',
                            source=src_ip,
                            attack_type='c2_beacon',
                            evidence={
                                'target': dst_ip,
                                'mean_interval': round(mean_interval, 2),
                                'regularity': round(regularity, 3),
                                'callbacks': len(timestamps)
                            }
                        )
        
        # Check ICMP payload for covert data
        if protocol == 'ICMP' and payload:
            payload_str = str(payload)
            
            # Check for unusual ICMP payload
            if len(payload_str) > 64:  # Lowered threshold
                logger.warning(f"[ALERT] ICMP covert channel suspected from {src_ip}")
                return self._create_alert(
                    title='ICMP Covert Channel Suspected',
                    severity='high',
                    description=f'Unusually large ICMP payload from {src_ip}',
                    source=src_ip,
                    attack_type='covert_channel',
                    evidence={
                        'payload_size': len(payload_str),
                        'destination': dst_ip
                    }
                )
        
        return None
    
    def _detect_ip_spoofing(self, src_ip: str, packet: Dict) -> Optional[Dict]:
        """Detect IP spoofing attempts"""
        
        if not src_ip:
            return None
        
        # Check for impossible/spoofed source IPs
        suspicious = False
        reason = None
        
        # Broadcast as source
        if src_ip == '255.255.255.255':
            suspicious = True
            reason = 'Broadcast address as source'
        
        # Multicast as source (224.0.0.0 - 239.255.255.255)
        elif src_ip.startswith('224.') or src_ip.startswith('239.'):
            suspicious = True
            reason = 'Multicast address as source'
        
        # 0.0.0.0 as source (outside of DHCP)
        elif src_ip == '0.0.0.0' and packet.get('dst_port') not in [67, 68]:
            suspicious = True
            reason = 'Null address as source'
        
        # Check for source IPs outside local network (10.48.58.0/24)
        # IPs like 10.0.0.1, 172.16.x.x, 192.168.x.x from other subnets are suspicious
        elif not src_ip.startswith('10.48.58.'):
            # Exception: loopback (127.x.x.x) is also suspicious on remote interface
            if src_ip.startswith('127.'):
                suspicious = True
                reason = 'Loopback address as remote source'
            # Private addresses from wrong subnets
            elif (src_ip.startswith('10.') or src_ip.startswith('172.16.') or 
                  src_ip.startswith('172.17.') or src_ip.startswith('172.18.') or
                  src_ip.startswith('172.19.') or src_ip.startswith('172.20.') or
                  src_ip.startswith('172.21.') or src_ip.startswith('172.22.') or
                  src_ip.startswith('172.23.') or src_ip.startswith('172.24.') or
                  src_ip.startswith('172.25.') or src_ip.startswith('172.26.') or
                  src_ip.startswith('172.27.') or src_ip.startswith('172.28.') or
                  src_ip.startswith('172.29.') or src_ip.startswith('172.30.') or
                  src_ip.startswith('172.31.') or src_ip.startswith('192.168.')):
                suspicious = True
                reason = f'Private IP from non-local subnet: {src_ip}'
        
        if suspicious:
            logger.warning(f"[ALERT] IP spoofing detected: {src_ip}")
            return self._create_alert(
                title='IP Spoofing Detected',
                severity='high',
                description=f'Spoofed source IP detected: {src_ip} - {reason}',
                source=src_ip,
                attack_type='ip_spoofing',
                evidence={
                    'spoofed_ip': src_ip,
                    'reason': reason
                }
            )
        
        return None
    
    def _detect_session_hijacking(self, src_ip: str, dst_ip: str, src_port: int, 
                                   dst_port: int, tcp_flags: int, payload: str, 
                                   timestamp: float) -> Optional[Dict]:
        """Detect TCP session hijacking attempts - out-of-sequence injection"""
        
        # Only interested in packets with data (PSH-ACK typically)
        if not payload or len(payload) < 10:
            return None
            
        # PSH-ACK flag = 24 (0x18), or just ACK with data
        has_data = tcp_flags in [24, 16, 25, 17]  # PSH-ACK, ACK, PSH-ACK-FIN, etc.
        
        if not has_data:
            return None
        
        session_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        reverse_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
        
        # Track injection attempts - packets with data to non-established sessions
        # or to common targets (like HTTP) without proper handshake
        tracker = self.injection_attempts[src_ip]
        window = self.thresholds['session_injection_window']
        
        # Clean old entries
        tracker['timestamps'] = [t for t in tracker['timestamps'] if timestamp - t < window]
        
        # Check if this looks like an injection (data packet without established session)
        # For simplicity, detect rapid data packets to same destination
        if session_key not in self.established_sessions and reverse_key not in self.established_sessions:
            # Check for suspicious patterns in payload
            suspicious_patterns = [
                b'hijack',
                b'GET /admin',
                b'POST /admin',
                b'Authorization:',
                b'Cookie:',
                b'session',
                b'token'
            ]
            
            payload_bytes = payload.encode() if isinstance(payload, str) else payload
            is_suspicious = any(pattern in payload_bytes.lower() if isinstance(payload_bytes, bytes) else pattern.decode() in payload_bytes.lower() 
                              for pattern in suspicious_patterns)
            
            if is_suspicious or len(tracker['timestamps']) > 3:
                tracker['count'] += 1
                tracker['timestamps'].append(timestamp)
                
                if tracker['count'] >= self.thresholds['session_injection_count']:
                    logger.warning(f"[ALERT] Session hijacking attempt from {src_ip}")
                    # Reset counter
                    self.injection_attempts[src_ip] = {'count': 0, 'timestamps': []}
                    
                    return self._create_alert(
                        title='Session Hijacking Attempt Detected',
                        severity='critical',
                        description=f'TCP session injection detected from {src_ip} targeting {dst_ip}:{dst_port}. Suspicious data packets without established session.',
                        source=src_ip,
                        attack_type='session_hijack',
                        evidence={
                            'target': f'{dst_ip}:{dst_port}',
                            'injection_count': tracker['count'],
                            'payload_preview': str(payload)[:100] if payload else ''
                        }
                    )
        
        return None
    
    def _detect_data_exfiltration(self, src_ip: str, dst_ip: str, payload_size: int, 
                                   timestamp: float) -> Optional[Dict]:
        """Detect potential data exfiltration - large outbound transfers"""
        
        if payload_size < 100:  # Skip small packets
            return None
        
        # Track outbound transfers (assume local IPs are internal)
        is_outbound = self._is_private_ip(src_ip) and not self._is_private_ip(dst_ip)
        
        if not is_outbound:
            return None
        
        tracker = self.outbound_transfers[f"{src_ip}->{dst_ip}"]
        window = self.thresholds['exfil_window']
        
        # Initialize first seen
        if tracker['first_seen'] == 0:
            tracker['first_seen'] = timestamp
        
        # Clean old entries
        tracker['timestamps'] = [t for t in tracker['timestamps'] if timestamp - t < window]
        
        # Reset if window expired
        if timestamp - tracker['first_seen'] > window:
            tracker['bytes'] = 0
            tracker['first_seen'] = timestamp
        
        tracker['bytes'] += payload_size
        tracker['timestamps'].append(timestamp)
        
        # Check threshold
        if tracker['bytes'] >= self.thresholds['exfil_size_bytes']:
            logger.warning(f"[ALERT] Data exfiltration detected from {src_ip} to {dst_ip}")
            
            transfer_size = tracker['bytes']
            # Reset tracker
            self.outbound_transfers[f"{src_ip}->{dst_ip}"] = {'bytes': 0, 'timestamps': [], 'first_seen': 0}
            
            return self._create_alert(
                title='Potential Data Exfiltration Detected',
                severity='critical',
                description=f'Large data transfer ({transfer_size / 1024:.1f} KB) from {src_ip} to external IP {dst_ip}',
                source=src_ip,
                attack_type='data_exfiltration',
                evidence={
                    'destination': dst_ip,
                    'bytes_transferred': transfer_size,
                    'duration_seconds': window,
                    'transfer_rate_kbps': round(transfer_size / 1024 / window, 2)
                }
            )
        
        return None
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal"""
        if not ip:
            return False
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            first = int(parts[0])
            second = int(parts[1])
            
            # 10.x.x.x
            if first == 10:
                return True
            # 172.16.x.x - 172.31.x.x
            if first == 172 and 16 <= second <= 31:
                return True
            # 192.168.x.x
            if first == 192 and second == 168:
                return True
            # Loopback
            if first == 127:
                return True
            return False
        except:
            return False
    
    # ========== HELPER METHODS ==========
    
    def _get_flag_name(self, flags: int) -> str:
        """Convert TCP flags to human-readable name"""
        if flags == 0:
            return 'NULL'
        elif flags == 2:
            return 'SYN'
        elif flags == 18:
            return 'SYN-ACK'
        elif flags == 16:
            return 'ACK'
        elif flags == 1:
            return 'FIN'
        elif flags == 4:
            return 'RST'
        elif flags == 41:
            return 'XMAS'
        elif flags == 24:
            return 'PSH-ACK'
        else:
            return f'FLAGS-{flags}'
    
    def _create_alert(self, title: str, severity: str, description: str, source: str, 
                      attack_type: str, evidence: Dict = None) -> Optional[Dict]:
        """Create alert if not in cooldown and within limits"""
        
        current_time = time.time()
        
        # ========== RATE LIMITING ==========
        # 1. Check per-type limit (max 3 alerts per attack type)
        if self.alert_counts.get(attack_type, 0) >= self.thresholds.get('max_alerts_per_type', 3):
            return None
        
        # 2. Check total alert limit
        total_alerts = sum(self.alert_counts.values())
        if total_alerts >= self.thresholds.get('max_total_alerts', 20):
            return None
        
        # 3. Check cooldown - now uses attack_type instead of title-source
        # This prevents the same TYPE of attack from spamming, regardless of source
        alert_key = attack_type  # Simplified to attack type only
        
        if alert_key in self.alert_history:
            last_time = self.alert_history[alert_key]
            if current_time - last_time < self.thresholds['alert_cooldown']:
                return None
        
        # Update history
        self.alert_history[alert_key] = current_time
        self.alert_counts[attack_type] += 1
        
        # Update stats
        if severity in ['critical', 'high']:
            self.packet_stats['malicious'] += 1
        else:
            self.packet_stats['suspicious'] += 1
        
        alert = {
            'id': int(current_time * 1000),
            'type': attack_type,
            'title': title,
            'severity': severity,
            'description': description,
            'source': source,
            'timestamp': datetime.now().isoformat(),
            'evidence': evidence or {},
            'count': self.alert_counts[attack_type]
        }
        
        logger.info(f"[Security] Alert created: {title} ({severity}) from {source}")
        
        return alert
    
    def _process_alert(self, alert: Dict, packet: Dict):
        """Process and broadcast alert"""
        
        if alert:
            # Log alert
            self.attack_logs.append(alert)
            if len(self.attack_logs) > 1000:
                self.attack_logs = self.attack_logs[-500:]
            
            # Log to logger
            logger.warning(f"[ALERT] [{alert['severity'].upper()}] {alert['title']}: {alert['description']}")
            
            # Call callback if set
            if self.alert_callback:
                try:
                    self.alert_callback(alert)
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}")
                    logger.error(f"[Security] Alert callback failed: {e}")
    
    def _update_stats(self, packet: Dict):
        """Update packet statistics"""
        self.packet_stats['total'] += 1
        
        protocol = packet.get('protocol', '').upper()
        dst_port = packet.get('dst_port', 0)
        
        if protocol == 'TCP':
            self.packet_stats['tcp'] += 1
            if dst_port == 80:
                self.packet_stats['http'] += 1
            elif dst_port == 443:
                self.packet_stats['https'] += 1
        elif protocol == 'UDP':
            self.packet_stats['udp'] += 1
            if dst_port == 53:
                self.packet_stats['dns'] += 1
        elif protocol == 'ICMP':
            self.packet_stats['icmp'] += 1
        elif protocol == 'ARP':
            self.packet_stats['arp'] += 1
        else:
            self.packet_stats['other'] += 1
    
    def get_packet_stats(self) -> Dict:
        """Return packet statistics"""
        return self.packet_stats.copy()
    
    def get_attack_logs(self) -> List[Dict]:
        """Return attack logs"""
        return self.attack_logs.copy()
    
    def get_alert_counts(self) -> Dict:
        """Return alert counts by type"""
        return dict(self.alert_counts)
    
    def clear_tracking(self):
        """Clear all tracking data (useful for testing)"""
        self.port_scan_tracker.clear()
        self.packet_rate.clear()
        self.dst_packet_rate.clear()
        self.dns_queries.clear()
        self.arp_requests.clear()
        self.beacon_tracker.clear()
        self.failed_logins.clear()
        self.alert_history.clear()
        logger.info("[Clear] All tracking data cleared")
        logger.info("[Clear] All tracking data cleared")
