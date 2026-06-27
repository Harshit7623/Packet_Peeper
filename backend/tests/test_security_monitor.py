"""
Comprehensive Attack Detection Tests — NetworkSecurityMonitor
==============================================================
Covers all 12 detection methods with:
- Positive detection (attack triggers alert)
- Sub-threshold / boundary tests (attack does NOT false-positive)
- Variant coverage (different scan types, protocols, flag combos)
"""

import time
import pytest
from network_security_monitor import NetworkSecurityMonitor


@pytest.fixture
def monitor():
    m = NetworkSecurityMonitor()
    m.enable_test_mode()
    return m


def _tcp(src_ip="1.2.3.4", dst_ip="10.0.0.1", dst_port=80, tcp_flags=2,
         src_port=12345, length=60, payload=""):
    return {
        "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": src_port, "dst_port": dst_port,
        "protocol": "TCP", "tcp_flags": tcp_flags,
        "length": length, "payload": payload,
    }


def _udp(src_ip="1.2.3.4", dst_ip="10.0.0.1", dst_port=53, src_port=12345,
         length=60, payload=""):
    return {
        "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": src_port, "dst_port": dst_port,
        "protocol": "UDP", "tcp_flags": 0,
        "length": length, "payload": payload,
    }


def _icmp(src_ip="1.2.3.4", dst_ip="10.0.0.1", length=64, payload=""):
    return {
        "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": 0, "dst_port": 0,
        "protocol": "ICMP", "tcp_flags": 0,
        "length": length, "payload": payload,
    }


def _arp(arp_src_ip="192.168.1.1", arp_src_mac="aa:bb:cc:dd:ee:ff",
         arp_op=1, src_ip="192.168.1.1", dst_ip="192.168.1.2"):
    return {
        "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": 0, "dst_port": 0,
        "protocol": "ARP", "tcp_flags": 0,
        "length": 42, "arp_src_ip": arp_src_ip,
        "arp_src_mac": arp_src_mac, "arp_op": arp_op,
    }


def _dns(src_ip="1.2.3.4", dst_ip="8.8.8.8", dst_port=53, payload="",
         src_port=12345, length=60):
    return {
        "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": src_port, "dst_port": dst_port,
        "protocol": "DNS", "tcp_flags": 0,
        "length": length, "payload": payload,
    }


def _collect(monitor, packets):
    alerts = []
    for p in packets:
        alerts.extend(monitor.analyze_packet(p))
    return [a for a in alerts if a is not None]


def _has_alert(alerts, attack_type):
    return any(a.get("alert_type") == attack_type or a.get("type") == attack_type for a in alerts)


# ============================================================
# 1. PORT SCAN DETECTION
# ============================================================

class TestPortScanDetection:

    def test_syn_scan_triggers(self, monitor):
        n = monitor.thresholds["port_scan_count"]
        pkts = [_tcp(dst_port=p) for p in range(1, n + 1)]
        alerts = _collect(monitor, pkts)
        assert _has_alert(alerts, "port_scan")

    def test_sub_threshold_no_alert(self, monitor):
        n = monitor.thresholds["port_scan_count"]
        pkts = [_tcp(dst_port=p) for p in range(1, n)]
        alerts = _collect(monitor, pkts)
        assert not _has_alert(alerts, "port_scan")

    def test_fin_scan_triggers(self, monitor):
        pkts = [_tcp(tcp_flags=1, dst_port=p) for p in [22, 80, 443]]
        alerts = _collect(monitor, pkts)
        assert _has_alert(alerts, "port_scan")

    def test_xmas_scan_triggers(self, monitor):
        pkts = [_tcp(tcp_flags=41, dst_port=p) for p in [22, 80, 443]]
        alerts = _collect(monitor, pkts)
        assert _has_alert(alerts, "port_scan")

    def test_ack_scan_external_triggers(self, monitor):
        old_threshold = monitor.thresholds["port_scan_count"]
        monitor.thresholds["port_scan_count"] = 20
        ports = list(range(1, 16))
        all_alerts = []
        for p in ports:
            all_alerts.extend(_collect(monitor, [_tcp(tcp_flags=16, src_ip="8.8.8.8", dst_port=p)]))
        monitor.thresholds["port_scan_count"] = old_threshold
        ack_alerts = [a for a in all_alerts if a.get("alert_type") == "port_scan"
                      and "ACK" in a.get("evidence", {}).get("scan_type", "")]
        assert len(ack_alerts) >= 1, "ACK Scan should fire at stealth_scan_count + 15 unique ports"

    def test_ack_scan_private_no_alert(self, monitor):
        old_threshold = monitor.thresholds["port_scan_count"]
        monitor.thresholds["port_scan_count"] = 20
        pkts = [_tcp(tcp_flags=16, src_ip="192.168.1.50", dst_port=p)
                for p in range(1, 16)]
        alerts = _collect(monitor, pkts)
        monitor.thresholds["port_scan_count"] = old_threshold
        ack_alerts = [a for a in alerts if a.get("alert_type") == "port_scan"
                      and "ACK" in a.get("evidence", {}).get("scan_type", "")]
        assert len(ack_alerts) == 0, "Private source should not trigger ACK scan"

    def test_duplicate_ports_count_once(self, monitor):
        n = monitor.thresholds["port_scan_count"]
        pkts = [_tcp(dst_port=80) for _ in range(n + 2)]
        alerts = _collect(monitor, pkts)
        assert not _has_alert(alerts, "port_scan")

    def test_reset_after_detection(self, monitor):
        n = monitor.thresholds["port_scan_count"]
        pkts1 = [_tcp(dst_port=p) for p in range(1, n + 1)]
        _collect(monitor, pkts1)
        monitor.reset_counters()
        monitor.warmup_end = 0
        pkts2 = [_tcp(dst_port=p + 100) for p in range(1, n + 1)]
        alerts2 = _collect(monitor, pkts2)
        assert _has_alert(alerts2, "port_scan")


# ============================================================
# 2. FLOOD DETECTION (SYN / UDP / ICMP)
# ============================================================

class TestFloodDetection:

    def test_syn_flood_triggers(self, monitor):
        n = monitor.thresholds["syn_flood_rate"] + 1
        pkts = [_tcp(src_ip="8.8.8.8", tcp_flags=2, dst_port=8443, src_port=0)
                for _ in range(n)]
        alerts = _collect(monitor, pkts)
        assert _has_alert(alerts, "flood"), \
            f"SYN flood should trigger (got: {[a.get('alert_type') for a in alerts]})"

    def test_udp_flood_triggers(self, monitor):
        n = monitor.thresholds["udp_flood_rate"] + 1
        pkts = [_udp(src_ip="8.8.8.8", dst_port=53, src_port=0) for _ in range(n)]
        alerts = _collect(monitor, pkts)
        assert _has_alert(alerts, "flood")

    def test_icmp_flood_triggers(self, monitor):
        n = monitor.thresholds["icmp_flood_rate"] + 1
        pkts = [_icmp(src_ip="8.8.8.8") for _ in range(n)]
        alerts = _collect(monitor, pkts)
        assert _has_alert(alerts, "flood")

    def test_private_ip_no_flood_alert(self, monitor):
        n = monitor.thresholds["syn_flood_rate"] + 1
        pkts = [_tcp(src_ip="192.168.1.50", tcp_flags=2, dst_port=80) for _ in range(n)]
        alerts = _collect(monitor, pkts)
        assert not _has_alert(alerts, "flood")

    def test_syn_flood_non_syn_no_alert(self, monitor):
        n = monitor.thresholds["syn_flood_rate"] + 1
        pkts = [_tcp(src_ip="8.8.8.8", tcp_flags=16, dst_port=80, src_port=0)
                for _ in range(n)]
        alerts = _collect(monitor, pkts)
        assert not _has_alert(alerts, "flood")

    def test_sub_threshold_no_alert(self, monitor):
        n = monitor.thresholds["udp_flood_rate"]
        pkts = [_udp(src_ip="8.8.8.8", dst_port=53, src_port=0) for _ in range(n - 1)]
        alerts = _collect(monitor, pkts)
        assert not _has_alert(alerts, "flood")


# ============================================================
# 3. DDoS DETECTION
# ============================================================

class TestDDoSDetection:

    def test_ddos_triggers(self, monitor):
        n = monitor.thresholds["ddos_sources"]
        pkts = [_tcp(src_ip=f"203.0.113.{i}", dst_ip="10.0.0.2", dst_port=80,
                      tcp_flags=0, length=64) for i in range(n + 1)]
        alerts = _collect(monitor, pkts)
        assert _has_alert(alerts, "ddos")

    def test_sub_threshold_no_alert(self, monitor):
        n = monitor.thresholds["ddos_sources"]
        pkts = [_tcp(src_ip=f"203.0.113.{i}", dst_ip="10.0.0.2", dst_port=80,
                      tcp_flags=0, length=64) for i in range(n - 1)]
        alerts = _collect(monitor, pkts)
        assert not _has_alert(alerts, "ddos")

    def test_same_source_no_ddos(self, monitor):
        n = monitor.thresholds["ddos_sources"]
        pkts = [_tcp(src_ip="203.0.113.10", dst_ip="10.0.0.2", dst_port=80)
                for _ in range(n + 5)]
        alerts = _collect(monitor, pkts)
        assert not _has_alert(alerts, "ddos")

    def test_reset_allows_redetect(self, monitor):
        n = monitor.thresholds["ddos_sources"]
        pkts = [_tcp(src_ip=f"203.0.113.{i}", dst_ip="10.0.0.2", dst_port=80,
                      tcp_flags=0, length=64) for i in range(n + 1)]
        _collect(monitor, pkts)
        monitor.reset_counters()
        monitor.warmup_end = 0
        pkts2 = [_tcp(src_ip=f"198.51.100.{i}", dst_ip="10.0.0.3", dst_port=80,
                       tcp_flags=0, length=64) for i in range(n + 1)]
        alerts2 = _collect(monitor, pkts2)
        assert _has_alert(alerts2, "ddos")


# ============================================================
# 4. BRUTE FORCE DETECTION
# ============================================================

class TestBruteForceDetection:

    def test_ssh_brute_force_triggers(self, monitor):
        n = monitor.thresholds["brute_force_attempts"]
        pkts = [_tcp(src_ip="203.0.113.20", dst_ip="10.0.0.1", dst_port=22,
                      tcp_flags=2) for _ in range(n + 1)]
        alerts = _collect(monitor, pkts)
        assert _has_alert(alerts, "brute_force")

    def test_ftp_brute_force_triggers(self, monitor):
        n = monitor.thresholds["brute_force_attempts"]
        pkts = [_tcp(src_ip="203.0.113.20", dst_ip="10.0.0.1", dst_port=21,
                      tcp_flags=2) for _ in range(n + 1)]
        alerts = _collect(monitor, pkts)
        assert _has_alert(alerts, "brute_force")

    def test_rdp_brute_force_triggers(self, monitor):
        n = monitor.thresholds["brute_force_attempts"]
        pkts = [_tcp(src_ip="203.0.113.20", dst_ip="10.0.0.1", dst_port=3389,
                      tcp_flags=2) for _ in range(n + 1)]
        alerts = _collect(monitor, pkts)
        assert _has_alert(alerts, "brute_force")

    def test_non_syn_ignored(self, monitor):
        n = monitor.thresholds["brute_force_attempts"]
        pkts = [_tcp(src_ip="203.0.113.20", dst_ip="10.0.0.1", dst_port=22,
                      tcp_flags=16) for _ in range(n + 1)]
        alerts = _collect(monitor, pkts)
        assert not _has_alert(alerts, "brute_force")

    def test_sub_threshold_no_alert(self, monitor):
        n = monitor.thresholds["brute_force_attempts"]
        pkts = [_tcp(src_ip="203.0.113.20", dst_ip="10.0.0.1", dst_port=22,
                      tcp_flags=2) for _ in range(n - 1)]
        alerts = _collect(monitor, pkts)
        assert not _has_alert(alerts, "brute_force")

    def test_non_auth_port_no_alert(self, monitor):
        n = monitor.thresholds["brute_force_attempts"] + 5
        pkts = [_tcp(src_ip="203.0.113.20", dst_ip="10.0.0.1", dst_port=8080,
                      tcp_flags=2) for _ in range(n)]
        alerts = _collect(monitor, pkts)
        assert not _has_alert(alerts, "brute_force")


# ============================================================
# 5. DNS TUNNELING DETECTION
# ============================================================

class TestDNSTunnelingDetection:

    def test_long_query_with_subdomains_triggers(self, monitor):
        payload = "a" * 60 + "." + ".".join(["sub"] * 8) + ".example.com"
        alerts = _collect(monitor, [_dns(payload=payload)])
        assert _has_alert(alerts, "dns_tunneling")

    def test_many_subdomains_with_rate_triggers(self, monitor):
        subdomains = ".".join(["sub"] * 10) + ".example.com"
        monitor.dns_queries["1.2.3.4"] = [time.time()] * (monitor.thresholds["dns_query_rate"] + 1)
        alerts = _collect(monitor, [_dns(payload=subdomains)])
        assert _has_alert(alerts, "dns_tunneling")

    def test_base64_pattern_contributes(self, monitor):
        b64 = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/=" * 2
        payload = b64 + ".".join(["x"] * 6) + ".com"
        alerts = _collect(monitor, [_dns(payload=payload)])
        assert _has_alert(alerts, "dns_tunneling")

    def test_hex_pattern_contributes(self, monitor):
        hex_str = "0123456789abcdef" * 4
        payload = hex_str + ".".join(["x"] * 6) + ".com"
        alerts = _collect(monitor, [_dns(payload=payload)])
        assert _has_alert(alerts, "dns_tunneling")

    def test_normal_query_no_alert(self, monitor):
        alerts = _collect(monitor, [_dns(payload="www.google.com")])
        assert not _has_alert(alerts, "dns_tunneling")

    def test_empty_payload_no_alert(self, monitor):
        alerts = _collect(monitor, [_dns(payload="")])
        assert not _has_alert(alerts, "dns_tunneling")


# ============================================================
# 6. ARP SPOOFING DETECTION
# ============================================================

class TestARPSpoofingDetection:

    def test_mac_change_triggers_spoofing(self, monitor):
        _collect(monitor, [_arp(arp_src_ip="192.168.1.1", arp_src_mac="aa:bb:cc:dd:ee:ff")])
        alerts = _collect(monitor, [_arp(arp_src_ip="192.168.1.1", arp_src_mac="11:22:33:44:55:66")])
        assert _has_alert(alerts, "arp_spoofing")

    def test_same_mac_no_alert(self, monitor):
        _collect(monitor, [_arp(arp_src_ip="192.168.1.1", arp_src_mac="aa:bb:cc:dd:ee:ff")])
        alerts = _collect(monitor, [_arp(arp_src_ip="192.168.1.1", arp_src_mac="aa:bb:cc:dd:ee:ff")])
        assert not _has_alert(alerts, "arp_spoofing")

    def test_arp_flood_triggers(self, monitor):
        n = monitor.thresholds.get("arp_flood_threshold", 20) + 2
        pkts = [_arp(arp_src_ip="192.168.1.100", arp_src_mac=f"aa:bb:cc:dd:ee:{i:02x}",
                      arp_op=1) for i in range(n)]
        alerts = _collect(monitor, pkts)
        assert _has_alert(alerts, "arp_flood")

    def test_no_mac_no_alert(self, monitor):
        alerts = _collect(monitor, [_arp(arp_src_ip="192.168.1.1", arp_src_mac="")])
        assert not _has_alert(alerts, "arp_spoofing")


# ============================================================
# 7. APPLICATION ATTACK DETECTION (SQLi / XSS / Cmd / Traversal)
# ============================================================

class TestApplicationAttackDetection:

    def test_sqli_or_1_equals_1(self, monitor):
        payload = "' OR 1=1 --"
        alerts = _collect(monitor, [_tcp(dst_port=80, payload=payload)])
        assert _has_alert(alerts, "sql_injection")

    def test_sqli_union_select(self, monitor):
        payload = "UNION SELECT username, password FROM users--"
        alerts = _collect(monitor, [_tcp(dst_port=80, payload=payload)])
        assert _has_alert(alerts, "sql_injection")

    def test_sqli_drop_table(self, monitor):
        payload = "DROP TABLE users"
        alerts = _collect(monitor, [_tcp(dst_port=80, payload=payload)])
        assert _has_alert(alerts, "sql_injection")

    def test_sqli_sleep_benchmark(self, monitor):
        payload = "SLEEP(5)"
        alerts = _collect(monitor, [_tcp(dst_port=80, payload=payload)])
        assert _has_alert(alerts, "sql_injection")

    def test_xss_script_tag(self, monitor):
        payload = '<script>alert("xss")</script>'
        alerts = _collect(monitor, [_tcp(dst_port=80, payload=payload)])
        assert _has_alert(alerts, "xss")

    def test_xss_onerror(self, monitor):
        payload = '<img src=x onerror=alert(1)>'
        alerts = _collect(monitor, [_tcp(dst_port=80, payload=payload)])
        assert _has_alert(alerts, "xss")

    def test_xss_javascript_uri(self, monitor):
        payload = 'javascript:alert(1)'
        alerts = _collect(monitor, [_tcp(dst_port=80, payload=payload)])
        assert _has_alert(alerts, "xss")

    def test_cmd_injection_semicolon(self, monitor):
        payload = "; cat /etc/passwd"
        alerts = _collect(monitor, [_tcp(dst_port=80, payload=payload)])
        assert _has_alert(alerts, "command_injection")

    def test_cmd_injection_subshell(self, monitor):
        payload = "$(cat /etc/passwd)"
        alerts = _collect(monitor, [_tcp(dst_port=80, payload=payload)])
        assert _has_alert(alerts, "command_injection")

    def test_cmd_injection_etc_passwd(self, monitor):
        payload = "/etc/passwd"
        alerts = _collect(monitor, [_tcp(dst_port=80, payload=payload)])
        assert _has_alert(alerts, "command_injection")

    def test_path_traversal_dotdot(self, monitor):
        payload = "../../etc/passwd"
        alerts = _collect(monitor, [_tcp(dst_port=80, payload=payload)])
        assert _has_alert(alerts, "path_traversal")

    def test_path_traversal_encoded(self, monitor):
        payload = "%2e%2e/etc/passwd"
        alerts = _collect(monitor, [_tcp(dst_port=80, payload=payload)])
        assert _has_alert(alerts, "path_traversal")

    def test_normal_http_no_alert(self, monitor):
        payload = "GET /index.html HTTP/1.1"
        alerts = _collect(monitor, [_tcp(dst_port=80, payload=payload)])
        assert not _has_alert(alerts, "sql_injection")
        assert not _has_alert(alerts, "xss")
        assert not _has_alert(alerts, "command_injection")
        assert not _has_alert(alerts, "path_traversal")

    def test_empty_payload_no_alert(self, monitor):
        alerts = _collect(monitor, [_tcp(dst_port=80, payload="")])
        assert not _has_alert(alerts, "sql_injection")


# ============================================================
# 8. MALFORMED PACKET / LAND ATTACK
# ============================================================

class TestMalformedPacketDetection:

    def test_land_attack_triggers(self, monitor):
        pkt = {
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.1",
            "src_port": 80, "dst_port": 80,
            "protocol": "TCP", "tcp_flags": 2,
            "length": 60, "payload": "",
        }
        alerts = _collect(monitor, [pkt])
        assert _has_alert(alerts, "land_attack")

    def test_localhost_land_exempt(self, monitor):
        pkt = {
            "src_ip": "127.0.0.1", "dst_ip": "127.0.0.1",
            "src_port": 80, "dst_port": 80,
            "protocol": "TCP", "tcp_flags": 2,
            "length": 60, "payload": "",
        }
        alerts = _collect(monitor, [pkt])
        assert not _has_alert(alerts, "land_attack")

    def test_normal_different_ips_no_alert(self, monitor):
        alerts = _collect(monitor, [_tcp(src_ip="10.0.0.1", dst_ip="10.0.0.2")])
        assert not _has_alert(alerts, "land_attack")


# ============================================================
# 9. C2 BEACON DETECTION (currently ICMP-only in analyze_packet)
# ============================================================

class TestC2BeaconDetection:

    def test_regular_icmp_beacon_triggers(self, monitor):
        n = monitor.thresholds["beacon_min_callbacks"]
        regularity_threshold = monitor.thresholds["beacon_regularity"]
        interval = 400
        base = time.time() - (n * interval)
        pkts = []
        for i in range(n + 1):
            t = base + (i * interval)
            pkt = _icmp(src_ip="203.0.113.50", dst_ip="10.0.0.1", payload="data")
            pkts.append((t, pkt))
        alerts = []
        for t, pkt in pkts:
            old_warmup = monitor.warmup_end
            monitor.warmup_end = 0
            saved_time = time.time
            try:
                import unittest.mock
                with unittest.mock.patch("network_security_monitor.time.time", return_value=t):
                    alerts.extend(monitor.analyze_packet(pkt))
            finally:
                monitor.warmup_end = old_warmup
        assert _has_alert(alerts, "c2_beacon")

    def test_irregular_beacon_no_alert(self, monitor):
        n = monitor.thresholds["beacon_min_callbacks"] + 2
        intervals = [100, 800, 50, 2000, 300, 1500, 20, 900, 4000, 75]
        base = time.time() - sum(intervals)
        pkts = []
        t = base
        for i in range(n):
            t += intervals[i % len(intervals)]
            pkts.append((t, _icmp(src_ip="203.0.113.50", dst_ip="10.0.0.1", payload="data")))
        alerts = []
        for t_pkt, pkt in pkts:
            monitor.warmup_end = 0
            import unittest.mock
            with unittest.mock.patch("network_security_monitor.time.time", return_value=t_pkt):
                alerts.extend(monitor.analyze_packet(pkt))
        assert not _has_alert(alerts, "c2_beacon")

    def test_tcp_beacon_now_detected(self, monitor):
        n = monitor.thresholds["beacon_min_callbacks"] + 1
        interval = 400
        base = time.time() - (n * interval)
        pkts = []
        for i in range(n + 1):
            t = base + (i * interval)
            pkts.append((t, _tcp(src_ip="8.8.8.8", dst_ip="10.0.0.1", dst_port=443, tcp_flags=24, payload="data")))
        alerts = []
        for t_pkt, pkt in pkts:
            monitor.warmup_end = 0
            import unittest.mock
            with unittest.mock.patch("network_security_monitor.time.time", return_value=t_pkt):
                alerts.extend(monitor.analyze_packet(pkt))
        assert _has_alert(alerts, "c2_beacon"), \
            "Beacon detection should now run for TCP (fix applied)"


# ============================================================
# 10. ICMP COVERT CHANNEL
# ============================================================

class TestICMPCovertChannel:

    def test_large_payload_triggers(self, monitor):
        payload = "A" * (monitor.thresholds["icmp_covert_min_bytes"] + 10)
        alerts = _collect(monitor, [_icmp(src_ip="203.0.113.60", payload=payload)])
        assert _has_alert(alerts, "covert_channel")

    def test_small_payload_no_alert(self, monitor):
        payload = "A" * 10
        alerts = _collect(monitor, [_icmp(src_ip="203.0.113.60", payload=payload)])
        assert not _has_alert(alerts, "covert_channel")

    def test_exact_at_threshold(self, monitor):
        payload = "X" * monitor.thresholds["icmp_covert_min_bytes"]
        alerts = _collect(monitor, [_icmp(src_ip="203.0.113.60", payload=payload)])
        assert not _has_alert(alerts, "covert_channel")


# ============================================================
# 11. IP SPOOFING DETECTION
# ============================================================

class TestIPSpoofingDetection:

    def test_broadcast_source_triggers(self, monitor):
        alerts = _collect(monitor, [_tcp(src_ip="255.255.255.255", dst_ip="10.0.0.1")])
        assert _has_alert(alerts, "ip_spoofing")

    def test_multicast_source_triggers(self, monitor):
        alerts = _collect(monitor, [_tcp(src_ip="224.0.0.1", dst_ip="10.0.0.1")])
        assert _has_alert(alerts, "ip_spoofing")

    def test_null_source_triggers(self, monitor):
        pkt = _tcp(src_ip="0.0.0.0", dst_ip="10.0.0.1", dst_port=80)
        alerts = _collect(monitor, [pkt])
        assert _has_alert(alerts, "ip_spoofing")

    def test_null_source_dhcp_exempt(self, monitor):
        pkt = _tcp(src_ip="0.0.0.0", dst_ip="10.0.0.1", dst_port=67)
        pkt["protocol"] = "UDP"
        alerts = _collect(monitor, [pkt])
        assert not _has_alert(alerts, "ip_spoofing")

    def test_normal_ip_no_alert(self, monitor):
        alerts = _collect(monitor, [_tcp(src_ip="192.168.1.10", dst_ip="10.0.0.1")])
        assert not _has_alert(alerts, "ip_spoofing")


# ============================================================
# 12. SESSION HIJACKING DETECTION
# ============================================================

class TestSessionHijacking:

    def test_suspicious_injection_triggers(self, monitor):
        n = monitor.thresholds["session_injection_count"]
        src = "203.0.113.70"
        monitor.injection_attempts[src]["timestamps"] = [time.time()] * 4
        monitor.injection_attempts[src]["count"] = 0
        pkts = []
        for i in range(n + 1):
            pkts.append(_tcp(
                src_ip=src, dst_ip="10.0.0.1", dst_port=80,
                tcp_flags=24, src_port=40000 + i,
                payload="GET /admin Cookie: session=abc123"
            ))
        alerts = _collect(monitor, pkts)
        assert _has_alert(alerts, "session_hijack"), \
            "Session injection with suspicious payload and no established session should trigger"

    def test_established_session_no_injection(self, monitor):
        monitor.established_sessions["10.0.0.1:80-203.0.113.80:40000"] = True
        pkts = [_tcp(
            src_ip="203.0.113.80", dst_ip="10.0.0.1", dst_port=80,
            tcp_flags=24, src_port=40000,
            payload="GET /admin Cookie: session=xyz"
        )]
        alerts = _collect(monitor, pkts)
        assert not _has_alert(alerts, "session_hijack")

    def test_no_payload_no_alert(self, monitor):
        pkts = [_tcp(src_ip="203.0.113.70", dst_ip="10.0.0.1", dst_port=80,
                      tcp_flags=24, payload="")]
        alerts = _collect(monitor, pkts)
        assert not _has_alert(alerts, "session_hijack")

    def test_non_data_flags_no_alert(self, monitor):
        pkts = [_tcp(src_ip="203.0.113.70", dst_ip="10.0.0.1", dst_port=80,
                      tcp_flags=2, payload="GET /admin Cookie: session=abc")]
        alerts = _collect(monitor, pkts)
        assert not _has_alert(alerts, "session_hijack")


# ============================================================
# 13. DATA EXFILTRATION DETECTION
# ============================================================

class TestDataExfiltration:

    def test_large_outbound_triggers(self, monitor):
        threshold = monitor.thresholds["exfil_size_bytes"]
        chunk = 5000
        n = (threshold // chunk) + 2
        pkts = [_tcp(src_ip="192.168.1.50", dst_ip="8.8.8.8", dst_port=443,
                      tcp_flags=24, length=chunk,
                      payload="A" * chunk) for _ in range(n)]
        alerts = _collect(monitor, pkts)
        assert _has_alert(alerts, "data_exfiltration")

    def test_inbound_no_alert(self, monitor):
        threshold = monitor.thresholds["exfil_size_bytes"]
        chunk = 5000
        n = (threshold // chunk) + 2
        pkts = [_tcp(src_ip="8.8.8.8", dst_ip="192.168.1.50", dst_port=443,
                      tcp_flags=24, length=chunk,
                      payload="A" * chunk) for _ in range(n)]
        alerts = _collect(monitor, pkts)
        assert not _has_alert(alerts, "data_exfiltration")

    def test_small_payload_no_alert(self, monitor):
        pkts = [_tcp(src_ip="192.168.1.50", dst_ip="8.8.8.8", dst_port=443,
                      tcp_flags=24, length=50, payload="A" * 50)]
        alerts = _collect(monitor, pkts)
        assert not _has_alert(alerts, "data_exfiltration")


# ============================================================
# ALERT RATE LIMITING
# ============================================================

class TestAlertRateLimiting:

    def test_per_type_limit(self, monitor):
        max_per_type = monitor.thresholds["max_alerts_per_type"]
        port_scan_n = monitor.thresholds["port_scan_count"]
        all_alerts = []
        for _ in range(max_per_type + 2):
            monitor.reset_counters()
            pkts = [_tcp(dst_port=p) for p in range(1, port_scan_n + 1)]
            all_alerts.extend(_collect(monitor, pkts))
        port_scan_alerts = [a for a in all_alerts if a.get("alert_type") == "port_scan"]
        assert len(port_scan_alerts) <= max_per_type

    def test_total_alert_limit(self, monitor):
        max_total = monitor.thresholds["max_total_alerts"]
        monitor.reset_counters()
        total_alerts = []
        for i in range(max_total + 20):
            monitor.reset_counters()
            src = f"255.255.{i % 256}.{i // 256}"
            alerts = _collect(monitor, [_tcp(src_ip=src, dst_ip="10.0.0.1")])
            total_alerts.extend(alerts)
        assert len(total_alerts) <= max_total

    def test_cooldown_prevents_duplicate(self, monitor):
        port_scan_n = monitor.thresholds["port_scan_count"]
        pkts = [_tcp(dst_port=p) for p in range(1, port_scan_n + 1)]
        alerts1 = _collect(monitor, pkts)
        alerts2 = _collect(monitor, pkts)
        assert len(alerts1) >= 1
        assert len([a for a in alerts2 if a.get("alert_type") == "port_scan"]) == 0


# ============================================================
# RESET COUNTERS
# ============================================================

class TestResetCounters:

    def test_reset_clears_port_scan_tracker(self, monitor):
        for p in [22, 80, 443]:
            monitor.analyze_packet(_tcp(dst_port=p))
        assert len(monitor.port_scan_tracker) > 0
        monitor.reset_counters()
        assert len(monitor.port_scan_tracker) == 0

    def test_reset_clears_attack_logs(self, monitor):
        port_scan_n = monitor.thresholds["port_scan_count"]
        pkts = [_tcp(dst_port=p) for p in range(1, port_scan_n + 1)]
        _collect(monitor, pkts)
        assert len(monitor.attack_logs) > 0
        monitor.reset_counters()
        assert len(monitor.attack_logs) == 0

    def test_reset_restarts_warmup(self, monitor):
        monitor.warmup_end = 0
        monitor.reset_counters()
        assert monitor.warmup_end > 0
