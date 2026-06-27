#!/usr/bin/env python3
"""
Quick Detection Test - Verifies the NetworkSecurityMonitor works correctly
"""

import sys
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from network_security_monitor import NetworkSecurityMonitor
import time


def _has_alert(alerts, attack_type):
    return any(
        a.get("alert_type") == attack_type or a.get("type") == attack_type
        for a in alerts
        if a is not None
    )


def _reset(monitor):
    monitor.reset_counters()
    monitor.warmup_end = 0


def test_detection():
    monitor = NetworkSecurityMonitor()
    monitor.enable_test_mode()

    print("\n" + "=" * 60)
    print("TESTING NETWORK SECURITY MONITOR DETECTION")
    print("=" * 60)

    total_tests = 0
    passed_tests = 0

    # Test 1: Port Scan Detection
    print("\n[TEST 1] Port Scan Detection")
    total_tests += 1
    _reset(monitor)
    alerts = []
    for port in range(1, 20):
        packet = {
            "src_ip": "1.2.3.4",
            "dst_ip": "10.0.0.1",
            "src_port": 54321,
            "dst_port": port,
            "protocol": "TCP",
            "tcp_flags": 2,
        }
        result = monitor.analyze_packet(packet)
        alerts.extend(r for r in result if r is not None)

    if _has_alert(alerts, "port_scan"):
        print("  PASSED - Port scan detected!")
        passed_tests += 1
    else:
        print("  FAILED - Port scan not detected")

    # Test 2: SYN Flood Detection
    print("\n[TEST 2] SYN Flood Detection")
    total_tests += 1
    _reset(monitor)
    alerts = []
    for i in range(20):
        packet = {
            "src_ip": "8.8.8.8",
            "dst_ip": "10.0.0.1",
            "src_port": 54000 + i,
            "dst_port": 80,
            "protocol": "TCP",
            "tcp_flags": 2,
            "payload": "",
        }
        result = monitor.analyze_packet(packet)
        alerts.extend(r for r in result if r is not None)

    if _has_alert(alerts, "flood"):
        print("  PASSED - SYN Flood detected!")
        passed_tests += 1
    else:
        print("  FAILED - SYN Flood not detected")

    # Test 3: Brute Force Detection
    print("\n[TEST 3] Brute Force Detection")
    total_tests += 1
    _reset(monitor)
    alerts = []
    for i in range(10):
        packet = {
            "src_ip": "8.8.8.8",
            "dst_ip": "10.0.0.1",
            "src_port": 50000 + i,
            "dst_port": 22,
            "protocol": "TCP",
            "tcp_flags": 2,
        }
        result = monitor.analyze_packet(packet)
        alerts.extend(r for r in result if r is not None)

    if _has_alert(alerts, "brute_force"):
        print("  PASSED - Brute force detected!")
        passed_tests += 1
    else:
        print("  FAILED - Brute force not detected")

    # Test 4: SQL Injection Detection
    print("\n[TEST 4] SQL Injection Detection")
    total_tests += 1
    _reset(monitor)
    packet = {
        "src_ip": "1.2.3.4",
        "dst_ip": "10.0.0.1",
        "src_port": 45678,
        "dst_port": 80,
        "protocol": "HTTP",
        "payload": "GET /login?user=' OR '1'='1' -- HTTP/1.1",
    }
    alerts = monitor.analyze_packet(packet)
    alerts = [a for a in alerts if a is not None]

    if _has_alert(alerts, "sql_injection"):
        print("  PASSED - SQL Injection detected!")
        passed_tests += 1
    else:
        print("  FAILED - SQL Injection not detected")

    # Test 5: XSS Detection
    print("\n[TEST 5] XSS Detection")
    total_tests += 1
    _reset(monitor)
    packet = {
        "src_ip": "1.2.3.5",
        "dst_ip": "10.0.0.1",
        "src_port": 45679,
        "dst_port": 80,
        "protocol": "HTTP",
        "payload": "GET /search?q=<script>alert('xss')</script> HTTP/1.1",
    }
    alerts = monitor.analyze_packet(packet)
    alerts = [a for a in alerts if a is not None]

    if _has_alert(alerts, "xss"):
        print("  PASSED - XSS detected!")
        passed_tests += 1
    else:
        print("  FAILED - XSS not detected")

    # Test 6: DNS Tunneling Detection
    print("\n[TEST 6] DNS Tunneling Detection")
    total_tests += 1
    _reset(monitor)
    alerts = []
    base64_sub = "YWRtaW46cGFzc3dvcmQxMjM0NTY3ODkw"
    for i in range(25):
        payload = (
            f"{base64_sub}.sub{i}.a.b.c.d.e.f.tunnel.evil.example.org"
        )
        packet = {
            "src_ip": "1.2.3.6",
            "dst_ip": "8.8.8.8",
            "src_port": 50000 + i,
            "dst_port": 53,
            "protocol": "DNS",
            "payload": payload,
        }
        result = monitor.analyze_packet(packet)
        alerts.extend(r for r in result if r is not None)

    if _has_alert(alerts, "dns_tunneling"):
        print("  PASSED - DNS Tunneling detected!")
        passed_tests += 1
    else:
        print("  FAILED - DNS Tunneling not detected")

    # Test 7: LAND Attack Detection
    print("\n[TEST 7] LAND Attack Detection")
    total_tests += 1
    _reset(monitor)
    packet = {
        "src_ip": "192.168.1.50",
        "dst_ip": "192.168.1.50",
        "src_port": 80,
        "dst_port": 80,
        "protocol": "TCP",
        "tcp_flags": 2,
    }
    alerts = monitor.analyze_packet(packet)
    alerts = [a for a in alerts if a is not None]

    if _has_alert(alerts, "land_attack"):
        print("  PASSED - LAND Attack detected!")
        passed_tests += 1
    else:
        print("  FAILED - LAND Attack not detected")

    # Test 8: Command Injection Detection
    print("\n[TEST 8] Command Injection Detection")
    total_tests += 1
    _reset(monitor)
    packet = {
        "src_ip": "1.2.3.7",
        "dst_ip": "10.0.0.1",
        "src_port": 45680,
        "dst_port": 80,
        "protocol": "HTTP",
        "payload": "GET /ping?host=127.0.0.1; cat /etc/passwd HTTP/1.1",
    }
    alerts = monitor.analyze_packet(packet)
    alerts = [a for a in alerts if a is not None]

    if _has_alert(alerts, "command_injection"):
        print("  PASSED - Command Injection detected!")
        passed_tests += 1
    else:
        print("  FAILED - Command Injection not detected")

    # Test 9: IP Spoofing Detection
    print("\n[TEST 9] IP Spoofing Detection")
    total_tests += 1
    _reset(monitor)
    packet = {
        "src_ip": "255.255.255.255",
        "dst_ip": "10.0.0.1",
        "src_port": 12345,
        "dst_port": 80,
        "protocol": "TCP",
        "tcp_flags": 2,
    }
    alerts = monitor.analyze_packet(packet)
    alerts = [a for a in alerts if a is not None]

    if _has_alert(alerts, "ip_spoofing"):
        print("  PASSED - IP Spoofing detected!")
        passed_tests += 1
    else:
        print("  FAILED - IP Spoofing not detected")

    # Test 10: XMAS Scan Detection
    print("\n[TEST 10] XMAS Scan Detection")
    total_tests += 1
    _reset(monitor)
    alerts = []
    for port in [21, 22, 23, 25, 80]:
        packet = {
            "src_ip": "1.2.3.8",
            "dst_ip": "10.0.0.1",
            "src_port": 54321,
            "dst_port": port,
            "protocol": "TCP",
            "tcp_flags": 41,
        }
        result = monitor.analyze_packet(packet)
        alerts.extend(r for r in result if r is not None)

    if _has_alert(alerts, "port_scan"):
        xmas_alerts = [
            a for a in alerts
            if a is not None and "XMAS" in a.get("title", "")
        ]
        if xmas_alerts:
            print("  PASSED - XMAS Scan detected!")
            passed_tests += 1
        else:
            print("  FAILED - Port scan detected but not XMAS type")
    else:
        print("  FAILED - XMAS Scan not detected")

    # Summary
    print("\n" + "=" * 60)
    print(f"TEST RESULTS: {passed_tests}/{total_tests} tests passed")
    print("=" * 60)

    print(f"\nPacket Stats: {monitor.get_packet_stats()}")
    print(f"Alert Counts: {monitor.get_alert_counts()}")

    if passed_tests == total_tests:
        print("\nALL TESTS PASSED! Detection system is working correctly.")
    else:
        print(f"\n{total_tests - passed_tests} test(s) failed. Review detection thresholds.")

    return passed_tests == total_tests


if __name__ == "__main__":
    success = test_detection()
    sys.exit(0 if success else 1)
