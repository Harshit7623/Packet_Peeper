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

def test_detection():
    """Test all detection types"""
    
    monitor = NetworkSecurityMonitor()
    print("\n" + "="*60)
    print("🧪 TESTING NETWORK SECURITY MONITOR DETECTION")
    print("="*60)
    
    total_tests = 0
    passed_tests = 0
    
    # Test 1: Port Scan Detection
    print("\n[TEST 1] Port Scan Detection")
    total_tests += 1
    alerts = []
    for port in range(1, 20):  # Scan 20 ports
        packet = {
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.1',
            'src_port': 54321,
            'dst_port': port,
            'protocol': 'TCP',
            'tcp_flags': 2,  # SYN
        }
        result = monitor.analyze_packet(packet)
        alerts.extend(result)
    
    if any(a['type'] == 'port_scan' for a in alerts):
        print("  ✅ PASSED - Port scan detected!")
        passed_tests += 1
    else:
        print("  ❌ FAILED - Port scan not detected")
    
    # Test 2: SYN Flood Detection
    print("\n[TEST 2] SYN Flood Detection")
    total_tests += 1
    monitor.clear_tracking()  # Reset state
    alerts = []
    for i in range(150):  # Send 150 SYN packets in short time
        packet = {
            'src_ip': '10.0.0.50',
            'dst_ip': '192.168.1.1',
            'src_port': 54000 + i,
            'dst_port': 80,
            'protocol': 'TCP',
            'tcp_flags': 2,
            'payload': '',
        }
        result = monitor.analyze_packet(packet)
        alerts.extend(result)
    
    if any(a['type'] == 'dos_flood' for a in alerts):
        print("  ✅ PASSED - SYN Flood detected!")
        passed_tests += 1
    else:
        print("  ❌ FAILED - SYN Flood not detected")
    
    # Test 3: Brute Force Detection
    print("\n[TEST 3] Brute Force Detection")
    total_tests += 1
    monitor.clear_tracking()
    alerts = []
    for i in range(10):  # 10 SSH connection attempts
        packet = {
            'src_ip': '172.16.0.100',
            'dst_ip': '192.168.1.10',
            'src_port': 50000 + i,
            'dst_port': 22,  # SSH
            'protocol': 'TCP',
            'tcp_flags': 2,
        }
        result = monitor.analyze_packet(packet)
        alerts.extend(result)
    
    if any(a['type'] == 'brute_force' for a in alerts):
        print("  ✅ PASSED - Brute force detected!")
        passed_tests += 1
    else:
        print("  ❌ FAILED - Brute force not detected")
    
    # Test 4: SQL Injection Detection
    print("\n[TEST 4] SQL Injection Detection")
    total_tests += 1
    monitor.clear_tracking()
    packet = {
        'src_ip': '192.168.1.200',
        'dst_ip': '192.168.1.1',
        'src_port': 45678,
        'dst_port': 80,
        'protocol': 'HTTP',
        'payload': "GET /login?user=' OR '1'='1' -- HTTP/1.1",
    }
    alerts = monitor.analyze_packet(packet)
    
    if any(a['type'] == 'sql_injection' for a in alerts):
        print("  ✅ PASSED - SQL Injection detected!")
        passed_tests += 1
    else:
        print("  ❌ FAILED - SQL Injection not detected")
    
    # Test 5: XSS Detection
    print("\n[TEST 5] XSS Detection")
    total_tests += 1
    monitor.clear_tracking()
    time.sleep(0.1)  # Small delay to reset cooldown
    packet = {
        'src_ip': '192.168.1.201',
        'dst_ip': '192.168.1.1',
        'src_port': 45679,
        'dst_port': 80,
        'protocol': 'HTTP',
        'payload': "GET /search?q=<script>alert('xss')</script> HTTP/1.1",
    }
    alerts = monitor.analyze_packet(packet)
    
    if any(a['type'] == 'xss' for a in alerts):
        print("  ✅ PASSED - XSS detected!")
        passed_tests += 1
    else:
        print("  ❌ FAILED - XSS not detected")
    
    # Test 6: DNS Tunneling Detection
    print("\n[TEST 6] DNS Tunneling Detection")
    total_tests += 1
    monitor.clear_tracking()
    alerts = []
    for i in range(15):  # Multiple DNS queries with suspicious patterns
        packet = {
            'src_ip': '192.168.1.150',
            'dst_ip': '8.8.8.8',
            'src_port': 50000 + i,
            'dst_port': 53,
            'protocol': 'DNS',
            'payload': f"YWRtaW46cGFzc3dvcmQxMjM0NTY3ODkw.data{i}.tunnel.evil.com",  # Base64-like
        }
        result = monitor.analyze_packet(packet)
        alerts.extend(result)
    
    if any(a['type'] == 'dns_tunneling' for a in alerts):
        print("  ✅ PASSED - DNS Tunneling detected!")
        passed_tests += 1
    else:
        print("  ❌ FAILED - DNS Tunneling not detected")
    
    # Test 7: LAND Attack Detection
    print("\n[TEST 7] LAND Attack Detection")
    total_tests += 1
    monitor.clear_tracking()
    packet = {
        'src_ip': '192.168.1.50',
        'dst_ip': '192.168.1.50',  # Same as source
        'src_port': 80,
        'dst_port': 80,
        'protocol': 'TCP',
        'tcp_flags': 2,
    }
    alerts = monitor.analyze_packet(packet)
    
    if any(a['type'] == 'land_attack' for a in alerts):
        print("  ✅ PASSED - LAND Attack detected!")
        passed_tests += 1
    else:
        print("  ❌ FAILED - LAND Attack not detected")
    
    # Test 8: Command Injection Detection
    print("\n[TEST 8] Command Injection Detection")
    total_tests += 1
    monitor.clear_tracking()
    time.sleep(0.1)
    packet = {
        'src_ip': '192.168.1.202',
        'dst_ip': '192.168.1.1',
        'src_port': 45680,
        'dst_port': 80,
        'protocol': 'HTTP',
        'payload': "GET /ping?host=127.0.0.1; cat /etc/passwd HTTP/1.1",
    }
    alerts = monitor.analyze_packet(packet)
    
    if any(a['type'] == 'command_injection' for a in alerts):
        print("  ✅ PASSED - Command Injection detected!")
        passed_tests += 1
    else:
        print("  ❌ FAILED - Command Injection not detected")
    
    # Test 9: IP Spoofing Detection
    print("\n[TEST 9] IP Spoofing Detection")
    total_tests += 1
    monitor.clear_tracking()
    packet = {
        'src_ip': '255.255.255.255',  # Broadcast as source
        'dst_ip': '192.168.1.1',
        'src_port': 12345,
        'dst_port': 80,
        'protocol': 'TCP',
        'tcp_flags': 2,
    }
    alerts = monitor.analyze_packet(packet)
    
    if any(a['type'] == 'ip_spoofing' for a in alerts):
        print("  ✅ PASSED - IP Spoofing detected!")
        passed_tests += 1
    else:
        print("  ❌ FAILED - IP Spoofing not detected")
    
    # Test 10: XMAS Scan Detection
    print("\n[TEST 10] XMAS Scan Detection")
    total_tests += 1
    monitor.clear_tracking()
    alerts = []
    for port in [21, 22, 23, 25, 80]:
        packet = {
            'src_ip': '192.168.1.250',
            'dst_ip': '192.168.1.1',
            'src_port': 54321,
            'dst_port': port,
            'protocol': 'TCP',
            'tcp_flags': 41,  # FIN + PSH + URG
        }
        result = monitor.analyze_packet(packet)
        alerts.extend(result)
    
    if any('XMAS' in a.get('title', '') for a in alerts):
        print("  ✅ PASSED - XMAS Scan detected!")
        passed_tests += 1
    else:
        print("  ❌ FAILED - XMAS Scan not detected")
    
    # Summary
    print("\n" + "="*60)
    print(f"📊 TEST RESULTS: {passed_tests}/{total_tests} tests passed")
    print("="*60)
    
    # Show stats
    print(f"\n📈 Packet Stats: {monitor.get_packet_stats()}")
    print(f"🚨 Alert Counts: {monitor.get_alert_counts()}")
    
    if passed_tests == total_tests:
        print("\n🎉 ALL TESTS PASSED! Detection system is working correctly.")
    else:
        print(f"\n⚠️ {total_tests - passed_tests} test(s) failed. Review detection thresholds.")
    
    return passed_tests == total_tests


if __name__ == "__main__":
    success = test_detection()
    sys.exit(0 if success else 1)
