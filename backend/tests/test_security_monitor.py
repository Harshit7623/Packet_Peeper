import pytest
from network_security_monitor import NetworkSecurityMonitor

def test_port_scan_detection():
    monitor = NetworkSecurityMonitor()
    # Ensure test mode for deterministic behavior and lower thresholds
    monitor.enable_test_mode()
    
    src_ip = "192.168.1.100"
    dst_ip = "10.0.0.1"
    
    alerts = []
    # Send 4 unique ports (below threshold)
    for port in [22, 80, 443, 8080]:
        packet = {'src_ip': src_ip, 'dst_ip': dst_ip, 'dst_port': port, 'protocol': 'TCP', 'tcp_flags': 2, 'length': 60}
        alerts.extend(monitor.analyze_packet(packet))
        
    assert not any(a['alert_type'] == 'port_scan' for a in alerts)
        
    # 5th port
    packet = {'src_ip': src_ip, 'dst_ip': dst_ip, 'dst_port': 3306, 'protocol': 'TCP', 'tcp_flags': 2, 'length': 60}
    alerts.extend(monitor.analyze_packet(packet))
    
    assert any(a.get('type') == 'port_scan' for a in alerts)

def test_ddos_detection():
    monitor = NetworkSecurityMonitor()
    monitor.enable_test_mode()
    
    src_ip = "192.168.1.200"
    dst_ip = "10.0.0.2"
    
    alerts = []
    # Threshold in test mode is usually 10
    for _ in range(11):
        packet = {'src_ip': src_ip, 'dst_ip': dst_ip, 'length': 64, 'protocol': 'TCP', 'dst_port': 80}
        alerts.extend(monitor.analyze_packet(packet))
        
    assert any(a.get('type') in ['flood', 'ddos'] for a in alerts)

def test_brute_force_detection():
    monitor = NetworkSecurityMonitor()
    monitor.enable_test_mode()
    
    src_ip = "10.0.0.50"
    dst_ip = "192.168.1.10"
    
    alerts = []
    # Threshold in test mode is 5
    for _ in range(6):
        packet = {'src_ip': src_ip, 'dst_ip': dst_ip, 'dst_port': 22, 'protocol': 'TCP', 'tcp_flags': 2, 'length': 60}
        alerts.extend(monitor.analyze_packet(packet))
        
    assert any(a.get('type') == 'brute_force' for a in alerts)
