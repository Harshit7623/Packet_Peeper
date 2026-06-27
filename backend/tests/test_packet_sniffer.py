import pytest
from scapy.all import IP, TCP, UDP, DNS, DNSQR
from packet_sniffer import classify_packet_service, match_ip_service, PacketSniffer

def test_match_ip_service():
    assert match_ip_service("142.250.190.46") == "google"
    assert match_ip_service("1.1.1.1") == "cloudflare"
    assert match_ip_service("9.9.9.9") is None

def test_classify_packet_service_dns():
    pkt = IP(src="192.168.1.1", dst="8.8.8.8") / UDP(sport=12345, dport=53) / DNS(rd=1, qr=0, qd=DNSQR(qname="www.youtube.com"))
    service = classify_packet_service(pkt)
    assert service == "youtube"

def test_classify_packet_service_port_fallback():
    pkt = IP(src="192.168.1.1", dst="93.184.216.34") / TCP(sport=12345, dport=80)
    assert classify_packet_service(pkt) == "HTTP"
    
    pkt_https = IP(src="192.168.1.1", dst="93.184.216.34") / TCP(sport=12345, dport=443)
    assert classify_packet_service(pkt_https) == "HTTPS"

def test_packet_sniffer_handle_packet():
    sniffer = PacketSniffer()
    captured = []
    sniffer.set_callback(lambda p: captured.append(p))
    
    pkt = IP(src="192.168.1.10", dst="142.250.190.46") / TCP(sport=12345, dport=443)
    sniffer.handle_packet(pkt)
    
    # Filter out security alerts if any
    packets = [p for p in captured if not p.get('alert_type')]
    assert len(packets) == 1
    packet_info = packets[0]
    
    assert packet_info['protocol'] == "TCP"
    assert packet_info['src_ip'] == "192.168.1.10"
    assert packet_info['dst_ip'] == "142.250.190.46"
    assert packet_info['src_port'] == 12345
    assert packet_info['dst_port'] == 443
    assert packet_info['service'] == "google"

def test_packet_sniffer_statistics():
    sniffer = PacketSniffer()
    sniffer.handle_packet(IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=10, dport=20))
    sniffer.handle_packet(IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=10, dport=20))
    
    stats = sniffer.get_statistics()
    assert stats['tcpPackets'] == 1
    assert stats['udpPackets'] == 1
    assert stats['totalPackets'] >= 2
