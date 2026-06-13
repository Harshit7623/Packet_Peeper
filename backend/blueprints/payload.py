"""
Payload Inspection API
Deep packet inspection endpoint — returns hex dump, ASCII, and protocol-layer details.
"""

import logging

from flask import Blueprint, request, jsonify

from config.config import FEATURES

import extensions as ext

payload_bp = Blueprint('payload', __name__, url_prefix='/api/payload')

_MAX_PAYLOAD_BYTES = 4096
_HEX_WIDTH = 16


def _hex_dump(data: bytes, width: int = _HEX_WIDTH) -> dict:
    hex_lines = []
    ascii_lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        hex_part = hex_part.ljust(width * 3 - 1)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        hex_lines.append(f'{offset:08x}  {hex_part}')
        ascii_lines.append(ascii_part)
    return {'hex': hex_lines, 'ascii': ascii_lines, 'total_bytes': len(data)}


def _extract_layers(packet) -> list:
    layers = []
    try:
        from scapy.all import IP, TCP, UDP, ICMP, DNS, Raw
        if packet.haslayer(IP):
            ip = packet[IP]
            layers.append({
                'name': 'IP',
                'fields': {
                    'version': ip.version,
                    'ihl': ip.ihl,
                    'ttl': ip.ttl,
                    'protocol': ip.proto,
                    'src': ip.src,
                    'dst': ip.dst,
                    'id': ip.id,
                    'flags': ip.flags,
                    'fragment_offset': ip.frag,
                    'total_length': ip.len,
                },
            })
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            layers.append({
                'name': 'TCP',
                'fields': {
                    'src_port': tcp.sport,
                    'dst_port': tcp.dport,
                    'seq': tcp.seq,
                    'ack': tcp.ack,
                    'data_offset': tcp.dataofs,
                    'flags': str(tcp.flags),
                    'window': tcp.window,
                    'urgent_ptr': tcp.urgptr,
                },
            })
        if packet.haslayer(UDP):
            udp = packet[UDP]
            layers.append({
                'name': 'UDP',
                'fields': {
                    'src_port': udp.sport,
                    'dst_port': udp.dport,
                    'length': udp.len,
                },
            })
        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            layers.append({
                'name': 'ICMP',
                'fields': {
                    'type': icmp.type,
                    'code': icmp.code,
                    'id': getattr(icmp, 'id', None),
                    'seq': getattr(icmp, 'seq', None),
                },
            })
        if packet.haslayer(DNS):
            dns = packet[DNS]
            layers.append({
                'name': 'DNS',
                'fields': {
                    'qr': dns.qr,
                    'opcode': dns.opcode,
                    'rcode': dns.rcode,
                    'qdcount': dns.qdcount,
                    'ancount': dns.ancount,
                    'query': dns.qd.qname.decode() if dns.qd and dns.qd.qname else None,
                },
            })
    except Exception:
        pass
    return layers


@payload_bp.route('/<int:packet_id>', methods=['GET'])
def inspect_packet(packet_id):
    if not ext.sniffer:
        return jsonify({'error': 'Sniffer not running'}), 503

    sniffer = ext.sniffer
    raw_packets = getattr(sniffer, '_raw_packet_buffer', [])

    if packet_id < 0 or packet_id >= len(raw_packets):
        if ext.db_service and FEATURES.get('persistent_storage'):
            return jsonify({'error': 'Payload inspection requires live capture data (not DB records)'}), 404
        return jsonify({'error': 'Packet not found'}), 404

    raw_packet = raw_packets[packet_id]
    max_bytes = request.args.get('max_bytes', _MAX_PAYLOAD_BYTES, type=int)
    max_bytes = min(max_bytes, 65536)

    try:
        raw_bytes = bytes(raw_packet)[:max_bytes]
    except Exception:
        return jsonify({'error': 'Could not serialize packet'}), 500

    dump = _hex_dump(raw_bytes)
    layers = _extract_layers(raw_packet)

    packet_meta = {}
    captured = sniffer.captured_packets
    if packet_id < len(captured):
        packet_meta = captured[packet_id]

    return jsonify({
        'packet_id': packet_id,
        'meta': packet_meta,
        'layers': layers,
        'hex_dump': dump['hex'],
        'ascii_dump': dump['ascii'],
        'total_bytes': dump['total_bytes'],
        'truncated': len(bytes(raw_packet)) > max_bytes,
        'raw_size': len(bytes(raw_packet)),
    })


@payload_bp.route('/recent', methods=['GET'])
def recent_payloads():
    if not ext.sniffer:
        return jsonify({'error': 'Sniffer not running'}), 503

    limit = request.args.get('limit', 50, type=int)
    limit = min(limit, 200)

    sniffer = ext.sniffer
    raw_packets = getattr(sniffer, '_raw_packet_buffer', [])
    captured = sniffer.captured_packets

    start = max(0, len(captured) - limit)
    results = []
    for i in range(start, len(captured)):
        meta = captured[i]
        has_raw = i < len(raw_packets)
        raw_size = 0
        if has_raw:
            try:
                raw_size = len(bytes(raw_packets[i]))
            except Exception:
                pass
        results.append({
            'index': i,
            'has_raw': has_raw,
            'raw_size': raw_size,
            'timestamp': meta.get('timestamp'),
            'protocol': meta.get('protocol'),
            'src_ip': meta.get('src_ip'),
            'dst_ip': meta.get('dst_ip'),
            'src_port': meta.get('src_port'),
            'dst_port': meta.get('dst_port'),
            'length': meta.get('length'),
            'service': meta.get('service'),
        })

    return jsonify({
        'packets': results,
        'total': len(captured),
        'offset': start,
    })
