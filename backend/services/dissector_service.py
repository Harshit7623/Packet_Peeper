"""
Protocol Dissection Plugin System
Pluggable protocol dissectors for deep packet inspection.
Built-in dissectors: DNS, HTTP, TLS, DHCP.
Custom dissectors can be registered dynamically.
"""

import json
import logging
import struct
from typing import Dict, List, Optional, Callable

logger = logging.getLogger('packet_peeper')


class ProtocolDissector:
    name: str = 'base'
    description: str = ''
    protocol: str = ''

    def dissect(self, payload: bytes, context: Dict = None) -> Optional[Dict]:
        return None


class DNSDissector(ProtocolDissector):
    name = 'dns'
    description = 'DNS protocol dissector'
    protocol = 'UDP'

    def dissect(self, payload: bytes, context: Dict = None) -> Optional[Dict]:
        ctx = context or {}
        dst_port = ctx.get('dst_port')
        src_port = ctx.get('src_port')
        if dst_port != 53 and src_port != 53:
            return None
        if len(payload) < 12:
            return None
        try:
            tid = struct.unpack('!H', payload[0:2])[0]
            flags = struct.unpack('!H', payload[2:4])[0]
            qr = (flags >> 15) & 1
            opcode = (flags >> 11) & 0xF
            rcode = flags & 0xF
            qdcount = struct.unpack('!H', payload[4:6])[0]
            ancount = struct.unpack('!H', payload[6:8])[0]

            queries = []
            offset = 12
            for _ in range(min(qdcount, 10)):
                if offset >= len(payload):
                    break
                qname, offset = self._parse_name(payload, offset)
                if offset + 4 > len(payload):
                    break
                qtype = struct.unpack('!H', payload[offset:offset + 2])[0]
                qclass = struct.unpack('!H', payload[offset + 2:offset + 4])[0]
                offset += 4
                queries.append({
                    'name': qname,
                    'type': qtype,
                    'class': qclass,
                })

            return {
                'dissector': self.name,
                'transaction_id': tid,
                'qr': 'response' if qr else 'query',
                'opcode': opcode,
                'rcode': rcode,
                'questions': qdcount,
                'answers': ancount,
                'queries': queries[:5],
            }
        except Exception:
            return None

    def _parse_name(self, data: bytes, offset: int) -> tuple:
        labels = []
        jumped = False
        original_offset = offset
        max_jumps = 10
        jumps = 0
        while offset < len(data):
            length = data[offset]
            if length == 0:
                if not jumped:
                    offset += 1
                break
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    break
                pointer = struct.unpack('!H', data[offset:offset + 2])[0] & 0x3FFF
                if not jumped:
                    original_offset = offset + 2
                offset = pointer
                jumped = True
                jumps += 1
                if jumps > max_jumps:
                    break
            else:
                start = offset + 1
                end = start + length
                if end > len(data):
                    break
                labels.append(data[start:end].decode('utf-8', errors='replace'))
                offset = end
        return '.'.join(labels), original_offset if jumped else offset


class HTTPDissector(ProtocolDissector):
    name = 'http'
    description = 'HTTP protocol dissector'
    protocol = 'TCP'

    def dissect(self, payload: bytes, context: Dict = None) -> Optional[Dict]:
        ctx = context or {}
        dst_port = ctx.get('dst_port')
        src_port = ctx.get('src_port')
        if dst_port not in (80, 8080, 8000, 3000) and src_port not in (80, 8080, 8000, 3000):
            return None
        try:
            text = payload[:4096].decode('utf-8', errors='replace')
            lines = text.split('\r\n')
            if not lines:
                return None
            first_line = lines[0]
            if first_line.startswith('HTTP/'):
                parts = first_line.split(' ', 2)
                return {
                    'dissector': self.name,
                    'direction': 'response',
                    'version': parts[0],
                    'status_code': int(parts[1]) if len(parts) > 1 else 0,
                    'reason': parts[2] if len(parts) > 2 else '',
                    'headers': self._parse_headers(lines[1:]),
                }
            elif any(first_line.startswith(m) for m in ('GET ', 'POST ', 'PUT ', 'DELETE ', 'PATCH ', 'HEAD ', 'OPTIONS ', 'CONNECT ')):
                parts = first_line.split(' ', 2)
                return {
                    'dissector': self.name,
                    'direction': 'request',
                    'method': parts[0],
                    'path': parts[1] if len(parts) > 1 else '/',
                    'version': parts[2] if len(parts) > 2 else '',
                    'headers': self._parse_headers(lines[1:]),
                }
            return None
        except Exception:
            return None

    def _parse_headers(self, lines: List[str]) -> Dict:
        headers = {}
        for line in lines:
            if ':' in line:
                key, _, value = line.partition(':')
                headers[key.strip().lower()] = value.strip()
            elif not line:
                break
        return headers


class TLSDissector(ProtocolDissector):
    name = 'tls'
    description = 'TLS ClientHello SNI dissector'
    protocol = 'TCP'

    def dissect(self, payload: bytes, context: Dict = None) -> Optional[Dict]:
        if len(payload) < 5:
            return None
        try:
            content_type = payload[0]
            if content_type != 22:
                return None
            version = struct.unpack('!H', payload[1:3])[0]
            length = struct.unpack('!H', payload[3:5])[0]
            if len(payload) < 5 + length or length < 4:
                return None
            handshake_type = payload[5]
            if handshake_type != 1:
                return None
            hs_len = struct.unpack('!I', b'\x00' + payload[6:9])[0]
            offset = 5 + 4
            if offset + 2 > len(payload):
                return None
            client_version = struct.unpack('!H', payload[offset:offset + 2])[0]
            offset += 32
            session_id_len = payload[offset] if offset < len(payload) else 0
            offset += 1 + session_id_len
            if offset + 2 > len(payload):
                return None
            cipher_len = struct.unpack('!H', payload[offset:offset + 2])[0]
            offset += 2 + cipher_len
            if offset >= len(payload):
                return None
            comp_len = payload[offset]
            offset += 1 + comp_len
            if offset + 2 > len(payload):
                return None
            ext_total = struct.unpack('!H', payload[offset:offset + 2])[0]
            offset += 2
            ext_end = offset + ext_total
            sni = None
            while offset + 4 <= ext_end and offset + 4 <= len(payload):
                ext_type = struct.unpack('!H', payload[offset:offset + 2])[0]
                ext_len = struct.unpack('!H', payload[offset + 2:offset + 4])[0]
                offset += 4
                if ext_type == 0 and offset + ext_len <= len(payload):
                    sni_list_len = struct.unpack('!H', payload[offset + 2:offset + 4])[0]
                    sni_type = payload[offset + 4]
                    if sni_type == 0:
                        sni_len = struct.unpack('!H', payload[offset + 5:offset + 7])[0]
                        sni = payload[offset + 7:offset + 7 + sni_len].decode('utf-8', errors='replace')
                offset += ext_len
            return {
                'dissector': self.name,
                'record_version': version,
                'client_version': client_version,
                'sni': sni,
            }
        except Exception:
            return None


class DHCPDissector(ProtocolDissector):
    name = 'dhcp'
    description = 'DHCP protocol dissector'
    protocol = 'UDP'

    def dissect(self, payload: bytes, context: Dict = None) -> Optional[Dict]:
        ctx = context or {}
        dst_port = ctx.get('dst_port')
        src_port = ctx.get('src_port')
        if dst_port not in (67, 68) and src_port not in (67, 68):
            return None
        if len(payload) < 240:
            return None
        try:
            op = payload[0]
            htype = payload[1]
            hlen = payload[2]
            xid = struct.unpack('!I', payload[4:8])[0]
            ciaddr = '.'.join(str(b) for b in payload[16:20])
            yiaddr = '.'.join(str(b) for b in payload[20:24])
            siaddr = '.'.join(str(b) for b in payload[24:28])
            giaddr = '.'.join(str(b) for b in payload[28:32])
            chaddr = ':'.join(f'{b:02x}' for b in payload[28:28 + hlen])

            magic = struct.unpack('!I', payload[236:240])[0]
            if magic != 0x63825363:
                return None

            return {
                'dissector': self.name,
                'op': {1: 'DISCOVER', 2: 'OFFER', 3: 'REQUEST', 4: 'DECLINE', 5: 'ACK', 6: 'NAK', 7: 'RELEASE', 8: 'INFORM'}.get(op, f'unknown({op})'),
                'transaction_id': xid,
                'client_ip': ciaddr,
                'your_ip': yiaddr,
                'server_ip': siaddr,
                'relay_ip': giaddr,
                'client_mac': chaddr,
            }
        except Exception:
            return None


class DissectorRegistry:
    def __init__(self):
        self._dissectors: Dict[str, ProtocolDissector] = {}
        self._port_map: Dict[int, List[str]] = {}
        self._register_builtins()

    def _register_builtins(self):
        for cls in [DNSDissector, HTTPDissector, TLSDissector, DHCPDissector]:
            inst = cls()
            self.register(inst)

    def register(self, dissector: ProtocolDissector):
        self._dissectors[dissector.name] = dissector
        return dissector.name

    def unregister(self, name: str) -> bool:
        return self._dissectors.pop(name, None) is not None

    def get(self, name: str) -> Optional[ProtocolDissector]:
        return self._dissectors.get(name)

    def list_dissectors(self) -> List[Dict]:
        return [
            {'name': d.name, 'description': d.description, 'protocol': d.protocol}
            for d in self._dissectors.values()
        ]

    def dissect(self, payload: bytes, context: Dict = None) -> List[Dict]:
        results = []
        for dissector in self._dissectors.values():
            try:
                result = dissector.dissect(payload, context)
                if result:
                    results.append(result)
            except Exception:
                pass
        return results


dissector_registry = DissectorRegistry()
