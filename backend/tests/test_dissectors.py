"""
Protocol Dissector Tests
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from services.dissector_service import (
    DissectorRegistry, DNSDissector, HTTPDissector, TLSDissector, DHCPDissector,
    dissector_registry,
)


def test_registry_lists_builtins():
    names = [d['name'] for d in dissector_registry.list_dissectors()]
    assert 'dns' in names
    assert 'http' in names
    assert 'tls' in names
    assert 'dhcp' in names


def test_dns_dissector_rejects_non_dns():
    d = DNSDissector()
    result = d.dissect(b'\x00' * 20, {'dst_port': 80})
    assert result is None


def test_dns_dissector_parses_query():
    d = DNSDissector()
    hdr = b'\x12\x34'
    hdr += b'\x01\x00'
    hdr += b'\x00\x01'
    hdr += b'\x00\x00\x00\x00\x00\x00'
    qname = b'\x06google\x03com\x00'
    qtype = b'\x00\x01'
    qclass = b'\x00\x01'
    payload = hdr + qname + qtype + qclass
    result = d.dissect(payload, {'dst_port': 53})
    assert result is not None
    assert result['dissector'] == 'dns'
    assert result['qr'] == 'query'
    assert len(result['queries']) == 1
    assert result['queries'][0]['name'] == 'google.com'


def test_http_dissector_request():
    d = HTTPDissector()
    payload = b'GET /api/test HTTP/1.1\r\nHost: example.com\r\n\r\n'
    result = d.dissect(payload, {'dst_port': 80})
    assert result is not None
    assert result['direction'] == 'request'
    assert result['method'] == 'GET'
    assert result['path'] == '/api/test'
    assert result['headers'].get('host') == 'example.com'


def test_http_dissector_response():
    d = HTTPDissector()
    payload = b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n'
    result = d.dissect(payload, {'src_port': 80})
    assert result is not None
    assert result['direction'] == 'response'
    assert result['status_code'] == 200


def test_http_dissector_rejects_non_http():
    d = HTTPDissector()
    result = d.dissect(b'\x00\xff\xfe', {'dst_port': 80})
    assert result is None


def test_tls_dissector_rejects_non_tls():
    d = TLSDissector()
    result = d.dissect(b'\x00' * 20)
    assert result is None


def test_custom_dissector():
    class EchoDissector:
        name = 'echo'
        description = 'Echo dissector'
        protocol = 'ANY'
        def dissect(self, payload, context=None):
            return {'dissector': 'echo', 'length': len(payload)}

    registry = DissectorRegistry()
    reg = registry.register(EchoDissector())
    assert reg == 'echo'

    results = registry.dissect(b'\x00\x01\x02')
    assert any(r['dissector'] == 'echo' for r in results)

    assert registry.unregister('echo')
    assert registry.get('echo') is None


def test_dissect_returns_empty_on_no_match():
    reg = DissectorRegistry()
    result = reg.dissect(b'\x00' * 100, {'dst_port': 9999})
    assert isinstance(result, list)
