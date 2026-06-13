"""
SIEM Integration Service Tests
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from services.siem_service import SIEMForwarder, siem_forwarder


def test_add_integration():
    f = SIEMForwarder()
    result = f.add_integration({'name': 'Test SIEM', 'type': 'webhook', 'url': 'https://example.com/webhook'})
    assert result['name'] == 'Test SIEM'
    assert result['type'] == 'webhook'
    assert result['enabled'] is True
    int_id = result['id']
    assert f.get_integration(int_id) is not None


def test_update_integration():
    f = SIEMForwarder()
    result = f.add_integration({'name': 'Test', 'type': 'syslog', 'host': '10.0.0.1'})
    int_id = result['id']
    updated = f.update_integration(int_id, {'name': 'Updated', 'port': 1514})
    assert updated['name'] == 'Updated'
    assert updated['port'] == 1514


def test_remove_integration():
    f = SIEMForwarder()
    result = f.add_integration({'name': 'Delete Me', 'type': 'webhook'})
    int_id = result['id']
    assert f.remove_integration(int_id) is True
    assert f.get_integration(int_id) is None


def test_remove_nonexistent():
    f = SIEMForwarder()
    assert f.remove_integration(99999) is False


def test_get_integrations():
    f = SIEMForwarder()
    f.add_integration({'name': 'A', 'type': 'webhook'})
    f.add_integration({'name': 'B', 'type': 'syslog'})
    integrations = f.get_integrations()
    assert len(integrations) == 2


def test_should_send_filter():
    f = SIEMForwarder()
    intg = {'severity_filter': ['high', 'critical']}
    assert f._should_send({'severity': 'critical'}, intg) is True
    assert f._should_send({'severity': 'high'}, intg) is True
    assert f._should_send({'severity': 'medium'}, intg) is False
    assert f._should_send({'severity': 'low'}, intg) is False


def test_should_send_empty_filter():
    f = SIEMForwarder()
    intg = {'severity_filter': []}
    assert f._should_send({'severity': 'low'}, intg) is True


def test_cef_format():
    f = SIEMForwarder()
    result = f._format_cef({
        'alert_type': 'port_scan',
        'title': 'Port Scan Detected',
        'severity': 'high',
        'source_ip': '10.0.0.1',
        'description': 'Scanning from 10.0.0.1',
    })
    assert result['version'] == '1.0'
    assert result['deviceVendor'] == 'PacketPeeper'
    assert result['severity'] == 7
    assert result['extensions']['src'] == '10.0.0.1'


def test_leef_format():
    f = SIEMForwarder()
    result = f._format_leef({
        'alert_type': 'ddos',
        'severity': 'critical',
        'source_ip': '192.168.1.1',
    })
    assert result['version'] == '2.0'
    assert result['vendor'] == 'PacketPeeper'
    assert result['eventID'] == 'ddos'


def test_cef_string_format():
    f = SIEMForwarder()
    result = f._format_cef_string({
        'alert_type': 'port_scan',
        'title': 'Test',
        'severity': 'high',
        'source_ip': '10.0.0.1',
        'destination_ip': '10.0.0.2',
        'description': 'Test alert',
    })
    assert result.startswith('CEF:1.0|PacketPeeper|NetworkMonitor|1.0|port_scan|Test|7|')


def test_enqueue_alert_starts_forwarder():
    f = SIEMForwarder()
    f._running = False
    f.enqueue_alert({'severity': 'high', 'title': 'test'})
    assert f._running is True
    f.stop()
