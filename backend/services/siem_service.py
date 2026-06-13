"""
SIEM Integration Service
Forwards alerts and security events to external SIEM systems via syslog or webhook.
"""

import json
import logging
import socket
import struct
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional

import requests as http_requests

logger = logging.getLogger('packet_peeper')


class SIEMForwarder:
    def __init__(self):
        self._lock = threading.Lock()
        self._integrations: Dict[int, Dict] = {}
        self._queue: List[Dict] = []
        self._running = False
        self._thread = None
        self._batch_size = 50
        self._flush_interval = 5.0
        self._next_id = 1

    def add_integration(self, config: Dict) -> Dict:
        integration = {
            'id': config.get('id', self._next_id),
            'name': config.get('name', 'SIEM'),
            'type': config.get('type', 'webhook'),
            'enabled': config.get('enabled', True),
            'url': config.get('url', ''),
            'host': config.get('host', ''),
            'port': config.get('port', 514),
            'protocol': config.get('protocol', 'udp'),
            'format': config.get('format', 'cef'),
            'headers': config.get('headers', {}),
            'severity_filter': config.get('severity_filter', ['high', 'critical']),
            'verify_ssl': config.get('verify_ssl', True),
            'last_error': None,
            'last_sent': None,
            'sent_count': 0,
            'error_count': 0,
        }
        with self._lock:
            self._integrations[integration['id']] = integration
            self._next_id = max(self._next_id, integration['id'] + 1)
        return integration

    def update_integration(self, int_id: int, updates: Dict) -> Optional[Dict]:
        with self._lock:
            integration = self._integrations.get(int_id)
            if not integration:
                return None
            for k, v in updates.items():
                if k in integration and k != 'id':
                    integration[k] = v
            return integration

    def remove_integration(self, int_id: int) -> bool:
        with self._lock:
            return self._integrations.pop(int_id, None) is not None

    def get_integrations(self) -> List[Dict]:
        with self._lock:
            return list(self._integrations.values())

    def get_integration(self, int_id: int) -> Optional[Dict]:
        with self._lock:
            return self._integrations.get(int_id)

    def enqueue_alert(self, alert: Dict):
        self._queue.append(alert)
        if not self._running:
            self.start()

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._forward_loop, daemon=True, name="siem-forwarder")
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        self._thread = None

    def _forward_loop(self):
        while self._running:
            try:
                if not self._queue:
                    time.sleep(self._flush_interval)
                    continue
                batch = self._queue[:self._batch_size]
                self._queue = self._queue[len(batch):]
                with self._lock:
                    integrations = [i for i in self._integrations.values() if i.get('enabled')]
                for integration in integrations:
                    for alert in batch:
                        self._send(alert, integration)
            except Exception as e:
                logger.error(f"[SIEM] Forward loop error: {e}")
                time.sleep(self._flush_interval)

    def _should_send(self, alert: Dict, integration: Dict) -> bool:
        severity_filter = integration.get('severity_filter', [])
        if not severity_filter:
            return True
        return alert.get('severity', 'medium') in severity_filter

    def _send(self, alert: Dict, integration: Dict):
        if not self._should_send(alert, integration):
            return
        try:
            int_type = integration.get('type', 'webhook')
            if int_type == 'webhook':
                self._send_webhook(alert, integration)
            elif int_type == 'syslog':
                self._send_syslog(alert, integration)
            integration['last_sent'] = datetime.utcnow().isoformat()
            integration['sent_count'] += 1
            integration['last_error'] = None
        except Exception as e:
            integration['error_count'] += 1
            integration['last_error'] = str(e)
            logger.error(f"[SIEM] {integration.get('name')}: {e}")

    def _send_webhook(self, alert: Dict, integration: Dict):
        url = integration.get('url', '')
        if not url:
            return
        fmt = integration.get('format', 'cef')
        if fmt == 'cef':
            payload = self._format_cef(alert)
        elif fmt == 'json':
            payload = alert
        elif fmt == 'leef':
            payload = self._format_leef(alert)
        else:
            payload = alert

        headers = {'Content-Type': 'application/json'}
        headers.update(integration.get('headers', {}))

        http_requests.post(
            url,
            json=payload,
            headers=headers,
            timeout=10,
            verify=integration.get('verify_ssl', True),
        )

    def _send_syslog(self, alert: Dict, integration: Dict):
        host = integration.get('host', 'localhost')
        port = integration.get('port', 514)
        protocol = integration.get('protocol', 'udp')
        fmt = integration.get('format', 'cef')

        if fmt == 'cef':
            message = self._format_cef_string(alert)
        elif fmt == 'leef':
            message = self._format_leef_string(alert)
        else:
            message = json.dumps(alert)

        severity = alert.get('severity', 'medium')
        pri = 10
        if severity == 'critical':
            pri = 10
        elif severity == 'high':
            pri = 11
        elif severity == 'medium':
            pri = 13
        else:
            pri = 14

        syslog_msg = f"<{pri}>1 {datetime.utcnow().isoformat()} packet-peeper - - - {message}"

        if protocol == 'udp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.sendto(syslog_msg.encode('utf-8'), (host, port))
            finally:
                sock.close()
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.settimeout(5)
                sock.connect((host, port))
                sock.sendall(syslog_msg.encode('utf-8'))
            finally:
                sock.close()

    def _format_cef(self, alert: Dict) -> Dict:
        severity_map = {'low': 3, 'medium': 5, 'high': 7, 'critical': 9}
        return {
            'version': '1.0',
            'deviceVendor': 'PacketPeeper',
            'deviceProduct': 'NetworkMonitor',
            'deviceVersion': '1.0',
            'signatureId': alert.get('alert_type', alert.get('type', 'unknown')),
            'name': alert.get('title', 'Security Alert'),
            'severity': severity_map.get(alert.get('severity', 'medium'), 5),
            'extensions': {
                'src': alert.get('source_ip', alert.get('source', 'unknown')),
                'dst': alert.get('destination_ip', ''),
                'msg': alert.get('description', ''),
                'rt': alert.get('timestamp', datetime.utcnow().isoformat()),
            },
        }

    def _format_cef_string(self, alert: Dict) -> str:
        cef = self._format_cef(alert)
        exts = ' '.join(f'{k}={v}' for k, v in cef.get('extensions', {}).items())
        return (
            f"CEF:{cef['version']}|{cef['deviceVendor']}|{cef['deviceProduct']}|"
            f"{cef['deviceVersion']}|{cef['signatureId']}|{cef['name']}|"
            f"{cef['severity']}|{exts}"
        )

    def _format_leef(self, alert: Dict) -> Dict:
        return {
            'version': '2.0',
            'vendor': 'PacketPeeper',
            'product': 'NetworkMonitor',
            'eventID': alert.get('alert_type', alert.get('type', 'unknown')),
            'severity': alert.get('severity', 'medium'),
            'attributes': {
                'src': alert.get('source_ip', alert.get('source', 'unknown')),
                'dst': alert.get('destination_ip', ''),
                'msg': alert.get('description', ''),
                'cat': alert.get('alert_type', ''),
            },
        }

    def _format_leef_string(self, alert: Dict) -> str:
        leef = self._format_leef(alert)
        attrs = '\t'.join(f'{k}={v}' for k, v in leef.get('attributes', {}).items())
        return (
            f"LEEF:{leef['version']}|{leef['vendor']}|{leef['product']}|"
            f"{leef['eventID']}|{leef['severity']}|{attrs}"
        )


siem_forwarder = SIEMForwarder()
