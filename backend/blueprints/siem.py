"""
SIEM Integration API
CRUD + test endpoints for SIEM forwarding integrations.
"""

import json
import logging

from flask import Blueprint, request, jsonify, g

import extensions as ext

siem_bp = Blueprint('siem', __name__, url_prefix='/api/siem')

logger = logging.getLogger('packet_peeper')


def _get_forwarder():
    from services.siem_service import siem_forwarder
    return siem_forwarder


@siem_bp.route('/integrations', methods=['GET'])
def list_integrations():
    forwarder = _get_forwarder()
    integrations = forwarder.get_integrations()
    return jsonify({'integrations': integrations, 'total': len(integrations)})


@siem_bp.route('/integrations', methods=['POST'])
def create_integration():
    data = request.get_json(silent=True) or {}
    name = data.get('name', '').strip()
    int_type = data.get('type', 'webhook')
    if not name:
        return jsonify({'error': 'Name is required'}), 400
    if int_type not in ('webhook', 'syslog'):
        return jsonify({'error': 'Type must be webhook or syslog'}), 400

    config = {
        'name': name,
        'type': int_type,
        'url': data.get('url', ''),
        'host': data.get('host', ''),
        'port': data.get('port', 514),
        'protocol': data.get('protocol', 'udp'),
        'format': data.get('format', 'cef'),
        'headers': data.get('headers', {}),
        'severity_filter': data.get('severity_filter', ['high', 'critical']),
        'verify_ssl': data.get('verify_ssl', True),
        'enabled': data.get('enabled', True),
    }

    forwarder = _get_forwarder()
    result = forwarder.add_integration(config)
    ext.add_log('info', 'SIEM', f"Created integration: {name} ({int_type})")
    return jsonify(result), 201


@siem_bp.route('/integrations/<int:int_id>', methods=['GET'])
def get_integration(int_id):
    forwarder = _get_forwarder()
    integration = forwarder.get_integration(int_id)
    if not integration:
        return jsonify({'error': 'Integration not found'}), 404
    return jsonify(integration)


@siem_bp.route('/integrations/<int:int_id>', methods=['PUT'])
def update_integration(int_id):
    data = request.get_json(silent=True) or {}
    forwarder = _get_forwarder()
    result = forwarder.update_integration(int_id, data)
    if not result:
        return jsonify({'error': 'Integration not found'}), 404
    return jsonify(result)


@siem_bp.route('/integrations/<int:int_id>', methods=['DELETE'])
def delete_integration(int_id):
    forwarder = _get_forwarder()
    success = forwarder.remove_integration(int_id)
    if not success:
        return jsonify({'error': 'Integration not found'}), 404
    ext.add_log('info', 'SIEM', f"Deleted integration ID {int_id}")
    return jsonify({'message': 'Integration deleted'})


@siem_bp.route('/integrations/<int:int_id>/toggle', methods=['POST'])
def toggle_integration(int_id):
    forwarder = _get_forwarder()
    integration = forwarder.get_integration(int_id)
    if not integration:
        return jsonify({'error': 'Integration not found'}), 404
    result = forwarder.update_integration(int_id, {'enabled': not integration.get('enabled', True)})
    return jsonify(result)


@siem_bp.route('/integrations/<int:int_id>/test', methods=['POST'])
def test_integration(int_id):
    forwarder = _get_forwarder()
    integration = forwarder.get_integration(int_id)
    if not integration:
        return jsonify({'error': 'Integration not found'}), 404

    test_alert = {
        'alert_type': 'test',
        'title': 'SIEM Integration Test',
        'description': 'This is a test alert from Packet Peeper',
        'severity': 'medium',
        'source_ip': '127.0.0.1',
        'destination_ip': '127.0.0.1',
        'timestamp': __import__('datetime').datetime.utcnow().isoformat(),
    }

    try:
        forwarder._send(test_alert, integration)
        if integration.get('last_error'):
            return jsonify({'success': False, 'error': integration['last_error']}), 400
        return jsonify({'success': True, 'message': 'Test alert sent successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@siem_bp.route('/integrations/<int:int_id>/logs', methods=['GET'])
def integration_logs(int_id):
    forwarder = _get_forwarder()
    integration = forwarder.get_integration(int_id)
    if not integration:
        return jsonify({'error': 'Integration not found'}), 404
    return jsonify({
        'id': int_id,
        'sent_count': integration.get('sent_count', 0),
        'error_count': integration.get('error_count', 0),
        'last_sent': integration.get('last_sent'),
        'last_error': integration.get('last_error'),
    })
