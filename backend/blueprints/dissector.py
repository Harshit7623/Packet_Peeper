"""
Protocol Dissection API
Endpoints for listing dissectors and running them against payloads.
"""

import logging

from flask import Blueprint, request, jsonify

import extensions as ext

dissector_bp = Blueprint('dissector', __name__, url_prefix='/api/dissectors')

logger = logging.getLogger('packet_peeper')


def _get_registry():
    from services.dissector_service import dissector_registry
    return dissector_registry


@dissector_bp.route('', methods=['GET'])
def list_dissectors():
    registry = _get_registry()
    return jsonify({'dissectors': registry.list_dissectors()})


@dissector_bp.route('/run', methods=['POST'])
def run_dissectors():
    data = request.get_json(silent=True) or {}
    packet_index = data.get('packet_index')
    payload_hex = data.get('payload_hex')
    context = data.get('context', {})

    registry = _get_registry()

    raw_bytes = None
    if payload_hex:
        try:
            raw_bytes = bytes.fromhex(payload_hex)
        except ValueError:
            return jsonify({'error': 'Invalid hex string'}), 400
    elif packet_index is not None and ext.sniffer:
        raw_packets = getattr(ext.sniffer, '_raw_packet_buffer', [])
        if packet_index < 0 or packet_index >= len(raw_packets):
            return jsonify({'error': 'Packet not found'}), 404
        try:
            raw_bytes = bytes(raw_packets[packet_index])
        except Exception:
            return jsonify({'error': 'Cannot read raw packet'}), 500
        captured = ext.sniffer.captured_packets
        if packet_index < len(captured):
            meta = captured[packet_index]
            context.setdefault('dst_port', meta.get('dst_port'))
            context.setdefault('src_port', meta.get('src_port'))
            context.setdefault('protocol', meta.get('protocol'))

    if raw_bytes is None:
        return jsonify({'error': 'Provide either packet_index or payload_hex'}), 400

    results = registry.dissect(raw_bytes, context)
    return jsonify({'results': results, 'count': len(results)})


@dissector_bp.route('/<name>/run', methods=['POST'])
def run_single_dissector(name):
    registry = _get_registry()
    dissector = registry.get(name)
    if not dissector:
        return jsonify({'error': f'Dissector {name} not found'}), 404

    data = request.get_json(silent=True) or {}
    payload_hex = data.get('payload_hex')
    context = data.get('context', {})

    if not payload_hex:
        return jsonify({'error': 'payload_hex required'}), 400

    try:
        raw_bytes = bytes.fromhex(payload_hex)
    except ValueError:
        return jsonify({'error': 'Invalid hex string'}), 400

    result = dissector.dissect(raw_bytes, context)
    return jsonify({'result': result, 'dissector': name})
