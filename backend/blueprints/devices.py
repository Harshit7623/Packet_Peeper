"""
Devices Blueprint
Handles device listing and network scanning.
"""

import logging

from flask import Blueprint, request, jsonify

from config.config import FEATURES

import extensions as ext

bp = Blueprint('devices', __name__, url_prefix='/api')
logger = logging.getLogger('packet_peeper')


@bp.route('/devices', methods=['GET'])
def get_devices():
    try:
        if ext.sniffer:
            devices = ext._collect_device_snapshot()
            if ext.db_service and FEATURES['persistent_storage']:
                for device in devices:
                    try:
                        ext.db_service.update_device(device)
                    except Exception as e:
                        logger.debug(f"DB update failed for device {device.get('ip_address')}: {e}")
            return jsonify(devices)
        return jsonify([])
    except Exception as e:
        logger.error(f"Error retrieving devices: {str(e)}")
        return jsonify([]), 200


@bp.route('/network/scan', methods=['POST'])
def api_scan_network():
    try:
        if ext.sniffer:
            devices = ext.sniffer.get_devices()
            if ext.socketio:
                ext.socketio.emit('devices_update', {'devices': devices}, namespace='/')
            ext.add_log('info', 'API', 'Network scan initiated')
            return jsonify({'message': 'Network scan initiated', 'devices_found': len(devices)})
        return jsonify({'message': 'Sniffer not running'}), 400
    except Exception as e:
        logger.error(f"Error scanning network: {str(e)}")
        return jsonify({'error': str(e)}), 500
