"""
Logs Blueprint
Handles log retrieval and clearing.
"""

import logging

from flask import Blueprint, request, jsonify

import extensions as ext

bp = Blueprint('logs', __name__, url_prefix='/api')
logger = logging.getLogger('packet_peeper')


@bp.route('/logs', methods=['GET'])
def get_logs():
    try:
        limit = request.args.get('limit', 100, type=int)
        with ext.logs_lock:
            return jsonify(ext.logs[-limit:] if ext.logs else [])
    except Exception as e:
        logger.error(f"Error retrieving logs: {str(e)}")
        return jsonify([]), 200


@bp.route('/logs/clear', methods=['POST'])
def api_clear_logs():
    try:
        with ext.logs_lock:
            ext.logs.clear()
        ext.add_log('info', 'System', 'Logs cleared via API')
        if ext.socketio:
            with ext.logs_lock:
                ext.socketio.emit('logs_list', list(ext.logs), namespace='/')
        return jsonify({'message': 'Logs cleared'})
    except Exception as e:
        logger.error(f"Error clearing logs: {str(e)}")
        return jsonify({'error': str(e)}), 500
