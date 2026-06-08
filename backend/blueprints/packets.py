"""
Packets Blueprint
Handles packet retrieval with optional filtering.
"""

import logging

from flask import Blueprint, request, jsonify

from config.config import FEATURES

import extensions as ext

bp = Blueprint('packets', __name__, url_prefix='/api')
logger = logging.getLogger('packet_peeper')


@bp.route('/packets', methods=['GET'])
def get_packets():
    try:
        if ext.db_service and FEATURES['persistent_storage']:
            limit = request.args.get('limit', 1000, type=int)
            start_time = ext._parse_iso_datetime(request.args.get('start'))
            end_time = ext._parse_iso_datetime(request.args.get('end'))
            protocol = request.args.get('protocol')
            src_ip = request.args.get('src_ip')
            dst_ip = request.args.get('dst_ip')
            db_packets = ext.db_service.get_packets(
                start_time=start_time,
                end_time=end_time,
                protocol=protocol,
                src_ip=src_ip,
                dst_ip=dst_ip,
                limit=limit,
            )
            return jsonify(db_packets)
        else:
            limit = request.args.get('limit', 1000, type=int)
            return jsonify(ext.sniffer.captured_packets[-limit:] if ext.sniffer else [])
    except Exception as e:
        logger.error(f"Error retrieving packets: {str(e)}")
        return jsonify([]), 200
