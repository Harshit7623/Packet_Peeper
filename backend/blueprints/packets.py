"""
Packets Blueprint
Handles packet retrieval with advanced filtering and pagination.
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
            offset = request.args.get('offset', 0, type=int)
            start_time = ext._parse_iso_datetime(request.args.get('start'))
            end_time = ext._parse_iso_datetime(request.args.get('end'))
            protocol = request.args.get('protocol')
            src_ip = request.args.get('src_ip')
            dst_ip = request.args.get('dst_ip')
            src_port = request.args.get('src_port', type=int)
            dst_port = request.args.get('dst_port', type=int)
            service = request.args.get('service')
            tcp_flags = request.args.get('tcp_flags', type=int)
            min_length = request.args.get('min_length', type=int)
            max_length = request.args.get('max_length', type=int)
            search = request.args.get('search')
            packets, total = ext.db_service.get_packets(
                start_time=start_time,
                end_time=end_time,
                protocol=protocol,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                service=service,
                tcp_flags=tcp_flags,
                min_length=min_length,
                max_length=max_length,
                search=search,
                limit=limit,
                offset=offset,
            )
            return jsonify({'data': packets, 'total': total, 'limit': limit, 'offset': offset})
        else:
            limit = request.args.get('limit', 1000, type=int)
            packets = ext.sniffer.captured_packets[-limit:] if ext.sniffer else []
            return jsonify({'data': packets, 'total': len(packets), 'limit': limit, 'offset': 0})
    except Exception as e:
        logger.error(f"Error retrieving packets: {str(e)}")
        return jsonify({'data': [], 'total': 0, 'limit': 1000, 'offset': 0}), 200
