"""
Search Blueprint
Unified search across packets, alerts, and devices.
"""

import logging

from flask import Blueprint, request, jsonify

from config.config import FEATURES

import extensions as ext

bp = Blueprint('search', __name__, url_prefix='/api')
logger = logging.getLogger('packet_peeper')


@bp.route('/search', methods=['GET'])
def unified_search():
    """Search across packets, alerts, and devices simultaneously."""
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify({'packets': [], 'alerts': [], 'devices': [], 'total': 0})

    limit = request.args.get('limit', 20, type=int)
    results = {'packets': [], 'alerts': [], 'devices': [], 'total': 0}

    try:
        if ext.db_service and FEATURES['persistent_storage']:
            packets, p_count = ext.db_service.get_packets(search=query, limit=limit)
            alerts, a_count = ext.db_service.get_alerts(search=query, limit=limit)
            devices, d_count = ext.db_service.get_devices(search=query, limit=limit)
            results['packets'] = packets
            results['alerts'] = alerts
            results['devices'] = devices
            results['total'] = p_count + a_count + d_count
        else:
            if ext.sniffer:
                q_lower = query.lower()
                filtered_packets = [
                    p for p in list(ext.sniffer.captured_packets[-5000:])
                    if q_lower in (p.get('src_ip', '') or '').lower()
                    or q_lower in (p.get('dst_ip', '') or '').lower()
                    or q_lower in (p.get('protocol', '') or '').lower()
                    or q_lower in (p.get('service', '') or '').lower()
                ]
                results['packets'] = filtered_packets[:limit]
                results['total'] += len(filtered_packets[:limit])

            with ext.alerts_lock:
                filtered_alerts = [
                    a for a in ext.alerts
                    if q_lower in (a.get('title', '') or '').lower()
                    or q_lower in (a.get('description', '') or '').lower()
                    or q_lower in (a.get('source_ip', '') or '').lower()
                    or q_lower in (a.get('alert_type', '') or '').lower()
                ]
                results['alerts'] = filtered_alerts[:limit]
                results['total'] += len(filtered_alerts[:limit])

        return jsonify(results)
    except Exception as e:
        logger.error(f"Error in unified search: {str(e)}")
        return jsonify({'packets': [], 'alerts': [], 'devices': [], 'total': 0}), 200
