"""
Analytics Blueprint
Handles analytics endpoints: protocol distribution, top talkers, bandwidth.
"""

import logging
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify

from config.config import FEATURES

import extensions as ext

bp = Blueprint('analytics', __name__, url_prefix='/api')
logger = logging.getLogger('packet_peeper')

@bp.route('/analytics', methods=['GET'])
def api_analytics():
    try:
        time_range = request.args.get('range', '24h')
        hours = 24
        if time_range == '7d':
            hours = 168
        elif time_range == '30d':
            hours = 720
        elif time_range == '1h':
            hours = 1

        stats = ext._collect_traffic_snapshot()
        flow_data = []
        if ext.db_service and FEATURES['persistent_storage']:
            flow_data = ext.db_service.get_bandwidth_history(hours=hours)
        elif hasattr(ext, 'bandwidth_history') and ext.bandwidth_history:
            flow_data = list(ext.bandwidth_history)

        return jsonify({
            'timeRange': time_range,
            'totalPackets': stats.get('totalPackets', 0),
            'totalBytes': stats.get('totalBytes', 0),
            'currentBandwidth': stats.get('currentBandwidth', 0),
            'peakBandwidth': stats.get('peakBandwidth', 0),
            'averageBandwidth': stats.get('averageBandwidth', 0),
            'protocols': stats.get('protocols', {}),
            'flow': flow_data[-120:] if flow_data else [],
        })
    except Exception as e:
        logger.error(f"Error getting analytics: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/analytics/protocols', methods=['GET'])
def api_analytics_protocols():
    try:
        if ext.sniffer:
            stats = ext.sniffer.get_statistics()
            return jsonify({
                'TCP': stats.get('tcpPackets', 0),
                'UDP': stats.get('udpPackets', 0),
                'ICMP': stats.get('icmpPackets', 0),
            })
        return jsonify({'TCP': 0, 'UDP': 0, 'ICMP': 0})
    except Exception as e:
        logger.error(f"Error getting protocol distribution: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/analytics/top-talkers', methods=['GET'])
def api_analytics_top_talkers():
    try:
        limit = request.args.get('limit', 10, type=int)
        devices = []
        if ext.db_service and FEATURES['persistent_storage']:
            devices = ext.db_service.get_devices(limit=1000)
        elif ext.sniffer:
            devices = ext._collect_device_snapshot()

        if devices:
            def _packets_total(device):
                return (
                    (device.get('packets_in') or device.get('packetsIn') or 0)
                    + (device.get('packets_out') or device.get('packetsOut') or 0)
                    + (device.get('packetsCaptured') or 0)
                )
            sorted_devices = sorted(devices, key=_packets_total, reverse=True)
            return jsonify(sorted_devices[:limit])
        return jsonify([])
    except Exception as e:
        logger.error(f"Error getting top talkers: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/analytics/bandwidth', methods=['GET'])
def api_analytics_bandwidth():
    try:
        hours = request.args.get('hours', 24, type=int)
        if ext.db_service and FEATURES['persistent_storage']:
            data = ext.db_service.get_bandwidth_history(hours=hours,
                                                        limit=max(10, hours * 6))
            return jsonify(data)
        elif hasattr(ext, 'bandwidth_history') and ext.bandwidth_history:
            return jsonify(list(ext.bandwidth_history)[-hours * 12:])
        return jsonify([])
    except Exception as e:
        logger.error(f"Error getting bandwidth history: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/traffic/flow', methods=['GET'])
def api_traffic_flow():
    """Traffic flow data for real-time protocol charts."""
    try:
        minutes = request.args.get('minutes', 30, type=int)
        buckets = request.args.get('buckets', 30, type=int)

        flow_data = []
        if ext.db_service and FEATURES['persistent_storage']:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(minutes=minutes)
            raw = ext.db_service.get_traffic_features(start_time=start_time,
                                                       end_time=end_time,
                                                       limit=buckets)
            for r in raw:
                flow_data.append({
                    'timestamp': r.get('window_start', ''),
                    'time_label': (r.get('window_start', '')[-8:-3]
                                   if r.get('window_start') else ''),
                    'tcp': r.get('tcp_packets', 0),
                    'udp': r.get('udp_packets', 0),
                    'icmp': r.get('icmp_packets', 0),
                    'other': r.get('other_packets', 0),
                    'total': r.get('total_packets', 0),
                    'bytes': r.get('total_bytes', 0),
                })
        elif hasattr(ext, 'traffic_history') and ext.traffic_history:
            history = list(ext.traffic_history)
            step = max(1, len(history) // buckets)
            for h in history[::step][-buckets:]:
                flow_data.append({
                    'timestamp': h.get('timestamp', ''),
                    'time_label': '',
                    'tcp': h.get('tcp', 0),
                    'udp': h.get('udp', 0),
                    'icmp': h.get('icmp', 0),
                    'other': h.get('other', 0),
                    'total': h.get('total', 0),
                    'bytes': h.get('bytes', h.get('total_bytes', 0)),
                })

        return jsonify({
            'flow': flow_data,
            'minutes': minutes,
            'bucket_count': buckets,
        })
    except Exception as e:
        logger.error(f"Error getting traffic flow: {str(e)}")
        return jsonify({'flow': [], 'minutes': minutes, 'bucket_count': buckets})


@bp.route('/traffic/stats', methods=['GET'])
def api_traffic_stats():
    try:
        stats = ext._collect_traffic_snapshot()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting traffic stats: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/traffic/top-talkers', methods=['GET'])
def api_traffic_top_talkers():
    try:
        limit = request.args.get('limit', 10, type=int)
        devices = []
        if ext.db_service and FEATURES['persistent_storage']:
            devices = ext.db_service.get_devices(limit=1000)
        elif ext.sniffer:
            devices = ext._collect_device_snapshot()

        if devices:
            def _packets_total(device):
                return (
                    (device.get('packets_in') or device.get('packetsIn') or 0)
                    + (device.get('packets_out') or device.get('packetsOut') or 0)
                    + (device.get('packetsCaptured') or 0)
                )
            sorted_devices = sorted(devices, key=_packets_total, reverse=True)
            return jsonify(sorted_devices[:limit])
        return jsonify([])
    except Exception as e:
        logger.error(f"Error getting top talkers: {str(e)}")
        return jsonify({'error': str(e)}), 500
