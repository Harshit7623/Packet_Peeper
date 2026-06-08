"""
Analytics Blueprint
Handles analytics, protocol distribution, top talkers, bandwidth, and traffic endpoints.
"""

import datetime
import time
import logging

from flask import Blueprint, request, jsonify

from config.config import FEATURES

import extensions as ext

bp = Blueprint('analytics', __name__, url_prefix='/api')
logger = logging.getLogger('packet_peeper')


@bp.route('/analytics', methods=['GET'])
def api_analytics():
    try:
        time_range = request.args.get('range', '24h')
        if ext.sniffer:
            stats = ext.sniffer.get_statistics()
            return jsonify({
                'total_packets': stats.get('totalPackets', 0),
                'protocols': {
                    'TCP': stats.get('tcpPackets', 0),
                    'UDP': stats.get('udpPackets', 0),
                    'ICMP': stats.get('icmpPackets', 0),
                    'Other': stats.get('otherPackets', 0),
                },
                'bandwidth': {
                    'current': stats.get('currentBandwidth', 0),
                    'peak': stats.get('peakBandwidth', 0),
                    'average': stats.get('averageBandwidth', 0),
                },
                'time_range': time_range,
            })
        if ext.db_service and FEATURES['persistent_storage']:
            latest = ext.db_service.get_traffic_stats(limit=1)
            if latest:
                row = latest[0]
                return jsonify({
                    'total_packets': row.get('total_packets', 0),
                    'protocols': {
                        'TCP': row.get('tcp_packets', 0),
                        'UDP': row.get('udp_packets', 0),
                        'ICMP': row.get('icmp_packets', 0),
                        'Other': 0,
                    },
                    'bandwidth': {
                        'current': row.get('current_bandwidth', 0),
                        'peak': row.get('peak_bandwidth', 0),
                        'average': row.get('average_bandwidth', 0),
                    },
                    'time_range': time_range,
                })
        return jsonify({})
    except Exception as e:
        logger.error(f"Error getting analytics: {str(e)}")
        return jsonify({}), 200


@bp.route('/analytics/protocols', methods=['GET'])
def api_protocol_distribution():
    try:
        if ext.sniffer:
            stats = ext.sniffer.get_statistics()
            total = stats.get('totalPackets', 1) or 1
            return jsonify({
                'distribution': [
                    {'name': 'TCP', 'value': stats.get('tcpPackets', 0), 'percentage': round(stats.get('tcpPackets', 0) / total * 100, 2)},
                    {'name': 'UDP', 'value': stats.get('udpPackets', 0), 'percentage': round(stats.get('udpPackets', 0) / total * 100, 2)},
                    {'name': 'ICMP', 'value': stats.get('icmpPackets', 0), 'percentage': round(stats.get('icmpPackets', 0) / total * 100, 2)},
                    {'name': 'Other', 'value': stats.get('otherPackets', 0), 'percentage': round(stats.get('otherPackets', 0) / total * 100, 2)},
                ],
            })
        if ext.db_service and FEATURES['persistent_storage']:
            latest = ext.db_service.get_traffic_stats(limit=1)
            if latest:
                row = latest[0]
                total = row.get('total_packets', 1) or 1
                return jsonify({
                    'distribution': [
                        {'name': 'TCP', 'value': row.get('tcp_packets', 0), 'percentage': round(row.get('tcp_packets', 0) / total * 100, 2)},
                        {'name': 'UDP', 'value': row.get('udp_packets', 0), 'percentage': round(row.get('udp_packets', 0) / total * 100, 2)},
                        {'name': 'ICMP', 'value': row.get('icmp_packets', 0), 'percentage': round(row.get('icmp_packets', 0) / total * 100, 2)},
                        {'name': 'Other', 'value': 0, 'percentage': 0},
                    ],
                })
        return jsonify({'distribution': []})
    except Exception as e:
        logger.error(f"Error getting protocol distribution: {str(e)}")
        return jsonify({'distribution': []}), 200


@bp.route('/analytics/top-talkers', methods=['GET'])
def api_analytics_top_talkers():
    try:
        limit = request.args.get('limit', 10, type=int)
        devices = []
        if ext.db_service and FEATURES['persistent_storage']:
            devices, _ = ext.db_service.get_devices(limit=1000)
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
        return jsonify([]), 200


@bp.route('/analytics/bandwidth', methods=['GET'])
def api_bandwidth_history():
    try:
        hours = request.args.get('hours', 24, type=int)
        if ext.db_service and FEATURES['persistent_storage']:
            return jsonify(ext.db_service.get_bandwidth_history(hours=hours))
        if ext.sniffer:
            stats = ext.sniffer.get_statistics()
            return jsonify([{
                'timestamp': datetime.datetime.now().isoformat(),
                'bandwidth': stats.get('currentBandwidth', 0),
            }])
        return jsonify([])
    except Exception as e:
        logger.error(f"Error getting bandwidth history: {str(e)}")
        return jsonify([]), 200


@bp.route('/traffic/stats', methods=['GET'])
def api_traffic_stats():
    try:
        if ext.sniffer:
            stats = ext.sniffer.get_statistics()
            return jsonify({
                'total_packets': stats.get('totalPackets', 0),
                'tcp_packets': stats.get('tcpPackets', 0),
                'udp_packets': stats.get('udpPackets', 0),
                'icmp_packets': stats.get('icmpPackets', 0),
                'current_bandwidth': stats.get('currentBandwidth', 0),
                'peak_bandwidth': stats.get('peakBandwidth', 0),
                'average_bandwidth': stats.get('averageBandwidth', 0),
            })
        if ext.db_service and FEATURES['persistent_storage']:
            latest = ext.db_service.get_traffic_stats(limit=1)
            if latest:
                return jsonify(latest[0])
        return jsonify({})
    except Exception as e:
        logger.error(f"Error getting traffic stats: {str(e)}")
        return jsonify({}), 200


@bp.route('/traffic/flow', methods=['GET'])
def api_traffic_flow():
    try:
        minutes = request.args.get('minutes', 30, type=int)
        bucket_count = request.args.get('buckets', 30, type=int)

        now = time.time()
        window = minutes * 60
        bucket_size = window / bucket_count

        buckets = []
        for i in range(bucket_count):
            bucket_start = now - window + (i * bucket_size)
            buckets.append({
                'timestamp': datetime.datetime.fromtimestamp(bucket_start).isoformat(),
                'time_label': datetime.datetime.fromtimestamp(bucket_start).strftime('%H:%M'),
                'tcp': 0, 'udp': 0, 'icmp': 0, 'other': 0, 'total': 0, 'bytes': 0,
            })

        if ext.sniffer and ext.sniffer.captured_packets:
            for pkt in ext.sniffer.captured_packets:
                try:
                    ts_str = pkt.get('timestamp', '')
                    if '.' in ts_str:
                        pkt_time = datetime.datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S.%f')
                    else:
                        pkt_time = datetime.datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
                    pkt_ts = pkt_time.timestamp()
                except Exception:
                    continue
                if pkt_ts < (now - window) or pkt_ts > now:
                    continue
                bucket_idx = min(bucket_count - 1, max(0, int((pkt_ts - (now - window)) / bucket_size)))
                proto = (pkt.get('protocol') or '').upper()
                if proto == 'TCP':
                    buckets[bucket_idx]['tcp'] += 1
                elif proto == 'UDP':
                    buckets[bucket_idx]['udp'] += 1
                elif proto == 'ICMP':
                    buckets[bucket_idx]['icmp'] += 1
                else:
                    buckets[bucket_idx]['other'] += 1
                buckets[bucket_idx]['total'] += 1
                buckets[bucket_idx]['bytes'] += pkt.get('length', 0)

        return jsonify({'data': buckets})
    except Exception as e:
        logger.error(f"Error fetching traffic flow: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/traffic/top-talkers', methods=['GET'])
def api_traffic_top_talkers():
    try:
        limit = request.args.get('limit', 10, type=int)
        talkers = []
        if ext.sniffer:
            sorted_devices = sorted(
                ext.sniffer.devices.items(),
                key=lambda x: x[1].get('bytes_transferred', 0),
                reverse=True,
            )[:limit]
            for ip, info in sorted_devices:
                talkers.append({
                    'ip': ip,
                    'packets': info.get('packet_count', 0),
                    'bytes': info.get('bytes_transferred', 0),
                    'mac': info.get('mac', 'Unknown'),
                    'vendor': info.get('vendor', 'Unknown'),
                })
        return jsonify(talkers)
    except Exception as e:
        logger.error(f"Error fetching top talkers: {str(e)}")
        return jsonify({'error': str(e)}), 500
