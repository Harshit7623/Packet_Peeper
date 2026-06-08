"""
Alerts Blueprint
Handles alert retrieval, security alerts, dismissal, and clearing.
"""

import logging

from flask import Blueprint, request, jsonify

from config.config import FEATURES

import extensions as ext

bp = Blueprint('alerts', __name__, url_prefix='/api')
logger = logging.getLogger('packet_peeper')


@bp.route('/alerts', methods=['GET'])
def get_alerts():
    try:
        if ext.db_service and FEATURES['persistent_storage']:
            limit = request.args.get('limit', 100, type=int)
            offset = request.args.get('offset', 0, type=int)
            start_time = ext._parse_iso_datetime(request.args.get('start'))
            end_time = ext._parse_iso_datetime(request.args.get('end'))
            severity = request.args.get('severity')
            alert_type = request.args.get('alert_type')
            source_ip = request.args.get('source_ip')
            destination_ip = request.args.get('destination_ip')
            title = request.args.get('title')
            resolved = request.args.get('resolved', type=lambda v: v.lower() == 'true' if v else None)
            search = request.args.get('search')
            alerts, total = ext.db_service.get_alerts(
                start_time=start_time,
                end_time=end_time,
                severity=severity,
                alert_type=alert_type,
                source_ip=source_ip,
                destination_ip=destination_ip,
                title=title,
                resolved=resolved,
                search=search,
                limit=limit,
                offset=offset,
            )
            return jsonify({'data': alerts, 'total': total, 'limit': limit, 'offset': offset})
        else:
            with ext.alerts_lock:
                return jsonify({'data': list(ext.alerts), 'total': len(ext.alerts), 'limit': 100, 'offset': 0})
    except Exception as e:
        logger.error(f"Error retrieving alerts: {str(e)}")
        return jsonify({'data': [], 'total': 0, 'limit': 100, 'offset': 0}), 200


@bp.route('/security_alerts', methods=['GET'])
def get_security_alerts():
    try:
        security_alert_types = ['port_scan', 'ddos', 'brute_force', 'dns_tunneling']
        if ext.db_service and FEATURES['persistent_storage']:
            limit = request.args.get('limit', 100, type=int)
            all_alerts, _ = ext.db_service.get_alerts(limit=limit)
            security_alerts = [
                a for a in all_alerts
                if (a.get('type') or a.get('alert_type')) in security_alert_types
            ]
            return jsonify({'data': security_alerts, 'total': len(security_alerts)})
        else:
            with ext.alerts_lock:
                security_alerts = [
                    a for a in ext.alerts
                    if (a.get('type') or a.get('alert_type')) in security_alert_types
                ]
                return jsonify({'data': security_alerts, 'total': len(security_alerts)})
    except Exception as e:
        logger.error(f"Error retrieving security alerts: {str(e)}")
        return jsonify({'data': [], 'total': 0}), 200


@bp.route('/alerts/<int:alert_id>/dismiss', methods=['POST'])
def api_dismiss_alert(alert_id):
    try:
        with ext.alerts_lock:
            ext.alerts = [a for a in ext.alerts if a.get('id') != alert_id]
            if ext.db_service:
                ext.db_service.dismiss_alert(alert_id)
        return jsonify({'message': f'Alert {alert_id} dismissed'})
    except Exception as e:
        logger.error(f"Error dismissing alert: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/alerts/clear', methods=['POST'])
def api_clear_alerts():
    try:
        with ext.alerts_lock:
            ext.alerts.clear()
            if ext.db_service and FEATURES['persistent_storage']:
                ext.db_service.clear_alerts()
            if ext.sniffer and hasattr(ext.sniffer, 'security_monitor') and ext.sniffer.security_monitor:
                ext.sniffer.security_monitor.reset_counters()
            ext.add_log('info', 'API', 'All alerts cleared and security counters reset')
            if ext.socketio:
                ext.socketio.emit('alerts_sync', [], namespace='/')
        return jsonify({'message': 'All alerts cleared'})
    except Exception as e:
        logger.error(f"Error clearing alerts: {str(e)}")
        return jsonify({'error': str(e)}), 500
