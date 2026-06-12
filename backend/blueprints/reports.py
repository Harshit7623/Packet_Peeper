"""
Reports Blueprint - Report history, download, parameterized generation, and scheduled reports.
"""

import os
import logging
import datetime

from flask import Blueprint, jsonify, request, g, send_file

import extensions as ext
from config.config import FEATURES, REPORTS_DIR
from services.report_generator import get_report_generator

bp = Blueprint('reports', __name__, url_prefix='/api/reports')
logger = logging.getLogger('packet_peeper')


@bp.route('/', methods=['GET'])
def list_reports():
    if not ext.db_service:
        return jsonify({'error': 'Database unavailable'}), 500
    try:
        limit = request.args.get('limit', 50, type=int)
        offset = request.args.get('offset', 0, type=int)
        org_id = g.get('org_id') if ext.auth_service else None
        reports, total = ext.db_service.get_reports(org_id=org_id, limit=limit, offset=offset)
        return jsonify({'reports': reports, 'total': total, 'limit': limit, 'offset': offset})
    except Exception as e:
        logger.error(f"Error listing reports: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/<int:report_id>', methods=['GET'])
def get_report(report_id):
    if not ext.db_service:
        return jsonify({'error': 'Database unavailable'}), 500
    try:
        org_id = g.get('org_id') if ext.auth_service else None
        report = ext.db_service.get_report(report_id, org_id=org_id)
        if not report:
            return jsonify({'error': 'Report not found'}), 404
        return jsonify({'report': report})
    except Exception as e:
        logger.error(f"Error getting report: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/<int:report_id>/download', methods=['GET'])
def download_report(report_id):
    if not ext.db_service:
        return jsonify({'error': 'Database unavailable'}), 500
    try:
        org_id = g.get('org_id') if ext.auth_service else None
        report = ext.db_service.get_report(report_id, org_id=org_id)
        if not report:
            return jsonify({'error': 'Report not found'}), 404
        file_path = report.get('file_path')
        if not file_path or not os.path.exists(file_path):
            return jsonify({'error': 'Report file not found on disk'}), 404
        report_type = report.get('report_type', 'json')
        mime_map = {'pdf': 'application/pdf', 'csv': 'text/csv', 'json': 'application/json'}
        mimetype = mime_map.get(report_type, 'application/octet-stream')
        filename = os.path.basename(file_path)
        return send_file(file_path, as_attachment=True, download_name=filename, mimetype=mimetype)
    except Exception as e:
        logger.error(f"Error downloading report: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/<int:report_id>', methods=['DELETE'])
def delete_report(report_id):
    if not ext.db_service:
        return jsonify({'error': 'Database unavailable'}), 500
    try:
        org_id = g.get('org_id') if ext.auth_service else None
        report = ext.db_service.get_report(report_id, org_id=org_id)
        if report:
            file_path = report.get('file_path')
            if file_path and os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except OSError:
                    pass
        success = ext.db_service.delete_report(report_id, org_id=org_id)
        if success:
            return jsonify({'message': 'Report deleted'})
        return jsonify({'error': 'Report not found'}), 404
    except Exception as e:
        logger.error(f"Error deleting report: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/generate', methods=['POST'])
def generate_report():
    try:
        data = request.get_json() or {}
        report_type = data.get('type', 'json')
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        packet_limit = data.get('packet_limit', 10000)
        alert_limit = data.get('alert_limit', 1000)
        severity = data.get('severity')

        if report_type not in ('pdf', 'csv', 'json'):
            return jsonify({'error': 'Invalid report type. Use pdf, csv, or json'}), 400

        packets = []
        alerts_list = []
        devices = []

        if ext.db_service and FEATURES['persistent_storage']:
            filters = {}
            if start_date:
                filters['start_date'] = start_date
            if end_date:
                filters['end_date'] = end_date
            packets, _ = ext.db_service.get_packets(limit=packet_limit, **filters)
            alerts_list, _ = ext.db_service.get_alerts(limit=alert_limit, **filters)
            devices, _ = ext.db_service.get_devices()
        elif ext.sniffer:
            packets = list(ext.sniffer.captured_packets[-packet_limit:]) if ext.sniffer.captured_packets else []
            with ext.alerts_lock:
                alerts_list = [ext._normalize_alert(a) for a in ext.alerts]
            devices = ext._collect_device_snapshot()

        if severity and severity != 'all':
            alerts_list = [a for a in alerts_list if a.get('severity') == severity]

        generator = get_report_generator()
        filepath = None

        if report_type == 'pdf':
            filepath = generator.generate_pdf_report(packets, alerts_list)
        elif report_type == 'csv':
            filepath = generator.generate_csv_report(packets, alerts_list)
        elif report_type == 'json':
            filepath = generator.generate_json_report(packets, alerts_list, devices)

        if not filepath:
            return jsonify({'error': 'Report generation failed'}), 500

        file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0

        # Save report metadata to DB
        if ext.db_service:
            org_id = g.get('org_id') if ext.auth_service else None
            ext.db_service.save_report({
                'type': report_type,
                'start_date': start_date or datetime.datetime.min.isoformat(),
                'end_date': end_date or datetime.datetime.now().isoformat(),
                'file_path': str(filepath),
                'total_packets': len(packets),
                'total_alerts': len(alerts_list),
                'file_size': file_size,
                'org_id': org_id,
            })

        return jsonify({
            'message': 'Report generated',
            'file_path': str(filepath),
            'report_type': report_type,
            'total_packets': len(packets),
            'total_alerts': len(alerts_list),
            'file_size': file_size,
        })
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return jsonify({'error': str(e)}), 500


# ==================== Scheduled Reports ====================

@bp.route('/schedules', methods=['GET'])
def list_scheduled_reports():
    if not ext.db_service:
        return jsonify({'error': 'Database unavailable'}), 500
    try:
        org_id = g.get('org_id') if ext.auth_service else None
        active_only = request.args.get('active_only', 'false').lower() == 'true'
        schedules = ext.db_service.get_scheduled_reports(org_id=org_id, active_only=active_only)
        return jsonify({'schedules': schedules, 'total': len(schedules)})
    except Exception as e:
        logger.error(f"Error listing scheduled reports: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/schedules', methods=['POST'])
def create_scheduled_report():
    if not ext.db_service:
        return jsonify({'error': 'Database unavailable'}), 500
    try:
        data = request.get_json() or {}
        name = data.get('name', 'Scheduled Report')
        report_type = data.get('report_type', 'json')
        frequency = data.get('frequency', 'daily')

        if report_type not in ('pdf', 'csv', 'json'):
            return jsonify({'error': 'Invalid report type'}), 400
        if frequency not in ('daily', 'weekly', 'monthly'):
            return jsonify({'error': 'Invalid frequency. Use daily, weekly, or monthly'}), 400

        org_id = g.get('org_id') if ext.auth_service else None
        schedule_id = ext.db_service.create_scheduled_report({
            'name': name,
            'report_type': report_type,
            'frequency': frequency,
            'start_date_offset_days': data.get('start_date_offset_days', 1),
            'end_date_offset_days': data.get('end_date_offset_days', 0),
            'severity': data.get('severity'),
            'is_active': data.get('is_active', True),
            'org_id': org_id,
        })
        if schedule_id:
            return jsonify({'message': 'Scheduled report created', 'id': schedule_id}), 201
        return jsonify({'error': 'Failed to create scheduled report'}), 500
    except Exception as e:
        logger.error(f"Error creating scheduled report: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/schedules/<int:schedule_id>', methods=['PUT'])
def update_scheduled_report(schedule_id):
    if not ext.db_service:
        return jsonify({'error': 'Database unavailable'}), 500
    try:
        data = request.get_json() or {}
        org_id = g.get('org_id') if ext.auth_service else None
        success = ext.db_service.update_scheduled_report(schedule_id, data, org_id=org_id)
        if success:
            return jsonify({'message': 'Scheduled report updated'})
        return jsonify({'error': 'Scheduled report not found'}), 404
    except Exception as e:
        logger.error(f"Error updating scheduled report: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/schedules/<int:schedule_id>', methods=['DELETE'])
def delete_scheduled_report(schedule_id):
    if not ext.db_service:
        return jsonify({'error': 'Database unavailable'}), 500
    try:
        org_id = g.get('org_id') if ext.auth_service else None
        success = ext.db_service.delete_scheduled_report(schedule_id, org_id=org_id)
        if success:
            return jsonify({'message': 'Scheduled report deleted'})
        return jsonify({'error': 'Scheduled report not found'}), 404
    except Exception as e:
        logger.error(f"Error deleting scheduled report: {str(e)}")
        return jsonify({'error': str(e)}), 500
