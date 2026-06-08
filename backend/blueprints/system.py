"""
System Blueprint
Handles system info, health checks, settings, AI assistant, reports, clear_all, test-mode, and debug endpoints.
"""

import os
import time
import logging
import datetime

from flask import Blueprint, request, jsonify, send_file, g

from config.config import ENABLE_AUTH, FEATURES, FLASK_ENV
from services.report_generator import get_report_generator
from services.ai_assistant import get_ai_assistant
from services.packet_processor import get_packet_processor
from services.database_services import AlertRecord, DeviceRecord, PacketRecord, UserSessionRecord

import extensions as ext

bp = Blueprint('system', __name__, url_prefix='/api')
logger = logging.getLogger('packet_peeper')


@bp.route('/system/info', methods=['GET'])
def api_system_info():
    try:
        import psutil
        import platform
        return jsonify({
            'platform': platform.system(),
            'platform_version': platform.version(),
            'python_version': platform.python_version(),
            'cpu_percent': psutil.cpu_percent(),
            'memory': {
                'total': psutil.virtual_memory().total,
                'available': psutil.virtual_memory().available,
                'percent': psutil.virtual_memory().percent,
            },
            'disk': {
                'total': psutil.disk_usage('/').total,
                'used': psutil.disk_usage('/').used,
                'percent': psutil.disk_usage('/').percent,
            },
        })
    except Exception as e:
        logger.error(f"Error getting system info: {str(e)}")
        return jsonify({}), 200


@bp.route('/health', methods=['GET'])
def api_health():
    db_status = None
    if ext.db_service:
        try:
            db_status = ext.db_service.get_status()
        except Exception:
            db_status = {'ready': False}

    return jsonify({
        'status': 'healthy',
        'uptime': time.time() - ext.start_time if ext.start_time else 0,
        'version': '2.0.0',
        'sniffing': ext.sniffing_state['is_running'],
        'database': db_status or {'ready': False},
        'auth_enabled': ENABLE_AUTH,
    })


@bp.route('/system/health', methods=['GET'])
def api_system_health():
    try:
        import psutil
        import platform

        cpu_percent = psutil.cpu_percent(interval=0.5)
        cpu_per_core = psutil.cpu_percent(interval=0, percpu=True)
        cpu_freq = psutil.cpu_freq()
        load_avg = os.getloadavg() if hasattr(os, 'getloadavg') else [0, 0, 0]

        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        disk = psutil.disk_usage('/')
        net_io = psutil.net_io_counters()
        process = psutil.Process()
        proc_mem = process.memory_info()
        uptime_seconds = time.time() - ext.start_time

        processor_queue = 0
        try:
            processor = get_packet_processor()
            stats = processor.get_stats()
            processor_queue = stats.get('queue_size', 0)
        except Exception:
            pass

        return jsonify({
            'cpu': {
                'percent': cpu_percent,
                'per_core': cpu_per_core,
                'cores': psutil.cpu_count(logical=True),
                'physical_cores': psutil.cpu_count(logical=False),
                'frequency': {
                    'current': cpu_freq.current if cpu_freq else 0,
                    'min': cpu_freq.min if cpu_freq else 0,
                    'max': cpu_freq.max if cpu_freq else 0,
                },
                'load_average': list(load_avg),
            },
            'memory': {
                'total': mem.total,
                'available': mem.available,
                'used': mem.used,
                'percent': mem.percent,
                'swap_total': swap.total,
                'swap_used': swap.used,
                'swap_percent': swap.percent,
            },
            'disk': {
                'total': disk.total,
                'used': disk.used,
                'free': disk.free,
                'percent': disk.percent,
            },
            'network': {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv,
                'errin': net_io.errin,
                'errout': net_io.errout,
                'dropin': net_io.dropin,
                'dropout': net_io.dropout,
            },
            'process': {
                'memory_rss': proc_mem.rss,
                'memory_vms': proc_mem.vms,
                'cpu_percent': process.cpu_percent(interval=0),
                'threads': process.num_threads(),
            },
            'processing': {
                'queue_size': processor_queue,
                'packets_captured': len(ext.sniffer.captured_packets) if ext.sniffer else 0,
                'alerts_count': len(ext.alerts),
                'devices_count': len(ext.sniffer.active_devices) if ext.sniffer else 0,
            },
            'uptime': uptime_seconds,
            'platform': platform.system(),
            'platform_version': platform.version(),
        })
    except Exception as e:
        logger.error(f"Error getting system health: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/settings', methods=['GET'])
def api_get_settings():
    return jsonify(ext.app_settings)


@bp.route('/settings', methods=['PUT'])
def api_update_settings():
    try:
        data = request.get_json()
        for key, value in data.items():
            if key in ext.app_settings:
                ext.app_settings[key] = value
        ext.add_log('info', 'API', 'Settings updated')
        return jsonify({'message': 'Settings updated', 'settings': ext.app_settings})
    except Exception as e:
        logger.error(f"Error updating settings: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/ai/remediate', methods=['POST'])
def api_ai_remediate():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No alert data provided'}), 400
        ai_assistant = get_ai_assistant()
        response = ai_assistant.get_remediation(data)
        ext.add_log('info', 'AI', f"Generated remediation for: {data.get('type', 'unknown')}")
        return jsonify(response.to_dict())
    except Exception as e:
        logger.error(f"Error getting AI remediation: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'explanation': 'Unable to generate AI response. Please try again.',
            'steps': ['Review the alert details manually.'],
            'severity_assessment': 'Unknown',
            'estimated_risk': 'Unable to assess',
        }), 500


@bp.route('/ai/explain', methods=['POST'])
def api_ai_explain():
    try:
        data = request.get_json()
        term = data.get('term', '')
        if not term:
            return jsonify({'error': 'No term provided'}), 400
        ai_assistant = get_ai_assistant()
        explanation = ai_assistant.explain_term(term)
        return jsonify(explanation)
    except Exception as e:
        logger.error(f"Error explaining term: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/ai/health-summary', methods=['GET'])
def api_ai_health_summary():
    try:
        critical_count = sum(1 for a in ext.alerts if a.get('severity') == 'critical')
        high_count = sum(1 for a in ext.alerts if a.get('severity') == 'high')
        medium_count = sum(1 for a in ext.alerts if a.get('severity') == 'medium')
        stats = {
            'total_alerts': len(ext.alerts),
            'critical_alerts': critical_count,
            'high_alerts': high_count,
            'medium_alerts': medium_count,
        }
        ai_assistant = get_ai_assistant()
        summary = ai_assistant.get_network_health_summary(stats)
        return jsonify(summary)
    except Exception as e:
        logger.error(f"Error getting health summary: {str(e)}")
        return jsonify({
            'status': '[Unknown]',
            'message': 'Unable to determine network health status.',
            'action': 'Check your alerts manually.',
        }), 500


@bp.route('/ai/status', methods=['GET'])
def api_ai_status():
    try:
        ai_assistant = get_ai_assistant()
        has_openai = bool(os.getenv("OPENAI_API_KEY"))
        has_anthropic = bool(os.getenv("ANTHROPIC_API_KEY"))
        has_ollama = False
        try:
            import requests
            resp = requests.get(f"{os.getenv('OLLAMA_URL', 'http://localhost:11434')}/api/tags", timeout=2)
            has_ollama = resp.status_code == 200
        except Exception:
            pass

        providers_available = {
            'openai': has_openai,
            'anthropic': has_anthropic,
            'ollama': has_ollama,
            'fallback': True,
        }

        return jsonify({
            'provider': ai_assistant.provider.value,
            'model': ai_assistant.model,
            'available': True,
            'cache_size': len(ai_assistant.cache),
            'providers_available': providers_available,
            'is_fallback': ai_assistant.provider.value == 'fallback',
            'confidence': 'High' if ai_assistant.provider.value != 'fallback' else 'Medium - Using fallback responses',
            'message': 'Using built-in responses' if ai_assistant.provider.value == 'fallback' else f'Connected to {ai_assistant.provider.value}',
        })
    except Exception as e:
        logger.error(f"Error getting AI status: {str(e)}")
        return jsonify({
            'provider': 'fallback',
            'available': True,
            'cache_size': 0,
            'providers_available': {'fallback': True},
            'is_fallback': True,
            'confidence': 'Medium - Using fallback responses',
            'message': 'Using built-in responses',
            'error': str(e),
        })


@bp.route('/reports', methods=['POST'])
def generate_report():
    try:
        data = request.get_json()
        report_type = data.get('type', 'json')

        packets = []
        alerts_list = []
        devices = []

        if ext.db_service and FEATURES['persistent_storage']:
            packets, _ = ext.db_service.get_packets(limit=10000)
            alerts_list, _ = ext.db_service.get_alerts(limit=1000)
            devices, _ = ext.db_service.get_devices()
        elif ext.sniffer:
            packets = list(ext.sniffer.captured_packets[-10000:]) if ext.sniffer.captured_packets else []
            with ext.alerts_lock:
                alerts_list = [ext._normalize_alert(a) for a in ext.alerts]
            devices = ext._collect_device_snapshot()

        generator = get_report_generator()

        if report_type == 'pdf':
            filepath = generator.generate_pdf_report(packets, alerts_list)
            if filepath:
                return send_file(filepath, as_attachment=True,
                                 download_name=f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
        elif report_type == 'csv':
            filepath = generator.generate_csv_report(packets, alerts_list)
            if filepath:
                return send_file(filepath, as_attachment=True,
                                 download_name=f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        elif report_type == 'json':
            filepath = generator.generate_json_report(packets, alerts_list, devices)
            if filepath:
                return send_file(filepath, as_attachment=True,
                                 download_name=f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

        return jsonify({'error': 'Report generation failed (maybe reportlab is missing for pdf)'}), 500
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/clear_all', methods=['POST'])
def api_clear_all():
    if ENABLE_AUTH:
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token or token in ext.jwt_blacklist:
            return jsonify({'error': 'Invalid or missing token'}), 403
    try:
        with ext.alerts_lock:
            ext.alerts.clear()
        if ext.sniffer:
            ext.sniffer.captured_packets.clear()
            ext.sniffer.devices.clear()
            ext.sniffer.active_devices.clear()
        if ext.db_service and FEATURES['persistent_storage']:
            with ext.db_service.get_session() as session:
                session.query(AlertRecord).delete()
                session.query(DeviceRecord).delete()
                session.query(PacketRecord).delete()
                session.query(UserSessionRecord).delete()
                session.commit()
        ext.add_log('info', 'API', 'All data cleared via /api/clear_all')
        return jsonify({'message': 'All data cleared'}), 200
    except Exception as e:
        logger.error(f"Error clearing all data: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/test-mode', methods=['POST'])
def api_toggle_test_mode():
    try:
        data = request.get_json() or {}
        enable = data.get('enable', True)

        if ext.sniffer and hasattr(ext.sniffer, 'security_monitor') and ext.sniffer.security_monitor:
            if enable:
                ext.sniffer.security_monitor.enable_test_mode()
                ext.add_log('info', 'API', 'Test mode ENABLED - thresholds lowered')
                return jsonify({'message': 'Test mode enabled', 'test_mode': True})
            else:
                ext.sniffer.security_monitor.disable_test_mode()
                ext.add_log('info', 'API', 'Test mode DISABLED - production thresholds restored')
                return jsonify({'message': 'Test mode disabled', 'test_mode': False})
        else:
            return jsonify({'error': 'Sniffer not running'}), 400
    except Exception as e:
        logger.error(f"Error toggling test mode: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/debug/scan-tracker', methods=['GET'])
def api_debug_scan_tracker():
    try:
        if ext.sniffer and hasattr(ext.sniffer, 'security_monitor') and ext.sniffer.security_monitor:
            monitor = ext.sniffer.security_monitor
            tracker_info = {}
            for ip, data in dict(monitor.port_scan_tracker).items():
                tracker_info[ip] = {
                    'ports_count': len(data.get('ports', set())),
                    'ports': list(data.get('ports', set()))[:20],
                    'flags': dict(data.get('flags', {})),
                    'timestamps_count': len(data.get('timestamps', [])),
                }
            return jsonify({
                'scan_tracker': tracker_info,
                'thresholds': monitor.thresholds,
                'packet_stats': monitor.packet_stats,
                'alert_counts': dict(monitor.alert_counts),
            })
        else:
            return jsonify({'error': 'Sniffer not running'}), 400
    except Exception as e:
        logger.error(f"Error getting debug info: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/stats', methods=['GET'])
def get_stats():
    try:
        if ext.sniffer:
            return jsonify(ext.sniffer.get_statistics())
        return jsonify({})
    except Exception as e:
        logger.error(f"Error retrieving stats: {str(e)}")
        return jsonify({}), 200
