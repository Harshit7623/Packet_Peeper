"""
Sniffing Blueprint
Handles sniffing start/stop/status and network interface listing.
"""

import socket
import threading
import os
import logging
import datetime

from flask import Blueprint, request, jsonify

from config.config import CAPTURE_INTERFACE, ASYNC_PROCESSING, FEATURES
from services.packet_processor import get_packet_processor

import extensions as ext

from packet_sniffer import PacketSniffer

bp = Blueprint('sniffing', __name__, url_prefix='/api')
logger = logging.getLogger('packet_peeper')


def _check_capture_permissions() -> tuple[bool, str | None]:
    try:
        if os.name != 'posix':
            return True, None
        test_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        test_sock.close()
        return True, None
    except PermissionError:
        return False, "Packet capture requires elevated privileges. Run backend with sudo or grant CAP_NET_RAW/CAP_NET_ADMIN."
    except Exception as e:
        return False, f"Unable to verify capture permissions: {str(e)}"


def start_sniffing(interface: str):
    try:
        logger.info(f"[Capture] Starting packet capture on interface: {interface}")
        ext.sniffer = PacketSniffer()
        if ext.db_service and FEATURES.get('persistent_storage', False):
            try:
                from services.custom_rules_service import CustomRulesEngine
                engine = CustomRulesEngine(db_service=ext.db_service)
                engine.reload_rules(force=True)
                ext.sniffer.security_monitor.set_custom_rules_engine(engine)
                logger.info("[CustomRules] Engine attached to security monitor")
            except Exception as e:
                logger.warning(f"[CustomRules] Failed to attach engine: {e}")
        if ASYNC_PROCESSING:
            processor = get_packet_processor()
            processor.register_callback(ext.packet_callback)
            processor.start()
            ext.sniffer.set_callback(processor.put_packet)
            logger.info("[Processor] Async packet processor started")
        else:
            ext.sniffer.set_callback(ext.packet_callback)
        ext.add_log('info', 'System', f"Starting packet capture on: {interface}")
        ext.sniffer.start_sniffing(interface)
        ext.sniffing_state['is_running'] = False
        ext.sniffing_state['interface'] = None
        ext.sniffing_state['last_error'] = "Packet capture stopped"
        logger.warning("[Capture] Packet capture loop exited")
    except Exception as e:
        error_msg = f"Error starting sniffing: {str(e)}"
        logger.error(error_msg)
        ext.add_log('error', 'System', error_msg)
        ext.sniffing_state['is_running'] = False
        ext.sniffing_state['interface'] = None
        ext.sniffing_state['last_error'] = str(e)
        import traceback
        traceback.print_exc()


@bp.route('/sniffing/start', methods=['POST'])
def api_start_sniffing():
    try:
        data = request.get_json() or {}
        interface = data.get('interface') or CAPTURE_INTERFACE

        if ext.sniffing_state['is_running']:
            return jsonify({'message': 'Sniffing already running', 'interface': ext.sniffing_state['interface']}), 200

        can_capture, capture_error = _check_capture_permissions()
        if not can_capture:
            ext.sniffing_state['last_error'] = capture_error
            logger.error(f"[Capture] Permission check failed: {capture_error}")
            return jsonify({'error': capture_error}), 403

        sniffing_thread = threading.Thread(
            target=start_sniffing,
            args=(interface,),
            daemon=True,
            name="PacketSnifferThread",
        )
        sniffing_thread.start()

        ext.sniffing_state['is_running'] = True
        ext.sniffing_state['interface'] = interface
        ext.sniffing_state['start_time'] = datetime.datetime.now().isoformat()
        ext.sniffing_state['thread'] = sniffing_thread
        ext.sniffing_state['last_error'] = None

        ext.add_log('info', 'API', f'Sniffing started on interface: {interface}')
        if ext.socketio:
            ext.socketio.emit('monitoring_state', {'is_running': True, 'interface': interface}, namespace='/')
            ext.socketio.emit('sniffing_status', {'status': 'started', 'interface': interface}, namespace='/')

        return jsonify({
            'message': 'Packet sniffing started',
            'interface': interface,
            'start_time': ext.sniffing_state['start_time'],
        })
    except Exception as e:
        logger.error(f"Error starting sniffing: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/sniffing/stop', methods=['POST'])
def api_stop_sniffing():
    try:
        if ext.sniffer:
            ext.sniffer.stop_sniffing()
            ext.sniffing_state['is_running'] = False
            ext.sniffing_state['interface'] = None
            ext.sniffing_state['last_error'] = None
            ext.add_log('info', 'API', 'Sniffing stopped')
            if ext.socketio:
                ext.socketio.emit('monitoring_state', {'is_running': False, 'interface': None}, namespace='/')
                ext.socketio.emit('sniffing_status', {'status': 'stopped'}, namespace='/')
            return jsonify({'message': 'Packet sniffing stopped'})
        else:
            return jsonify({'message': 'No active sniffing session'}), 200
    except Exception as e:
        logger.error(f"Error stopping sniffing: {str(e)}")
        return jsonify({'error': str(e)}), 500


@bp.route('/sniffing/status', methods=['GET'])
def api_sniffing_status():
    return jsonify({
        'is_running': ext.sniffing_state['is_running'],
        'interface': ext.sniffing_state['interface'],
        'start_time': ext.sniffing_state['start_time'],
        'last_error': ext.sniffing_state.get('last_error'),
    })


@bp.route('/interfaces', methods=['GET'])
def api_get_interfaces():
    try:
        import psutil
        interfaces = []
        for iface, addrs in psutil.net_if_addrs().items():
            iface_lower = iface.lower()
            if iface_lower.startswith('lo') or iface_lower.startswith('loopback') or iface_lower.startswith('vethernet'):
                continue
            interface_info = {'name': iface, 'addresses': []}
            for addr in addrs:
                if getattr(addr, 'family', None) == socket.AF_INET:
                    interface_info['addresses'].append(addr.address)
            if interface_info['addresses']:
                interfaces.append(interface_info)

        if not interfaces:
            for iface, addrs in psutil.net_if_addrs().items():
                interface_info = {'name': iface, 'addresses': []}
                for addr in addrs:
                    if getattr(addr, 'family', None) == socket.AF_INET:
                        interface_info['addresses'].append(addr.address)
                if interface_info['addresses']:
                    interfaces.append(interface_info)

        return jsonify({'interfaces': interfaces})
    except Exception as e:
        logger.error(f"Error getting interfaces: {str(e)}")
        return jsonify({'interfaces': []}), 200
