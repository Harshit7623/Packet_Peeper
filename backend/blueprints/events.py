"""
Events Module - Socket.IO event handlers.
Registered in app.py after socketio is created.
"""

import logging
import threading
import datetime

from config.config import ENABLE_AUTH, CAPTURE_INTERFACE
from services.packet_processor import get_packet_processor

import extensions as ext
from blueprints.sniffing import start_sniffing

logger = logging.getLogger('packet_peeper')


def register_events(socketio):

    @socketio.on('connect')
    def handle_connect(auth=None):
        try:
            if ENABLE_AUTH:
                token = ''
                if isinstance(auth, dict):
                    token = (auth.get('token') or '').strip()
                if not token:
                    token = ext._extract_token_from_request()
                payload, error_code = ext.auth_service.verify_token(token)
                if error_code:
                    logger.warning(f"[Socket] Unauthorized connection attempt: {error_code}")
                    return False

                from flask import request as flask_request
                ext._register_socket_session(
                    sid=flask_request.sid,
                    user=payload.get('sub'),
                    user_id=payload.get('uid'),
                    role=payload.get('role'),
                    org_id=payload.get('oid'),
                )
                logger.info(f"[OK] Authenticated socket connection for user: {payload.get('sub')} (role={payload.get('role')})")
            else:
                from flask import request as flask_request
                ext._register_socket_session(
                    sid=flask_request.sid,
                    user='anonymous', user_id=0,
                    role='admin', org_id=None,
                )

            logger.info("[OK] Client connected")
            socketio.emit('connection_status', {
                'status': 'connected',
                'auth_required': ENABLE_AUTH,
            })

            with ext.alerts_lock:
                if ext.alerts:
                    socketio.emit('alerts_sync', list(ext.alerts))

            if ext.sniffer:
                socketio.emit('update_statistics', ext.sniffer.get_statistics())

        except Exception as e:
            logger.error(f"Error in connect handler: {str(e)}")

    @socketio.on('disconnect')
    def handle_disconnect(data=None):
        from flask import request as flask_request
        ext._remove_socket_session(flask_request.sid)
        logger.info("[Socket] Client disconnected")

    @socketio.on('get_logs')
    def handle_get_logs(data=None):
        with ext.logs_lock:
            socketio.emit('logs_list', list(ext.logs))

    @socketio.on('clear_logs')
    def handle_clear_logs(data=None):
        rbac = ext._check_socket_rbac('clear_logs')
        if rbac:
            code, msg = rbac
            socketio.emit('error', {'event': 'clear_logs', 'code': code, 'message': msg})
            return
        with ext.logs_lock:
            ext.logs.clear()
        ext.add_log('info', 'System', 'Logs cleared')
        with ext.logs_lock:
            socketio.emit('logs_list', list(ext.logs))

    @socketio.on('get_processor_stats')
    def handle_processor_stats(data=None):
        processor = get_packet_processor()
        socketio.emit('processor_stats', processor.get_stats())

    @socketio.on('start_sniffing')
    def handle_start_sniffing(data=None):
        rbac = ext._check_socket_rbac('start_sniffing')
        if rbac:
            code, msg = rbac
            socketio.emit('sniffing_status', {'status': 'error', 'message': msg})
            return
        try:
            payload = data or {}
            interface = payload.get('interface') or CAPTURE_INTERFACE

            if ext.sniffing_state.get('is_running'):
                socketio.emit('sniffing_status', {'status': 'already_running', 'interface': ext.sniffing_state.get('interface')})
                return

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

            ext.add_log('info', 'WebSocket', f'Sniffing started on interface: {interface}')
            socketio.emit('sniffing_status', {'status': 'started', 'interface': interface})

        except Exception as e:
            logger.error(f"Error starting sniffing via WebSocket: {str(e)}")
            socketio.emit('sniffing_status', {'status': 'error', 'message': str(e)})

    @socketio.on('stop_sniffing')
    def handle_stop_sniffing(data=None):
        rbac = ext._check_socket_rbac('stop_sniffing')
        if rbac:
            code, msg = rbac
            socketio.emit('sniffing_status', {'status': 'error', 'message': msg})
            return
        try:
            if ext.sniffer:
                ext.sniffer.stop_sniffing()
                ext.sniffing_state['is_running'] = False
                ext.sniffing_state['interface'] = None
                ext.add_log('info', 'WebSocket', 'Sniffing stopped')
                socketio.emit('sniffing_status', {'status': 'stopped'})
            else:
                socketio.emit('sniffing_status', {'status': 'not_running'})
        except Exception as e:
            logger.error(f"Error stopping sniffing via WebSocket: {str(e)}")
            socketio.emit('sniffing_status', {'status': 'error', 'message': str(e)})

    @socketio.on('scan_devices')
    def handle_scan_devices(data=None):
        rbac = ext._check_socket_rbac('scan_devices')
        if rbac:
            code, msg = rbac
            socketio.emit('devices_update', {'devices': [], 'error': msg})
            return
        try:
            if ext.sniffer:
                devices = ext._collect_device_snapshot()
                socketio.emit('devices_update', {'devices': devices, 'totalDevices': len(devices)})
                ext.add_log('info', 'WebSocket', f'Device scan complete: {len(devices)} devices found')
            else:
                socketio.emit('devices_update', {'devices': [], 'totalDevices': 0, 'error': 'Sniffer not running'})
        except Exception as e:
            logger.error(f"Error scanning devices via WebSocket: {str(e)}")
            socketio.emit('devices_update', {'devices': [], 'error': str(e)})
