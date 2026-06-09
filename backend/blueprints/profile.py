"""
Profile Blueprint
Handles user profile CRUD: get, update, change password, device info.
"""

import socket
import platform
import logging
import datetime

from flask import Blueprint, request, jsonify, g

from config.config import ENABLE_AUTH
from services.auth_service import require_auth

import extensions as ext

bp = Blueprint('profile', __name__, url_prefix='/api/profile')
logger = logging.getLogger('packet_peeper')


@bp.route('', methods=['GET'])
@require_auth
def api_get_profile():
    if not ENABLE_AUTH or not ext.auth_service:
        return jsonify({
            'username': 'operator',
            'email': 'operator@local',
            'role': 'admin',
            'default_org_id': None,
            'organizations': [],
            'created_at': datetime.datetime.fromtimestamp(ext.start_time).isoformat(),
            'last_login': datetime.datetime.now().isoformat(),
            'device_info': {
                'hostname': socket.gethostname(),
                'os': platform.system(),
                'platform': platform.platform(),
            },
            'preferences': {},
            'active_sessions': [],
            'active_session_count': 0,
        })

    username = getattr(g, 'current_user', None)
    if not username:
        return jsonify({'error': 'Authentication required'}), 401

    profile = ext.auth_service.get_user_profile(username)
    if not profile:
        return jsonify({'error': 'User not found'}), 404

    return jsonify(profile)


@bp.route('', methods=['PUT'])
@require_auth
def api_update_profile():
    if not ENABLE_AUTH or not ext.auth_service:
        return jsonify({'error': 'Profile updates not available'}), 403

    username = g.current_user
    payload = request.get_json(silent=True) or {}

    allowed_updates = {
        'device_info': payload.get('device_info'),
        'preferences': payload.get('preferences'),
        'email': payload.get('email'),
    }
    allowed_updates = {k: v for k, v in allowed_updates.items() if v is not None}

    success, message = ext.auth_service.update_profile(username, allowed_updates)
    if not success:
        return jsonify({'error': message}), 400

    logger.info(f'Profile updated for user {username}')
    return jsonify({
        'message': 'Profile updated successfully',
        'user': ext.auth_service.get_user_profile(username),
    })


@bp.route('/password', methods=['POST'])
@require_auth
def api_change_password():
    if not ENABLE_AUTH or not ext.auth_service:
        return jsonify({'error': 'Password change not available'}), 403

    username = g.current_user
    payload = request.get_json(silent=True) or {}
    old_password = payload.get('old_password') or ''
    new_password = payload.get('new_password') or ''
    new_password_confirm = payload.get('new_password_confirm') or ''

    if not old_password or not new_password or not new_password_confirm:
        return jsonify({'error': 'All password fields are required'}), 400

    if new_password != new_password_confirm:
        return jsonify({'error': 'New passwords do not match'}), 400

    success, message = ext.auth_service.change_password(username, old_password, new_password)
    if not success:
        logger.warning(f'Failed password change for user {username}')
        return jsonify({'error': message}), 400

    logger.info(f'Password changed for user {username}')
    return jsonify({'message': 'Password changed successfully'})


@bp.route('/device-info', methods=['GET'])
@require_auth
def api_get_device_info():
    try:
        import psutil
        import uuid

        mac_address = uuid.uuid1().hex[:12]
        try:
            import subprocess
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if 'link/ether' in line:
                    mac_address = line.split('link/ether')[1].split()[0]
                    break
        except Exception:
            pass

        ip_address = socket.gethostbyname(socket.gethostname())
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
            s.close()
        except Exception:
            pass

        hostname = socket.gethostname()
        cpu_count = psutil.cpu_count()
        total_memory = psutil.virtual_memory().total

        return jsonify({
            'mac_address': mac_address,
            'ip_address': ip_address,
            'hostname': hostname,
            'cpu_count': cpu_count,
            'total_memory': total_memory,
            'os': platform.system(),
        })
    except Exception as e:
        logger.error(f'Error getting device info: {str(e)}')
        return jsonify({'error': 'Failed to retrieve device information'}), 500
