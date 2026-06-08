"""
Auth Blueprint
Handles login, register, logout, and auth status.
"""

import socket
import logging
import time
import os

from flask import Blueprint, request, jsonify, g

from config.config import ENABLE_AUTH, AUTH_TOKEN_EXPIRY, FLASK_ENV
from services.auth_service import AuthService

import extensions as ext

bp = Blueprint('auth', __name__, url_prefix='/api/auth')
logger = logging.getLogger('packet_peeper')

RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_LOGIN_ATTEMPTS = int(os.getenv("RATE_LIMIT_LOGIN_ATTEMPTS", "8"))


@bp.route('/login', methods=['POST'])
def api_auth_login():
    if not ENABLE_AUTH:
        dummy_token = 'dummy-token'
        return jsonify({
            'message': 'Login successful (auth disabled)',
            'token': dummy_token,
            'expires_in': 0,
            'user': {'username': 'operator'},
            'auth_enabled': False,
        })

    allowed, retry_after = ext._check_rate_limit('auth-login', RATE_LIMIT_LOGIN_ATTEMPTS, RATE_LIMIT_WINDOW_SECONDS)
    if not allowed:
        return jsonify({
            'error': 'Too many login attempts',
            'retry_after_seconds': retry_after,
        }), 429

    payload = request.get_json(silent=True) or {}
    identifier = (payload.get('username') or payload.get('email') or '').strip()
    password = payload.get('password') or ''

    if not identifier or not password:
        return jsonify({'error': 'Username/email and password are required'}), 400

    auth_service = ext.auth_service
    if not auth_service:
        return jsonify({'error': 'Authentication service unavailable'}), 500

    device_info = {
        'ip_address': ext._get_client_ip(),
        'mac_address': payload.get('mac_address', 'unknown'),
        'hostname': socket.gethostname(),
        'user_agent': request.headers.get('User-Agent', 'unknown'),
    }

    success, message, token, user_data = auth_service.login_user(identifier, password, device_info)

    if not success:
        ext.add_log('warning', 'Auth', f'Failed login attempt for user "{identifier}" from {ext._get_client_ip()}')
        return jsonify({'error': message}), 401

    ext.add_log('info', 'Auth', f'User "{identifier}" authenticated from {ext._get_client_ip()}')

    response = jsonify({
        'message': 'Login successful',
        'token': token,
        'expires_in': AUTH_TOKEN_EXPIRY,
        'user': user_data,
        'auth_enabled': True,
    })
    response.set_cookie(
        'pp_auth_token',
        token,
        max_age=AUTH_TOKEN_EXPIRY,
        httponly=True,
        secure=(FLASK_ENV == 'production'),
        samesite='Lax',
    )
    return response


@bp.route('/register', methods=['POST'])
def api_auth_register():
    if not ENABLE_AUTH or not ext.auth_service:
        return jsonify({'error': 'User registration is disabled'}), 400

    allowed, retry_after = ext._check_rate_limit('auth-register', RATE_LIMIT_LOGIN_ATTEMPTS * 2, RATE_LIMIT_WINDOW_SECONDS)
    if not allowed:
        return jsonify({
            'error': 'Too many registration attempts',
            'retry_after_seconds': retry_after,
        }), 429

    payload = request.get_json(silent=True) or {}
    username = (payload.get('username') or '').strip()
    email = (payload.get('email') or '').strip()
    password = payload.get('password') or ''
    password_confirm = payload.get('password_confirm') or ''

    if not username or not email or not password or not password_confirm:
        return jsonify({'error': 'Username, email, and passwords are required'}), 400

    if password != password_confirm:
        return jsonify({'error': 'Passwords do not match'}), 400

    device_info = {
        'ip_address': payload.get('ip_address', ext._get_client_ip()),
        'mac_address': payload.get('mac_address', 'unknown'),
        'hostname': socket.gethostname(),
        'user_agent': request.headers.get('User-Agent', 'unknown'),
    }

    success, message, user_data = ext.auth_service.register_user(username, email, password, device_info)

    if not success:
        logger.warning(f'Registration failed for {username}: {message}')
        return jsonify({'error': message}), 400

    logger.info(f'New user registered: {username}')
    return jsonify({
        'message': 'User registered successfully',
        'user': user_data,
    }), 201


@bp.route('/status', methods=['GET'])
def api_auth_status():
    if not ENABLE_AUTH:
        return jsonify({
            'auth_enabled': False,
            'authenticated': True,
            'user': {'username': 'operator'},
            'expires_in': None,
        })

    auth_service = ext.auth_service
    if not auth_service:
        return jsonify({'auth_enabled': True, 'authenticated': False, 'error': 'auth_unavailable'}), 500

    token = ext._extract_token_from_request()
    payload, error_code = auth_service.verify_token(token)
    if error_code:
        return jsonify({
            'auth_enabled': True,
            'authenticated': False,
            'error': error_code,
        })

    exp_timestamp = int(payload.get('exp', 0))
    expires_in = max(0, exp_timestamp - int(time.time()))
    return jsonify({
        'auth_enabled': True,
        'authenticated': True,
        'user': {
            'username': payload.get('sub'),
            'role': payload.get('role'),
        },
        'expires_in': expires_in,
    })


@bp.route('/logout', methods=['POST'])
def api_auth_logout():
    if not ENABLE_AUTH:
        return jsonify({'message': 'Authentication is disabled'}), 200

    token = ext._extract_token_from_request()
    payload, _ = ext.auth_service.verify_token(token) if ext.auth_service else (None, None)

    if ext.auth_service and token:
        ext.auth_service.logout_user(token)

    if payload:
        ext.add_log('info', 'Auth', f'User "{payload.get("sub", "unknown")}" logged out')

    response = jsonify({'message': 'Logout successful'})
    response.delete_cookie('pp_auth_token')
    return response
