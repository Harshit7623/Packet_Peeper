"""
Packet Peeper - Flask Backend Application (Refactored)
Integrates database, async processing, and reporting services
"""

from flask import Flask, request, jsonify, send_file, send_from_directory, g
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import threading
import sys
import time
import json
import logging
import logging.handlers
import datetime
import os
import socket
import secrets
from collections import defaultdict
from functools import wraps
from pathlib import Path
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import check_password_hash, generate_password_hash

# Import config first (before anything else)
from config.config import (
    FLASK_ENV, FLASK_DEBUG, SECRET_KEY, HOST, PORT,
    LOG_LEVEL, LOG_FILE, LOG_FORMAT, LOG_MAX_BYTES, LOG_BACKUP_COUNT,
    SOCKETIO_PING_TIMEOUT, SOCKETIO_PING_INTERVAL, SOCKETIO_TRANSPORTS,
    ALERT_MAX_STORED, FEATURES, ASYNC_PROCESSING, CAPTURE_INTERFACE,
    ENABLE_AUTH, AUTH_TOKEN_EXPIRY, JWT_SECRET
)

# Import services
from services.database_services import get_database_service
from services.packet_processor import init_packet_processor, get_packet_processor
from services.report_generator import get_report_generator
from services.ai_assistant import get_ai_assistant, init_ai_assistant
from packet_sniffer import PacketSniffer
from network_security_monitor import NetworkSecurityMonitor

# ============== FLASK SETUP ==============
PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIST_DIR = PROJECT_ROOT / 'frontend' / 'dist'

AUTH_USERNAME = os.getenv("AUTH_USERNAME", "admin")
AUTH_PASSWORD = os.getenv("AUTH_PASSWORD", "admin123")
AUTH_PASSWORD_HASH = os.getenv("AUTH_PASSWORD_HASH") or generate_password_hash(AUTH_PASSWORD)
AUTH_TOKEN_SALT = "packet-peeper-auth"

RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_MAX_REQUESTS = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "300"))
RATE_LIMIT_LOGIN_ATTEMPTS = int(os.getenv("RATE_LIMIT_LOGIN_ATTEMPTS", "8"))

ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "*").split(",")
    if origin.strip()
]
CORS_ORIGINS = "*" if ALLOWED_ORIGINS == ["*"] else ALLOWED_ORIGINS

if FRONTEND_DIST_DIR.exists():
    app = Flask(__name__, static_folder=str(FRONTEND_DIST_DIR), static_url_path='')
else:
    app = Flask(__name__)

app.config['SECRET_KEY'] = SECRET_KEY
app.config['ENV'] = FLASK_ENV
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv("MAX_REQUEST_BYTES", str(2 * 1024 * 1024)))

# CORS configuration: Allow requests from all frontend dev server ports
CORS(app, 
    resources={r"/*": {"origins": CORS_ORIGINS}},
    supports_credentials=False,
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    expose_headers=["Content-Type", "Authorization"]
)

# Allow Socket.IO connections from frontend dev server
socketio_cors_allowed_origins = CORS_ORIGINS

# ============== LOGGING SETUP ==============
log_dir = Path(LOG_FILE).parent
log_dir.mkdir(parents=True, exist_ok=True)

# Configure logging with rotation
logger = logging.getLogger('packet_peeper')
logger.setLevel(getattr(logging, LOG_LEVEL))

# File handler with rotation
file_handler = logging.handlers.RotatingFileHandler(
    LOG_FILE,
    maxBytes=LOG_MAX_BYTES,
    backupCount=LOG_BACKUP_COUNT
)
file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
logger.addHandler(file_handler)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
logger.addHandler(console_handler)

# ============== SOCKETIO SETUP ==============
socketio = SocketIO(
    app,
    cors_allowed_origins=socketio_cors_allowed_origins,
    async_mode='threading',
    logger=FLASK_DEBUG,
    engineio_logger=FLASK_DEBUG,
    ping_timeout=SOCKETIO_PING_TIMEOUT,
    ping_interval=SOCKETIO_PING_INTERVAL,
    max_http_buffer_size=1e8,
    allow_upgrades=True,
    http_compression=True,
    transports=SOCKETIO_TRANSPORTS,
    always_connect=True,
)

# ============== GLOBAL STATE ==============
alerts = []
logs = []
sniffer = None
db_service = None
start_time = time.time()  # Application start time
auth_serializer = URLSafeTimedSerializer(JWT_SECRET)
active_sessions = {}
revoked_sessions = set()
rate_limit_state = defaultdict(list)

PUBLIC_API_PATHS = {
    '/api/auth/login',
    '/api/auth/status',
    '/api/health',
}

# ============== DATABASE INITIALIZATION ==============
try:
    db_service = get_database_service()
    logger.info("[OK] Database service initialized")
except Exception as e:
    logger.warning(f"[WARN] Database initialization failed: {str(e)}")

# ============== PACKET PROCESSOR INITIALIZATION ==============
try:
    packet_processor = init_packet_processor()
    logger.info("[OK] Packet processor initialized")
except Exception as e:
    logger.error(f"[ERROR] Packet processor initialization failed: {str(e)}")

# ============== UTILITY FUNCTIONS ==============

def add_log(level: str, source: str, message: str):
    """Add log entry and broadcast to clients"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {
        'timestamp': timestamp,
        'level': level,
        'source': source,
        'message': message
    }
    
    logs.append(log_entry)
    if len(logs) > 1000:
        logs.pop(0)
    
    # Log to file
    log_method = getattr(logger, level.lower(), logger.info)
    log_method(f"[{source}] {message}")
    
    # Broadcast to clients
    socketio.emit('new_log', log_entry, namespace='/')


def _resolve_cors_origin() -> str:
    """Return the best allowed origin for the current request."""
    if CORS_ORIGINS == '*':
        return '*'

    request_origin = request.headers.get('Origin', '')
    if request_origin and request_origin in CORS_ORIGINS:
        return request_origin

    if CORS_ORIGINS:
        return CORS_ORIGINS[0]

    return '*'


def _get_client_ip() -> str:
    forwarded_for = request.headers.get('X-Forwarded-For', '')
    if forwarded_for:
        first_ip = forwarded_for.split(',')[0].strip()
        if first_ip:
            return first_ip
    return request.remote_addr or 'unknown'


def _check_rate_limit(scope: str, max_requests: int, window_seconds: int):
    """Simple in-memory burst limiter keyed by client IP."""
    now = time.time()
    key = f"{scope}:{_get_client_ip()}"
    timestamps = rate_limit_state[key]

    while timestamps and now - timestamps[0] > window_seconds:
        timestamps.pop(0)

    if len(timestamps) >= max_requests:
        retry_after = max(1, int(window_seconds - (now - timestamps[0])))
        return False, retry_after

    timestamps.append(now)
    return True, 0


def _cleanup_expired_sessions():
    """Trim expired in-memory sessions and revocation markers."""
    if not active_sessions:
        return

    now = time.time()
    expired_ids = [
        session_id
        for session_id, data in active_sessions.items()
        if now - data.get('iat', now) > AUTH_TOKEN_EXPIRY
    ]

    for session_id in expired_ids:
        active_sessions.pop(session_id, None)
        revoked_sessions.discard(session_id)


def _extract_token_from_request() -> str:
    auth_header = request.headers.get('Authorization', '')
    if auth_header.lower().startswith('bearer '):
        return auth_header.split(' ', 1)[1].strip()

    return request.cookies.get('pp_auth_token', '').strip()


def _issue_access_token(username: str):
    session_id = secrets.token_urlsafe(16)
    issued_at = int(time.time())
    payload = {
        'sub': username,
        'sid': session_id,
        'iat': issued_at,
    }

    token = auth_serializer.dumps(payload, salt=AUTH_TOKEN_SALT)
    active_sessions[session_id] = {
        'username': username,
        'iat': issued_at,
        'ip': _get_client_ip(),
    }
    return token, payload


def _verify_access_token(token: str):
    if not token:
        return None, 'missing_token'

    try:
        payload = auth_serializer.loads(
            token,
            salt=AUTH_TOKEN_SALT,
            max_age=AUTH_TOKEN_EXPIRY,
        )
    except SignatureExpired:
        return None, 'token_expired'
    except BadSignature:
        return None, 'invalid_token'

    session_id = payload.get('sid')
    username = payload.get('sub')

    if not session_id or not username:
        return None, 'invalid_token'

    if session_id in revoked_sessions:
        return None, 'token_revoked'

    session_data = active_sessions.get(session_id)
    if not session_data:
        return None, 'session_not_found'

    if session_data.get('username') != username:
        return None, 'invalid_session'

    session_data['last_seen'] = int(time.time())
    return payload, None


def auth_required(func):
    """Decorator for API routes that require authenticated access."""

    @wraps(func)
    def wrapped(*args, **kwargs):
        if not ENABLE_AUTH:
            return func(*args, **kwargs)

        payload, error_code = _verify_access_token(_extract_token_from_request())
        if error_code:
            return jsonify({'error': 'Authentication required', 'code': error_code}), 401

        g.current_user = payload.get('sub')
        g.current_session_id = payload.get('sid')
        return func(*args, **kwargs)

    return wrapped

def broadcast_alert(alert_type: str, message: str, severity: str = 'medium',
                   source: str = 'System', additional_info: dict = None) -> bool:
    """Broadcast alert to all connected clients"""
    try:
        timestamp = datetime.datetime.now().isoformat()
        alert = {
            'id': len(alerts) + 1,
            'type': alert_type,
            'title': message[:50] + '...' if len(message) > 50 else message,
            'description': message,
            'timestamp': timestamp,
            'source': source,
            'severity': severity,
        }
        
        if additional_info:
            alert.update(additional_info)
        
        alerts.insert(0, alert)
        if len(alerts) > ALERT_MAX_STORED:
            alerts.pop()
        
        # Save to database if enabled
        if db_service and FEATURES['persistent_storage']:
            db_service.save_alert(alert)
        
        # Broadcast to clients
        socketio.emit('new_alert', alert, namespace='/')
        logger.info(f"[ALERT] {severity.upper()} - {message}")
        
        return True
    
    except Exception as e:
        logger.error(f"Error broadcasting alert: {str(e)}")
        return False

def security_alert_callback(alert: dict):
    """Callback for security alerts from NetworkSecurityMonitor"""
    global alerts
    try:
        if alert is None:
            return  # Alert was filtered by rate limiter
            
        # Check for duplicate alerts of same type (within last 20)
        alert_type = alert.get('type')
        existing_count = sum(1 for a in alerts[:20] if a.get('type') == alert_type)
        
        # Skip if we already have 3+ of this alert type in recent history
        if existing_count >= 3:
            logger.debug(f"Skipping duplicate alert type: {alert_type} (already {existing_count})")
            return
        
        # Add to alerts list
        alerts.insert(0, alert)
        if len(alerts) > ALERT_MAX_STORED:
            alerts.pop()
        
        # Save to database if enabled
        if db_service and FEATURES['persistent_storage']:
            try:
                db_service.save_alert(alert)
            except Exception as e:
                logger.error(f"Error saving alert to database: {e}")
        
        # Broadcast to all connected clients
        socketio.emit('new_alert', alert, namespace='/')
        
        # Also emit to security-specific channel
        socketio.emit('security_alert', alert, namespace='/')
        
        logger.warning(f"[ALERT] [{alert.get('severity', 'medium').upper()}] {alert.get('title')}: {alert.get('description')}")
        
    except Exception as e:
        logger.error(f"Error in security alert callback: {e}")

def packet_callback(packet_info: dict):
    """Callback for each processed packet"""
    try:
        # Check if this is a security alert passed through the packet callback
        if packet_info.get('alert_type') == 'security':
            security_alert_callback(packet_info)
            return
        
        # Emit packet via WebSocket
        socketio.emit('new_packet', packet_info, namespace='/')
        
        # Save to database if enabled
        if db_service and FEATURES['persistent_storage']:
            db_service.save_packet(packet_info)
        
        # Get updated statistics
        if sniffer:
            stats = sniffer.get_statistics()
            socketio.emit('update_statistics', stats, namespace='/')
        
        # Log (only for non-debug level to reduce noise)
        if LOG_LEVEL == 'DEBUG':
            add_log('debug', 'PacketSniffer', 
                   f"Captured {packet_info.get('protocol')} packet: "
                   f"{packet_info.get('src_ip')} -> {packet_info.get('dst_ip')}")
    
    except Exception as e:
        logger.error(f"Error in packet callback: {str(e)}")

def device_update_loop():
    """Periodically broadcast device updates"""
    while True:
        try:
            if sniffer:
                devices = sniffer.get_devices()
                active_devices = list(sniffer.active_devices.values())
                
                all_devices = []
                seen_ips = set()
                
                for device in devices:
                    if device.get('ipAddress'):
                        all_devices.append(device)
                        seen_ips.add(device['ipAddress'])
                
                for device in active_devices:
                    if device.get('ipAddress') and device['ipAddress'] not in seen_ips:
                        all_devices.append(device)
                
                socketio.emit('devices_update', {
                    'devices': all_devices,
                    'timestamp': time.time(),
                    'totalDevices': len(all_devices),
                }, namespace='/')
            
            time.sleep(2)
        
        except Exception as e:
            logger.error(f"Error in device update loop: {str(e)}")
            time.sleep(5)

def traffic_update_loop():
    """Periodically broadcast traffic statistics"""
    while True:
        try:
            if sniffer:
                stats = sniffer.get_statistics()
                protocols = {
                    'TCP': stats.get('tcpPackets', 0),
                    'UDP': stats.get('udpPackets', 0),
                    'ICMP': stats.get('icmpPackets', 0),
                }
                
                socketio.emit('traffic_update', {
                    'total_packets': stats.get('totalPackets', 0),
                    'bandwidth': {
                        'current': stats.get('currentBandwidth', 0),
                        'peak': stats.get('peakBandwidth', 0),
                        'average': stats.get('averageBandwidth', 0),
                    },
                    'protocols': protocols,
                }, namespace='/')
            
            time.sleep(1)
        
        except Exception as e:
            logger.error(f"Error in traffic update loop: {str(e)}")
            time.sleep(5)

# ============== FLASK ROUTES ==============

# Handle CORS preflight requests for all API endpoints
@app.before_request
def handle_preflight_and_guards():
    _cleanup_expired_sessions()

    if request.method == "OPTIONS":
        response = app.make_default_options_response()
        response.headers['Access-Control-Allow-Origin'] = _resolve_cors_origin()
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        response.headers['Access-Control-Max-Age'] = '600'
        return response

    if not request.path.startswith('/api/'):
        return None

    allowed, retry_after = _check_rate_limit('api', RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECONDS)
    if not allowed:
        return jsonify({
            'error': 'Rate limit exceeded',
            'retry_after_seconds': retry_after,
        }), 429

    if ENABLE_AUTH and request.path not in PUBLIC_API_PATHS:
        payload, error_code = _verify_access_token(_extract_token_from_request())
        if error_code:
            return jsonify({'error': 'Authentication required', 'code': error_code}), 401

        g.current_user = payload.get('sub')
        g.current_session_id = payload.get('sid')

    return None

@app.after_request
def after_request(response):
    """Add CORS and baseline security headers to all responses."""
    response.headers['Access-Control-Allow-Origin'] = _resolve_cors_origin()
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
    response.headers['Vary'] = 'Origin'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'

    if request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store'

    if FLASK_ENV == 'production':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    return response

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_spa(path):
    """Serve React SPA - serves index.html for all non-API routes"""
    static_folder = Path(app.static_folder) if app.static_folder else None

    # API routes handled by Flask
    if path.startswith('api/'):
        return jsonify({'error': 'API endpoint not found'}), 404

    if not static_folder or not static_folder.exists():
        return jsonify({'error': 'Frontend build not found. Build frontend/dist first.'}), 404
    
    # Serve static files (JS, CSS, images, etc.)
    if path and ('.' in path or path.startswith('assets/')):
        try:
            return send_from_directory(app.static_folder, path)
        except Exception:
            pass
    
    # Serve index.html for all other routes (SPA routing)
    try:
        return send_from_directory(app.static_folder, 'index.html')
    except Exception:
        return jsonify({'error': 'Frontend not found'}), 404


@app.route('/api/auth/login', methods=['POST'])
def api_auth_login():
    """Authenticate operator and issue a signed access token."""
    if not ENABLE_AUTH:
        return jsonify({'error': 'Authentication is disabled by server configuration'}), 400

    allowed, retry_after = _check_rate_limit('auth-login', RATE_LIMIT_LOGIN_ATTEMPTS, RATE_LIMIT_WINDOW_SECONDS)
    if not allowed:
        return jsonify({
            'error': 'Too many login attempts',
            'retry_after_seconds': retry_after,
        }), 429

    payload = request.get_json(silent=True) or {}
    username = (payload.get('username') or '').strip()
    password = payload.get('password') or ''

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    is_valid_user = username == AUTH_USERNAME
    is_valid_password = False

    if is_valid_user:
        try:
            is_valid_password = check_password_hash(AUTH_PASSWORD_HASH, password)
        except Exception:
            is_valid_password = False

    if not (is_valid_user and is_valid_password):
        add_log('warning', 'Auth', f'Failed login attempt for user "{username}" from {_get_client_ip()}')
        return jsonify({'error': 'Invalid username or password'}), 401

    token, _ = _issue_access_token(username)
    add_log('info', 'Auth', f'User "{username}" authenticated from {_get_client_ip()}')

    response = jsonify({
        'message': 'Login successful',
        'token': token,
        'expires_in': AUTH_TOKEN_EXPIRY,
        'user': {'username': username},
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


@app.route('/api/auth/status', methods=['GET'])
def api_auth_status():
    """Return current authentication state for the caller."""
    if not ENABLE_AUTH:
        return jsonify({
            'auth_enabled': False,
            'authenticated': True,
            'user': {'username': 'operator'},
            'expires_in': None,
        })

    token = _extract_token_from_request()
    payload, error_code = _verify_access_token(token)
    if error_code:
        return jsonify({
            'auth_enabled': True,
            'authenticated': False,
            'error': error_code,
        })

    expires_in = max(0, AUTH_TOKEN_EXPIRY - int(time.time()) + int(payload.get('iat', time.time())))
    return jsonify({
        'auth_enabled': True,
        'authenticated': True,
        'user': {'username': payload.get('sub')},
        'expires_in': expires_in,
    })


@app.route('/api/auth/logout', methods=['POST'])
def api_auth_logout():
    """Revoke current access token and clear cookie state."""
    if not ENABLE_AUTH:
        return jsonify({'message': 'Authentication is disabled'}), 200

    token = _extract_token_from_request()
    payload, _ = _verify_access_token(token)

    if payload and payload.get('sid'):
        session_id = payload.get('sid')
        revoked_sessions.add(session_id)
        active_sessions.pop(session_id, None)
        add_log('info', 'Auth', f'User "{payload.get("sub", "unknown")}" logged out')

    response = jsonify({'message': 'Logout successful'})
    response.delete_cookie('pp_auth_token')
    return response

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get alerts from database or memory"""
    try:
        if db_service and FEATURES['persistent_storage']:
            limit = request.args.get('limit', 100, type=int)
            db_alerts = db_service.get_alerts(limit=limit)
            return jsonify(db_alerts)
        else:
            return jsonify(alerts)
    except Exception as e:
        logger.error(f"Error retrieving alerts: {str(e)}")
        return jsonify(alerts), 200

@app.route('/api/security_alerts', methods=['GET'])
def get_security_alerts():
    """Get security-specific alerts"""
    try:
        security_alert_types = ['port_scan', 'ddos', 'brute_force', 'dns_tunneling']
        
        if db_service and FEATURES['persistent_storage']:
            limit = request.args.get('limit', 100, type=int)
            all_alerts = db_service.get_alerts(limit=limit)
            security_alerts = [a for a in all_alerts if a.get('type') in security_alert_types]
            return jsonify(security_alerts)
        else:
            security_alerts = [a for a in alerts if a.get('type') in security_alert_types]
            return jsonify(security_alerts)
    except Exception as e:
        logger.error(f"Error retrieving security alerts: {str(e)}")
        return jsonify([]), 200

@app.route('/api/packets', methods=['GET'])
def get_packets():
    """Get captured packets"""
    try:
        if db_service and FEATURES['persistent_storage']:
            limit = request.args.get('limit', 1000, type=int)
            db_packets = db_service.get_packets(limit=limit)
            return jsonify(db_packets)
        else:
            limit = request.args.get('limit', 1000, type=int)
            return jsonify(sniffer.captured_packets[-limit:] if sniffer else [])
    except Exception as e:
        logger.error(f"Error retrieving packets: {str(e)}")
        return jsonify([]), 200

@app.route('/api/devices', methods=['GET'])
def get_devices():
    """Get network devices"""
    try:
        if sniffer:
            devices = sniffer.get_devices()
            if db_service and FEATURES['persistent_storage']:
                db_devices = db_service.get_devices()
                return jsonify(db_devices)
            return jsonify(devices)
        return jsonify([])
    except Exception as e:
        logger.error(f"Error retrieving devices: {str(e)}")
        return jsonify([]), 200

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get network statistics"""
    try:
        if sniffer:
            return jsonify(sniffer.get_statistics())
        return jsonify({})
    except Exception as e:
        logger.error(f"Error retrieving stats: {str(e)}")
        return jsonify({}), 200

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Get application logs"""
    try:
        limit = request.args.get('limit', 100, type=int)
        return jsonify(logs[-limit:] if logs else [])
    except Exception as e:
        logger.error(f"Error retrieving logs: {str(e)}")
        return jsonify([]), 200

@app.route('/api/reports', methods=['POST'])
def generate_report():
    """Generate report in requested format"""
    try:
        data = request.get_json()
        report_type = data.get('type', 'json')  # pdf, csv, json
        
        if sniffer and db_service and FEATURES['persistent_storage']:
            packets = db_service.get_packets(limit=10000)
            alerts_list = db_service.get_alerts(limit=1000)
            devices = db_service.get_devices()
            
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
        
        return jsonify({'error': 'Report generation failed'}), 500
    
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============== SNIFFING CONTROL API ==============

sniffing_state = {
    'is_running': False,
    'interface': None,
    'start_time': None,
    'thread': None,
    'last_error': None
}


def _check_capture_permissions() -> tuple[bool, str | None]:
    """Verify the current process can open raw sockets for packet capture."""
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

@app.route('/api/sniffing/start', methods=['POST'])
def api_start_sniffing():
    """Start packet sniffing via API"""
    global sniffer, sniffing_state
    
    try:
        data = request.get_json() or {}
        interface = data.get('interface') or CAPTURE_INTERFACE
        
        if sniffing_state['is_running']:
            return jsonify({'message': 'Sniffing already running', 'interface': sniffing_state['interface']}), 200

        can_capture, capture_error = _check_capture_permissions()
        if not can_capture:
            sniffing_state['last_error'] = capture_error
            logger.error(f"[Capture] Permission check failed: {capture_error}")
            return jsonify({'error': capture_error}), 403
        
        # Start sniffing in background thread
        sniffing_thread = threading.Thread(
            target=start_sniffing,
            args=(interface,),
            daemon=True,
            name="PacketSnifferThread"
        )
        sniffing_thread.start()
        
        sniffing_state['is_running'] = True
        sniffing_state['interface'] = interface
        sniffing_state['start_time'] = datetime.datetime.now().isoformat()
        sniffing_state['thread'] = sniffing_thread
        sniffing_state['last_error'] = None
        
        add_log('info', 'API', f'Sniffing started on interface: {interface}')
        
        return jsonify({
            'message': 'Packet sniffing started',
            'interface': interface,
            'start_time': sniffing_state['start_time']
        })
    
    except Exception as e:
        logger.error(f"Error starting sniffing: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/sniffing/stop', methods=['POST'])
def api_stop_sniffing():
    """Stop packet sniffing via API"""
    global sniffer, sniffing_state
    
    try:
        if sniffer:
            sniffer.stop_sniffing()
            sniffing_state['is_running'] = False
            sniffing_state['interface'] = None
            sniffing_state['last_error'] = None
            add_log('info', 'API', 'Sniffing stopped')
            return jsonify({'message': 'Packet sniffing stopped'})
        else:
            return jsonify({'message': 'No active sniffing session'}), 200
    
    except Exception as e:
        logger.error(f"Error stopping sniffing: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/sniffing/status', methods=['GET'])
def api_sniffing_status():
    """Get sniffing status"""
    return jsonify({
        'is_running': sniffing_state['is_running'],
        'interface': sniffing_state['interface'],
        'start_time': sniffing_state['start_time'],
        'last_error': sniffing_state.get('last_error')
    })

@app.route('/api/interfaces', methods=['GET'])
def api_get_interfaces():
    """Get available network interfaces"""
    try:
        import psutil
        interfaces = []
        for iface, addrs in psutil.net_if_addrs().items():
            iface_lower = iface.lower()

            # Filter out loopback and virtual adapters where possible.
            if iface_lower.startswith('lo') or iface_lower.startswith('loopback') or iface_lower.startswith('vethernet'):
                continue

            interface_info = {'name': iface, 'addresses': []}
            for addr in addrs:
                if getattr(addr, 'family', None) == socket.AF_INET:
                    interface_info['addresses'].append(addr.address)

            # Skip interfaces without IPv4 addresses.
            if interface_info['addresses']:
                interfaces.append(interface_info)

        # Fallback: if filtering removed everything, return a best-effort list.
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

# ============== NETWORK SCANNING API ==============

@app.route('/api/network/scan', methods=['POST'])
def api_scan_network():
    """Trigger network device scan"""
    try:
        if sniffer:
            # Trigger device discovery
            devices = sniffer.get_devices()
            socketio.emit('devices_update', {'devices': devices}, namespace='/')
            add_log('info', 'API', 'Network scan initiated')
            return jsonify({'message': 'Network scan initiated', 'devices_found': len(devices)})
        return jsonify({'message': 'Sniffer not running'}), 400
    except Exception as e:
        logger.error(f"Error scanning network: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============== ALERTS API ==============

@app.route('/api/alerts/<int:alert_id>/dismiss', methods=['POST'])
def api_dismiss_alert(alert_id):
    """Dismiss a specific alert"""
    global alerts
    try:
        alerts = [a for a in alerts if a.get('id') != alert_id]
        if db_service:
            db_service.dismiss_alert(alert_id)
        return jsonify({'message': f'Alert {alert_id} dismissed'})
    except Exception as e:
        logger.error(f"Error dismissing alert: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/clear', methods=['POST'])
def api_clear_alerts():
    """Clear all alerts and reset security monitor counters"""
    global alerts, sniffer
    try:
        # Clear in-memory alerts
        alerts.clear()
        
        # Clear database alerts if persistent storage is enabled
        if db_service and FEATURES['persistent_storage']:
            db_service.clear_alerts()
        
        # Reset security monitor counters to prevent continued spam
        if sniffer and hasattr(sniffer, 'security_monitor') and sniffer.security_monitor:
            sniffer.security_monitor.reset_counters()
            
        add_log('info', 'API', 'All alerts cleared and security counters reset')
        socketio.emit('alerts_sync', [], namespace='/')
        return jsonify({'message': 'All alerts cleared'})
    except Exception as e:
        logger.error(f"Error clearing alerts: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/test-mode', methods=['POST'])
def api_toggle_test_mode():
    """Toggle test mode for easier attack detection during testing"""
    global sniffer
    try:
        data = request.get_json() or {}
        enable = data.get('enable', True)
        
        if sniffer and hasattr(sniffer, 'security_monitor') and sniffer.security_monitor:
            if enable:
                sniffer.security_monitor.enable_test_mode()
                add_log('info', 'API', 'Test mode ENABLED - thresholds lowered')
                return jsonify({'message': 'Test mode enabled', 'test_mode': True})
            else:
                sniffer.security_monitor.disable_test_mode()
                add_log('info', 'API', 'Test mode DISABLED - production thresholds restored')
                return jsonify({'message': 'Test mode disabled', 'test_mode': False})
        else:
            return jsonify({'error': 'Sniffer not running'}), 400
    except Exception as e:
        logger.error(f"Error toggling test mode: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/detection/profile', methods=['GET', 'POST'])
def api_detection_profile():
    """Get or set detection profile for attack sensitivity tuning"""
    global sniffer
    try:
        if request.method == 'GET':
            # Return current profile and available profiles
            if sniffer and hasattr(sniffer, 'security_monitor') and sniffer.security_monitor:
                monitor = sniffer.security_monitor
                return jsonify({
                    'current_profile': monitor.get_profile(),
                    'available_profiles': ['strict', 'balanced', 'sensitive', 'test'],
                    'current_thresholds': monitor.get_thresholds(),
                    'description': {
                        'strict': 'High bar for alerts - fewer false positives, may miss subtle attacks',
                        'balanced': 'Default tuning - balanced between sensitivity and false positive rate',
                        'sensitive': 'Low bar for alerts - catches more potential attacks, more false positives',
                        'test': 'Very low bar - for testing, expects many alerts even from normal traffic'
                    }
                })
            else:
                return jsonify({'error': 'Sniffer not running'}), 400
        
        elif request.method == 'POST':
            # Set detection profile
            data = request.get_json() or {}
            profile = data.get('profile', 'balanced')
            
            if sniffer and hasattr(sniffer, 'security_monitor') and sniffer.security_monitor:
                monitor = sniffer.security_monitor
                new_profile = monitor.set_profile(profile)
                add_log('info', 'API', f'Detection profile changed to: {new_profile}')
                return jsonify({
                    'message': f'Profile changed to {new_profile}',
                    'current_profile': new_profile,
                    'current_thresholds': monitor.get_thresholds()
                })
            else:
                return jsonify({'error': 'Sniffer not running'}), 400
    
    except Exception as e:
        logger.error(f"Error managing detection profile: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug/scan-tracker', methods=['GET'])
def api_debug_scan_tracker():
    """Debug endpoint to check port scan tracker state"""
    global sniffer
    try:
        if sniffer and hasattr(sniffer, 'security_monitor') and sniffer.security_monitor:
            monitor = sniffer.security_monitor
            tracker_info = {}
            for ip, data in dict(monitor.port_scan_tracker).items():
                tracker_info[ip] = {
                    'ports_count': len(data.get('ports', set())),
                    'ports': list(data.get('ports', set()))[:20],  # First 20 ports
                    'flags': dict(data.get('flags', {})),
                    'timestamps_count': len(data.get('timestamps', []))
                }
            return jsonify({
                'scan_tracker': tracker_info,
                'thresholds': monitor.thresholds,
                'packet_stats': monitor.packet_stats,
                'alert_counts': dict(monitor.alert_counts)
            })
        else:
            return jsonify({'error': 'Sniffer not running'}), 400
    except Exception as e:
        logger.error(f"Error getting debug info: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============== LOGS API ==============

@app.route('/api/logs/clear', methods=['POST'])
def api_clear_logs():
    """Clear all logs"""
    global logs
    try:
        logs.clear()
        add_log('info', 'System', 'Logs cleared via API')
        socketio.emit('logs_list', logs, namespace='/')
        return jsonify({'message': 'Logs cleared'})
    except Exception as e:
        logger.error(f"Error clearing logs: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============== SETTINGS API ==============

app_settings = {
    'auto_blocking': True,
    'real_time_alerts': True,
    'desktop_notifications': True,
    'sound_alerts': False,
    'capture_filter': '',
    'max_packets': 10000,
    'alert_threshold': 5
}

@app.route('/api/settings', methods=['GET'])
def api_get_settings():
    """Get application settings"""
    return jsonify(app_settings)

@app.route('/api/settings', methods=['PUT'])
def api_update_settings():
    """Update application settings"""
    try:
        data = request.get_json()
        for key, value in data.items():
            if key in app_settings:
                app_settings[key] = value
        add_log('info', 'API', 'Settings updated')
        return jsonify({'message': 'Settings updated', 'settings': app_settings})
    except Exception as e:
        logger.error(f"Error updating settings: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============== AI ASSISTANT API ==============

@app.route('/api/ai/remediate', methods=['POST'])
def api_ai_remediate():
    """Get AI-powered remediation advice for an alert"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No alert data provided'}), 400
        
        ai_assistant = get_ai_assistant()
        response = ai_assistant.get_remediation(data)
        
        add_log('info', 'AI', f"Generated remediation for: {data.get('type', 'unknown')}")
        
        return jsonify(response.to_dict())
    
    except Exception as e:
        logger.error(f"Error getting AI remediation: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'explanation': 'Unable to generate AI response. Please try again.',
            'steps': ['Review the alert details manually.'],
            'severity_assessment': 'Unknown',
            'estimated_risk': 'Unable to assess'
        }), 500

@app.route('/api/ai/explain', methods=['POST'])
def api_ai_explain():
    """Get AI explanation for a technical term"""
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

@app.route('/api/ai/health-summary', methods=['GET'])
def api_ai_health_summary():
    """Get AI-generated network health summary"""
    try:
        # Gather stats
        critical_count = sum(1 for a in alerts if a.get('severity') == 'critical')
        high_count = sum(1 for a in alerts if a.get('severity') == 'high')
        medium_count = sum(1 for a in alerts if a.get('severity') == 'medium')
        
        stats = {
            'total_alerts': len(alerts),
            'critical_alerts': critical_count,
            'high_alerts': high_count,
            'medium_alerts': medium_count
        }
        
        ai_assistant = get_ai_assistant()
        summary = ai_assistant.get_network_health_summary(stats)
        
        return jsonify(summary)
    
    except Exception as e:
        logger.error(f"Error getting health summary: {str(e)}")
        return jsonify({
            'status': '[Unknown]',
            'message': 'Unable to determine network health status.',
            'action': 'Check your alerts manually.'
        }), 500

@app.route('/api/ai/status', methods=['GET'])
def api_ai_status():
    """Get AI assistant status and configuration"""
    try:
        ai_assistant = get_ai_assistant()
        
        # Check if API keys are configured
        has_openai = bool(os.getenv("OPENAI_API_KEY"))
        has_anthropic = bool(os.getenv("ANTHROPIC_API_KEY"))
        has_ollama = False
        try:
            import requests
            resp = requests.get(f"{os.getenv('OLLAMA_URL', 'http://localhost:11434')}/api/tags", timeout=2)
            has_ollama = resp.status_code == 200
        except:
            pass
        
        providers_available = {
            'openai': has_openai,
            'anthropic': has_anthropic,
            'ollama': has_ollama,
            'fallback': True  # Always available
        }
        
        return jsonify({
            'provider': ai_assistant.provider.value,
            'model': ai_assistant.model,
            'available': True,
            'cache_size': len(ai_assistant.cache),
            'providers_available': providers_available,
            'is_fallback': ai_assistant.provider.value == 'fallback',
            'confidence': 'High' if ai_assistant.provider.value != 'fallback' else 'Medium - Using fallback responses',
            'message': 'Using built-in responses' if ai_assistant.provider.value == 'fallback' else f'Connected to {ai_assistant.provider.value}'
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
            'error': str(e)
        })

# ============== SYSTEM INFO API ==============

@app.route('/api/system/info', methods=['GET'])
def api_system_info():
    """Get system information"""
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
                'percent': psutil.virtual_memory().percent
            },
            'disk': {
                'total': psutil.disk_usage('/').total,
                'used': psutil.disk_usage('/').used,
                'percent': psutil.disk_usage('/').percent
            }
        })
    except Exception as e:
        logger.error(f"Error getting system info: {str(e)}")
        return jsonify({}), 200

@app.route('/api/health', methods=['GET'])
def api_health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'uptime': time.time() - start_time if 'start_time' in globals() else 0,
        'version': '2.0.0',
        'sniffing': sniffing_state['is_running'],
        'database': db_service is not None,
        'auth_enabled': ENABLE_AUTH,
    })

# ============== ANALYTICS API ==============

@app.route('/api/analytics', methods=['GET'])
def api_analytics():
    """Get analytics data"""
    try:
        time_range = request.args.get('range', '24h')
        
        if sniffer:
            stats = sniffer.get_statistics()
            return jsonify({
                'total_packets': stats.get('totalPackets', 0),
                'protocols': {
                    'TCP': stats.get('tcpPackets', 0),
                    'UDP': stats.get('udpPackets', 0),
                    'ICMP': stats.get('icmpPackets', 0),
                    'Other': stats.get('otherPackets', 0)
                },
                'bandwidth': {
                    'current': stats.get('currentBandwidth', 0),
                    'peak': stats.get('peakBandwidth', 0),
                    'average': stats.get('averageBandwidth', 0)
                },
                'time_range': time_range
            })
        return jsonify({})
    except Exception as e:
        logger.error(f"Error getting analytics: {str(e)}")
        return jsonify({}), 200

@app.route('/api/analytics/protocols', methods=['GET'])
def api_protocol_distribution():
    """Get protocol distribution"""
    try:
        if sniffer:
            stats = sniffer.get_statistics()
            total = stats.get('totalPackets', 1) or 1
            return jsonify({
                'distribution': [
                    {'name': 'TCP', 'value': stats.get('tcpPackets', 0), 'percentage': round(stats.get('tcpPackets', 0) / total * 100, 2)},
                    {'name': 'UDP', 'value': stats.get('udpPackets', 0), 'percentage': round(stats.get('udpPackets', 0) / total * 100, 2)},
                    {'name': 'ICMP', 'value': stats.get('icmpPackets', 0), 'percentage': round(stats.get('icmpPackets', 0) / total * 100, 2)},
                    {'name': 'Other', 'value': stats.get('otherPackets', 0), 'percentage': round(stats.get('otherPackets', 0) / total * 100, 2)},
                ]
            })
        return jsonify({'distribution': []})
    except Exception as e:
        logger.error(f"Error getting protocol distribution: {str(e)}")
        return jsonify({'distribution': []}), 200

@app.route('/api/analytics/top-talkers', methods=['GET'])
def api_top_talkers():
    """Get top talking devices"""
    try:
        limit = request.args.get('limit', 10, type=int)
        if sniffer:
            devices = sniffer.get_devices()
            # Sort by packet count
            sorted_devices = sorted(devices, key=lambda d: d.get('packets_in', 0) + d.get('packets_out', 0), reverse=True)
            return jsonify(sorted_devices[:limit])
        return jsonify([])
    except Exception as e:
        logger.error(f"Error getting top talkers: {str(e)}")
        return jsonify([]), 200

@app.route('/api/analytics/bandwidth', methods=['GET'])
def api_bandwidth_history():
    """Get bandwidth history (placeholder - would need historical data storage)"""
    try:
        hours = request.args.get('hours', 24, type=int)
        # Return current stats as a single data point for now
        if sniffer:
            stats = sniffer.get_statistics()
            return jsonify([{
                'timestamp': datetime.datetime.now().isoformat(),
                'bandwidth': stats.get('currentBandwidth', 0)
            }])
        return jsonify([])
    except Exception as e:
        logger.error(f"Error getting bandwidth history: {str(e)}")
        return jsonify([]), 200

@app.route('/api/traffic/stats', methods=['GET'])
def api_traffic_stats():
    """Get traffic statistics"""
    try:
        if sniffer:
            stats = sniffer.get_statistics()
            return jsonify({
                'total_packets': stats.get('totalPackets', 0),
                'tcp_packets': stats.get('tcpPackets', 0),
                'udp_packets': stats.get('udpPackets', 0),
                'icmp_packets': stats.get('icmpPackets', 0),
                'current_bandwidth': stats.get('currentBandwidth', 0),
                'peak_bandwidth': stats.get('peakBandwidth', 0),
                'average_bandwidth': stats.get('averageBandwidth', 0)
            })
        return jsonify({})
    except Exception as e:
        logger.error(f"Error getting traffic stats: {str(e)}")
        return jsonify({}), 200

# ============== SOCKETIO EVENTS ==============

@socketio.on('connect')
def handle_connect(auth=None):
    """Handle client connection"""
    try:
        if ENABLE_AUTH:
            token = ''
            if isinstance(auth, dict):
                token = (auth.get('token') or '').strip()
            if not token:
                token = _extract_token_from_request()

            payload, error_code = _verify_access_token(token)
            if error_code:
                logger.warning(f"[Socket] Unauthorized connection attempt: {error_code}")
                return False

            logger.info(f"[OK] Authenticated socket connection for user: {payload.get('sub')}")

        logger.info("[OK] Client connected")
        emit('connection_status', {
            'status': 'connected',
            'auth_required': ENABLE_AUTH,
        })
        
        if alerts:
            emit('alerts_sync', alerts)
        
        if sniffer:
            emit('update_statistics', sniffer.get_statistics())
    
    except Exception as e:
        logger.error(f"Error in connect handler: {str(e)}")

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info("[Socket] Client disconnected")

@socketio.on('get_logs')
def handle_get_logs():
    """Send logs to client"""
    emit('logs_list', logs)

@socketio.on('clear_logs')
def handle_clear_logs():
    """Clear logs"""
    logs.clear()
    add_log('info', 'System', 'Logs cleared')
    emit('logs_list', logs)

@socketio.on('get_processor_stats')
def handle_processor_stats():
    """Get packet processor statistics"""
    processor = get_packet_processor()
    emit('processor_stats', processor.get_stats())

@socketio.on('start_sniffing')
def handle_start_sniffing(data=None):
    """Handle start sniffing request from WebSocket"""
    global sniffer, sniffing_state
    
    try:
        payload = data or {}
        interface = payload.get('interface') or CAPTURE_INTERFACE
        
        if sniffing_state.get('is_running'):
            emit('sniffing_status', {'status': 'already_running', 'interface': sniffing_state.get('interface')})
            return
        
        # Start sniffing in background thread
        sniffing_thread = threading.Thread(
            target=start_sniffing,
            args=(interface,),
            daemon=True,
            name="PacketSnifferThread"
        )
        sniffing_thread.start()
        
        sniffing_state['is_running'] = True
        sniffing_state['interface'] = interface
        sniffing_state['start_time'] = datetime.datetime.now().isoformat()
        
        add_log('info', 'WebSocket', f'Sniffing started on interface: {interface}')
        emit('sniffing_status', {'status': 'started', 'interface': interface})
        
    except Exception as e:
        logger.error(f"Error starting sniffing via WebSocket: {str(e)}")
        emit('sniffing_status', {'status': 'error', 'message': str(e)})

@socketio.on('stop_sniffing')
def handle_stop_sniffing():
    """Handle stop sniffing request from WebSocket"""
    global sniffer, sniffing_state
    
    try:
        if sniffer:
            sniffer.stop_sniffing()
            sniffing_state['is_running'] = False
            sniffing_state['interface'] = None
            add_log('info', 'WebSocket', 'Sniffing stopped')
            emit('sniffing_status', {'status': 'stopped'})
        else:
            emit('sniffing_status', {'status': 'not_running'})
    
    except Exception as e:
        logger.error(f"Error stopping sniffing via WebSocket: {str(e)}")
        emit('sniffing_status', {'status': 'error', 'message': str(e)})

@socketio.on('scan_devices')
def handle_scan_devices():
    """Handle device scan request from WebSocket"""
    try:
        if sniffer:
            devices = sniffer.get_devices()
            emit('devices_update', {'devices': devices, 'totalDevices': len(devices)})
            add_log('info', 'WebSocket', f'Device scan complete: {len(devices)} devices found')
        else:
            emit('devices_update', {'devices': [], 'totalDevices': 0, 'error': 'Sniffer not running'})
    except Exception as e:
        logger.error(f"Error scanning devices via WebSocket: {str(e)}")
        emit('devices_update', {'devices': [], 'error': str(e)})

# ============== SNIFFING SETUP ==============

def start_sniffing(interface: str):
    """Start packet sniffing on specified interface"""
    global sniffer, sniffing_state
    
    try:
        logger.info(f"[Capture] Starting packet capture on interface: {interface}")
        
        sniffer = PacketSniffer()
        sniffer.set_callback(packet_callback)
        
        # Register packet processor callback if async is enabled
        if ASYNC_PROCESSING:
            processor = get_packet_processor()
            processor.register_callback(packet_callback)
            processor.start()
            logger.info("[Processor] Async packet processor started")
        
        add_log('info', 'System', f"Starting packet capture on: {interface}")
        sniffer.start_sniffing(interface)

        # If capture function returns, mark sniffing as stopped.
        sniffing_state['is_running'] = False
        sniffing_state['interface'] = None
        sniffing_state['last_error'] = "Packet capture stopped"
        logger.warning("[Capture] Packet capture loop exited")
    
    except Exception as e:
        error_msg = f"Error starting sniffing: {str(e)}"
        logger.error(error_msg)
        add_log('error', 'System', error_msg)
        sniffing_state['is_running'] = False
        sniffing_state['interface'] = None
        sniffing_state['last_error'] = str(e)
        import traceback
        traceback.print_exc()

# ============== MAIN ==============

if __name__ == '__main__':
    interface = sys.argv[1] if len(sys.argv) >= 2 else CAPTURE_INTERFACE

    logger.info(f"[Server] Packet Peeper Backend Starting")
    logger.info(f"[Server] Environment: {FLASK_ENV}")
    logger.info(f"[Server] Database: {FEATURES['persistent_storage']}")
    logger.info(f"[Server] Async Processing: {ASYNC_PROCESSING}")
    logger.info(f"[Server] Capture interface: {interface}")

    if ENABLE_AUTH and AUTH_USERNAME == 'admin' and AUTH_PASSWORD == 'admin123' and 'AUTH_PASSWORD_HASH' not in os.environ:
        logger.warning('[Security] ENABLE_AUTH is on with default credentials. Set AUTH_USERNAME and AUTH_PASSWORD_HASH.')
    
    add_log('info', 'System', "Packet Peeper backend starting")
    
    # Start sniffing in background thread
    sniffing_thread = threading.Thread(
        target=start_sniffing,
        args=(interface,),
        daemon=True,
        name="PacketSnifferThread"
    )
    sniffing_thread.start()
    
    # Start device update thread
    device_thread = threading.Thread(
        target=device_update_loop,
        daemon=True,
        name="DeviceUpdateThread"
    )
    device_thread.start()
    
    # Start traffic update thread
    traffic_thread = threading.Thread(
        target=traffic_update_loop,
        daemon=True,
        name="TrafficUpdateThread"
    )
    traffic_thread.start()
    
    # Start Flask-SocketIO server
    logger.info(f"[Server] Starting Flask server on {HOST}:{PORT}")
    # Disable debug mode and reloader to prevent crashes and double-execution
    try:
        socketio.run(app, host=HOST, port=PORT, debug=False, use_reloader=False, allow_unsafe_werkzeug=True)
    except Exception as e:
        logger.error(f"[Server] Flask server crashed with error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        logger.info("[Server] Flask server shutting down")