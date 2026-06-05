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
from collections import defaultdict, deque
from pathlib import Path

import sys
import os
if getattr(sys, 'frozen', False):
    # Running in a PyInstaller bundle
    base_dir = sys._MEIPASS
    # Add _internal or MEIPASS to path to ensure services/config are found
    if base_dir not in sys.path:
        sys.path.insert(0, base_dir)
    # Also add the directory containing the executable just in case
    exe_dir = os.path.dirname(sys.executable)
    if exe_dir not in sys.path:
        sys.path.insert(0, exe_dir)

from services.auth_service import AuthService, require_auth

# Import config first (before anything else)
from config.config import (
    FLASK_ENV, FLASK_DEBUG, SECRET_KEY, HOST, PORT,
    LOG_LEVEL, LOG_FILE, LOG_FORMAT, LOG_MAX_BYTES, LOG_BACKUP_COUNT,
    SOCKETIO_PING_TIMEOUT, SOCKETIO_PING_INTERVAL, SOCKETIO_TRANSPORTS,
    ALERT_MAX_STORED, FEATURES, ASYNC_PROCESSING, CAPTURE_INTERFACE,
    ENABLE_AUTH, AUTH_TOKEN_EXPIRY, JWT_SECRET,
    TRAFFIC_STATS_INTERVAL, TRAFFIC_STATS_RETENTION_DAYS,
    LOG_MAX_STORED, DEVICE_UPDATE_INTERVAL, TRAFFIC_UPDATE_INTERVAL,
    DB_CLEANUP_INTERVAL_HOURS,
    SOCKETIO_ASYNC_MODE,
    AUTO_START_SNIFFING,
    PACKET_DEDUP_WINDOW_SECONDS, PACKET_DEDUP_MAX
)

# Import DB models for clearing data
from services.database_services import AlertRecord, DeviceRecord, PacketRecord, UserSessionRecord

# Import services
from services.database_services import get_database_service
from services.packet_processor import init_packet_processor, get_packet_processor
from services.report_generator import get_report_generator
from services.ai_assistant import get_ai_assistant, init_ai_assistant
from packet_sniffer import PacketSniffer
from network_security_monitor import NetworkSecurityMonitor

# ============== FLASK SETUP ==============
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Determine frontend dist path – works in development and packaged AppImage.
# In an AppImage the layout is:
#   resources/backend/packet_peeper_backend   (CWD = resources/backend)
#   resources/frontend/index.html
# In development:
#   backend/app.py  →  PROJECT_ROOT/frontend/dist
_FRONTEND_CANDIDATES = [
    PROJECT_ROOT / 'frontend' / 'dist',          # dev layout
    Path(os.getcwd()) / '..' / 'frontend',       # AppImage: CWD=resources/backend, sibling=resources/frontend
    Path(os.getcwd()).parent / 'frontend',        # same, resolved
    Path(__file__).resolve().parent / '..' / '..' / 'frontend',  # __file__ inside resources/backend/backend/
]
FRONTEND_DIST_DIR = None
for _cand in _FRONTEND_CANDIDATES:
    _cand = _cand.resolve()
    if (_cand / 'index.html').exists():
        FRONTEND_DIST_DIR = _cand
        break
if FRONTEND_DIST_DIR is None:
    FRONTEND_DIST_DIR = PROJECT_ROOT / 'frontend' / 'dist'  # fallback


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
    async_mode=SOCKETIO_ASYNC_MODE,
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
jwt_blacklist = set()
logs = []
sniffer = None
db_service = None
start_time = time.time()  # Application start time
auth_service = None
rate_limit_state = defaultdict(list)
last_traffic_persist_ts = 0.0
alerts_lock = threading.Lock()
logs_lock = threading.Lock()
recent_packet_hashes = deque()
recent_packet_hash_set = set()

PUBLIC_API_PATHS = {
    '/api/auth/login',
    '/api/auth/register',
    '/api/auth/status',
    '/api/health',
    '/api/reports',
    '/api/system/health',
    '/api/system/info',
    '/api/traffic/flow',
}

# ============== DATABASE INITIALIZATION ==============
try:
    db_service = get_database_service()
    logger.info("[OK] Database service initialized")
except Exception as e:
    logger.warning(f"[WARN] Database initialization failed: {str(e)}")

# ============== AUTH SERVICE INITIALIZATION ==============
try:
    auth_service = AuthService(jwt_secret=JWT_SECRET, db_service=db_service, token_expiry=AUTH_TOKEN_EXPIRY)
    logger.info("[OK] Authentication service initialized")
except Exception as e:
    auth_service = None
    logger.warning(f"[WARN] Authentication service initialization failed: {str(e)}")

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

    with logs_lock:
        logs.append(log_entry)
        while len(logs) > LOG_MAX_STORED:
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
    """Trim expired sessions."""
    if auth_service:
        auth_service.cleanup_expired_sessions()


def _parse_iso_datetime(value: str | None) -> datetime.datetime | None:
    if not value:
        return None
    try:
        return datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    except Exception:
        return None


def _normalize_alert(alert: dict) -> dict:
    """Ensure alert payload contains required fields for clients and storage."""
    normalized = dict(alert or {})
    if normalized.get('type') and not normalized.get('alert_type'):
        normalized['alert_type'] = normalized.get('type')
    normalized.setdefault('severity', 'medium')
    normalized.setdefault('timestamp', datetime.datetime.now().isoformat())
    normalized.setdefault('title', normalized.get('type', 'Security Alert'))
    normalized.setdefault('description', normalized.get('title'))
    if not normalized.get('source'):
        normalized['source'] = normalized.get('source_ip', 'unknown')
    return normalized


def _persist_traffic_stats(stats: dict) -> None:
    """Persist traffic stats on a fixed interval to reduce write volume."""
    global last_traffic_persist_ts
    if not db_service or not FEATURES['persistent_storage']:
        return

    now = time.time()
    if now - last_traffic_persist_ts < TRAFFIC_STATS_INTERVAL:
        return

    last_traffic_persist_ts = now
    payload = {
        'total_packets': stats.get('totalPackets', 0),
        'tcp_packets': stats.get('tcpPackets', 0),
        'udp_packets': stats.get('udpPackets', 0),
        'icmp_packets': stats.get('icmpPackets', 0),
        'current_bandwidth': stats.get('currentBandwidth', 0),
        'peak_bandwidth': stats.get('peakBandwidth', 0),
        'average_bandwidth': stats.get('averageBandwidth', 0),
    }

    db_service.save_traffic_stats(payload)


def _extract_token_from_request() -> str:
    auth_header = request.headers.get('Authorization', '')
    if auth_header.lower().startswith('bearer '):
        return auth_header.split(' ', 1)[1].strip()

    return request.cookies.get('pp_auth_token', '').strip()


 

def broadcast_alert(alert_type: str, message: str, severity: str = 'medium',
                   source: str = 'System', additional_info: dict = None) -> bool:
    """Broadcast alert to all connected clients"""
    try:
        timestamp = datetime.datetime.now().isoformat()
        with alerts_lock:
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

        alert = _normalize_alert(alert)
            
        # Check for duplicate alerts of same type (within last 20)
        alert_type = alert.get('type')
        with alerts_lock:
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
        
        # Save to database if enabled (with lightweight dedup window)
        if db_service and FEATURES['persistent_storage']:
            should_save = True
            payload_hash = packet_info.get('payload_hash')
            if payload_hash and PACKET_DEDUP_WINDOW_SECONDS > 0:
                now = time.time()
                while recent_packet_hashes:
                    oldest_ts, oldest_hash = recent_packet_hashes[0]
                    if now - oldest_ts <= PACKET_DEDUP_WINDOW_SECONDS:
                        break
                    recent_packet_hashes.popleft()
                    recent_packet_hash_set.discard(oldest_hash)

                if payload_hash in recent_packet_hash_set:
                    should_save = False
                else:
                    recent_packet_hashes.append((now, payload_hash))
                    recent_packet_hash_set.add(payload_hash)
                    if len(recent_packet_hashes) > PACKET_DEDUP_MAX:
                        old_ts, old_hash = recent_packet_hashes.popleft()
                        recent_packet_hash_set.discard(old_hash)

            if should_save:
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
        logger.error(f"Error in packet callback: {type(e).__name__}: {str(e)}", exc_info=True)


def _collect_device_snapshot() -> list[dict]:
    """Collect active device view (with packet counts) and enrich with interface metadata.
    Active devices provide per‑IP packet counters, which are what the UI displays.
    Interface entries are added only when they represent an IP not already present.
    Gateway IPs (detected as sniffer.default_gateway) are excluded to avoid showing routers.
    """
    if not sniffer:
        return []

    # Active devices have the real packet stats (packetsIn/Out). Use them as the base.
    active_devices = list(getattr(sniffer, 'active_devices', {}).values())
    interface_devices = sniffer.get_devices() if hasattr(sniffer, 'get_devices') else []

    merged = []
    seen_ips = set()

    for device in active_devices:
        ip = device.get('ipAddress') or device.get('ip_address')
        if ip:
            seen_ips.add(ip)
        merged.append(device)

    # Add any interface device that wasn't already represented by an active device.
    for device in interface_devices:
        ip = device.get('ipAddress') or device.get('ip_address')
        if ip and ip in seen_ips:
            continue
        merged.append(device)

    # Exclude the default gateway if it was detected (gateway/router not shown as device).
    if getattr(sniffer, 'default_gateway', None):
        merged = [d for d in merged if (d.get('ipAddress') or d.get('ip_address')) != sniffer.default_gateway]

    return merged

def device_update_loop():
    """Periodically broadcast device updates"""
    while True:
        try:
            if sniffer:
                all_devices = _collect_device_snapshot()
                
                socketio.emit('devices_update', {
                    'devices': all_devices,
                    'timestamp': time.time(),
                    'totalDevices': len(all_devices),
                }, namespace='/')

                if db_service and FEATURES['persistent_storage']:
                    for device in all_devices:
                        db_service.update_device(device)
            
            time.sleep(DEVICE_UPDATE_INTERVAL)
        
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

                _persist_traffic_stats(stats)
            
            time.sleep(TRAFFIC_UPDATE_INTERVAL)
        
        except Exception as e:
            logger.error(f"Error in traffic update loop: {type(e).__name__}: {str(e)}", exc_info=True)
            time.sleep(5)

def database_cleanup_loop():
    """Periodically clean up old database records."""
    interval_seconds = max(1, DB_CLEANUP_INTERVAL_HOURS) * 3600
    while True:
        try:
            if db_service and FEATURES['persistent_storage']:
                retention_days = app_settings.get('data_retention_days', 7)
                db_service.cleanup_old_records(days=retention_days)
            time.sleep(interval_seconds)
        except Exception as e:
            logger.error(f"Error in database cleanup loop: {str(e)}")
            time.sleep(300)

# ============== FLASK ROUTES ==============

# Handle CORS preflight requests for all API endpoints
@app.before_request
def handle_preflight_and_guards():
    _cleanup_expired_sessions()
    g.auth_service = auth_service

    if request.method == "OPTIONS":
        response = app.make_default_options_response()
        response.headers['Access-Control-Allow-Origin'] = _resolve_cors_origin()
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        response.headers['Access-Control-Max-Age'] = '600'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
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
        if not auth_service:
            return jsonify({'error': 'Authentication service unavailable'}), 500

        token = _extract_token_from_request()
        payload, error_code = auth_service.verify_token(token)
        if error_code:
            return jsonify({'error': 'Authentication required', 'code': error_code}), 401

        g.current_user = payload.get('sub')
        g.current_user_id = payload.get('uid')
        g.current_role = payload.get('role')
        g.current_session_id = payload.get('sid')

    return None

@app.after_request
def after_request(response):
    """Add CORS and baseline security headers to all responses."""
    response.headers['Access-Control-Allow-Origin'] = _resolve_cors_origin()
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
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
        # Authentication is disabled; return a dummy token for frontend compatibility
        dummy_token = 'dummy-token'
        return jsonify({
            'message': 'Login successful (auth disabled)',
            'token': dummy_token,
            'expires_in': 0,
            'user': {'username': 'operator'},
            'auth_enabled': False,
        })

    allowed, retry_after = _check_rate_limit('auth-login', RATE_LIMIT_LOGIN_ATTEMPTS, RATE_LIMIT_WINDOW_SECONDS)
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

    if not auth_service:
        return jsonify({'error': 'Authentication service unavailable'}), 500

    # Get device info
    device_info = {
        'ip_address': _get_client_ip(),
        'mac_address': payload.get('mac_address', 'unknown'),
        'hostname': socket.gethostname(),
        'user_agent': request.headers.get('User-Agent', 'unknown'),
    }

    success, message, token, user_data = auth_service.login_user(identifier, password, device_info)

    if not success:
        add_log('warning', 'Auth', f'Failed login attempt for user "{identifier}" from {_get_client_ip()}')
        return jsonify({'error': message}), 401

    add_log('info', 'Auth', f'User "{identifier}" authenticated from {_get_client_ip()}')

    # Generate and return token (UserService provides signed token)
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


@app.route('/api/auth/register', methods=['POST'])
def api_auth_register():
    """Register a new user account (local authentication only)."""
    if not ENABLE_AUTH or not auth_service:
        return jsonify({'error': 'User registration is disabled'}), 400

    allowed, retry_after = _check_rate_limit('auth-register', RATE_LIMIT_LOGIN_ATTEMPTS * 2, RATE_LIMIT_WINDOW_SECONDS)
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

    # Get device info from request
    device_info = {
        'ip_address': payload.get('ip_address', _get_client_ip()),
        'mac_address': payload.get('mac_address', 'unknown'),
        'hostname': socket.gethostname(),
        'user_agent': request.headers.get('User-Agent', 'unknown'),
    }

    success, message, user_data = auth_service.register_user(username, email, password, device_info)
    
    if not success:
        logger.warning(f'Registration failed for {username}: {message}')
        return jsonify({'error': message}), 400

    logger.info(f'New user registered: {username}')
    return jsonify({
        'message': 'User registered successfully',
        'user': user_data,
    }), 201


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

    if not auth_service:
        return jsonify({'auth_enabled': True, 'authenticated': False, 'error': 'auth_unavailable'}), 500

    token = _extract_token_from_request()
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


@app.route('/api/auth/logout', methods=['POST'])
def api_auth_logout():
    """Revoke current access token and clear cookie state."""
    if not ENABLE_AUTH:
        return jsonify({'message': 'Authentication is disabled'}), 200

    token = _extract_token_from_request()
    payload, _ = auth_service.verify_token(token) if auth_service else (None, None)

    if auth_service and token:
        auth_service.logout_user(token)

    if payload:
        add_log('info', 'Auth', f'User "{payload.get("sub", "unknown")}" logged out')

    response = jsonify({'message': 'Logout successful'})
    response.delete_cookie('pp_auth_token')
    return response


# ============== USER PROFILE ENDPOINTS ==============

@app.route('/api/profile', methods=['GET'])
@require_auth
def api_get_profile():
    """Get current user profile information."""
    if not ENABLE_AUTH or not auth_service:
        # Return fallback profile when auth is disabled
        import platform
        return jsonify({
            'username': 'operator',
            'email': 'operator@local',
            'role': 'admin',
            'created_at': datetime.datetime.fromtimestamp(start_time).isoformat(),
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

    profile = auth_service.get_user_profile(username)
    
    if not profile:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify(profile)


@app.route('/api/profile', methods=['PUT'])
@require_auth
def api_update_profile():
    """Update current user profile."""
    if not ENABLE_AUTH or not auth_service:
        return jsonify({'error': 'Profile updates not available'}), 403

    username = g.current_user
    payload = request.get_json(silent=True) or {}
    
    # Only allow certain fields to be updated
    allowed_updates = {
        'device_info': payload.get('device_info'),
        'preferences': payload.get('preferences'),
        'email': payload.get('email'),
    }
    
    # Remove None values
    allowed_updates = {k: v for k, v in allowed_updates.items() if v is not None}
    
    success, message = auth_service.update_profile(username, allowed_updates)
    
    if not success:
        return jsonify({'error': message}), 400
    
    logger.info(f'Profile updated for user {username}')
    return jsonify({
        'message': 'Profile updated successfully',
        'user': auth_service.get_user_profile(username),
    })


@app.route('/api/profile/password', methods=['POST'])
@require_auth
def api_change_password():
    """Change user password."""
    if not ENABLE_AUTH or not auth_service:
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

    success, message = auth_service.change_password(username, old_password, new_password)
    
    if not success:
        logger.warning(f'Failed password change for user {username}')
        return jsonify({'error': message}), 400

    logger.info(f'Password changed for user {username}')
    return jsonify({'message': 'Password changed successfully'})


@app.route('/api/profile/device-info', methods=['GET'])
@require_auth
def api_get_device_info():
    """Get local device information."""
    try:
        import socket
        import psutil
        import uuid
        import platform
        
        # Get MAC address
        mac_address = uuid.uuid1().hex[:12]
        try:
            import subprocess
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if 'link/ether' in line:
                    mac_address = line.split('link/ether')[1].split()[0]
                    break
        except:
            pass
        
        # Get IP address
        ip_address = socket.gethostbyname(socket.gethostname())
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
            s.close()
        except:
            pass
        
        # Get system info
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


@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get alerts from database or memory"""
    try:
        if db_service and FEATURES['persistent_storage']:
            limit = request.args.get('limit', 100, type=int)
            db_alerts = db_service.get_alerts(limit=limit)
            return jsonify(db_alerts)
        else:
            with alerts_lock:
                return jsonify(list(alerts))
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
            security_alerts = [
                a for a in all_alerts
                if (a.get('type') or a.get('alert_type')) in security_alert_types
            ]
            return jsonify(security_alerts)
        else:
            with alerts_lock:
                security_alerts = [
                    a for a in alerts
                    if (a.get('type') or a.get('alert_type')) in security_alert_types
                ]
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
            start_time = _parse_iso_datetime(request.args.get('start'))
            end_time = _parse_iso_datetime(request.args.get('end'))
            protocol = request.args.get('protocol')
            src_ip = request.args.get('src_ip')
            dst_ip = request.args.get('dst_ip')

            db_packets = db_service.get_packets(
                start_time=start_time,
                end_time=end_time,
                protocol=protocol,
                src_ip=src_ip,
                dst_ip=dst_ip,
                limit=limit
            )
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
            # Return live snapshot of devices (active devices with packet counts)
            devices = _collect_device_snapshot()
            # Keep DB in sync if persistence is enabled, but never replace the response with DB data.
            if db_service and FEATURES['persistent_storage']:
                for device in devices:
                    try:
                        db_service.update_device(device)
                    except Exception as e:
                        logger.debug(f"DB update failed for device {device.get('ip_address')}: {e}")
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
        with logs_lock:
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

        packets = []
        alerts_list = []
        devices = []

        if db_service and FEATURES['persistent_storage']:
            packets = db_service.get_packets(limit=10000)
            alerts_list = db_service.get_alerts(limit=1000)
            devices = db_service.get_devices()
        elif sniffer:
            packets = list(sniffer.captured_packets[-10000:]) if sniffer.captured_packets else []
            with alerts_lock:
                alerts_list = [_normalize_alert(a) for a in alerts]
            devices = _collect_device_snapshot()

        # Always generate a report, even if empty
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
        socketio.emit('monitoring_state', {'is_running': True, 'interface': interface}, namespace='/')
        socketio.emit('sniffing_status', {'status': 'started', 'interface': interface}, namespace='/')
        
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
            socketio.emit('monitoring_state', {'is_running': False, 'interface': None}, namespace='/')
            socketio.emit('sniffing_status', {'status': 'stopped'}, namespace='/')
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
        with alerts_lock:
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
        with alerts_lock:
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

@app.route('/api/clear_all', methods=['POST'])
def api_clear_all():
    """Clear all in-memory and persisted data: alerts, devices, packets, user sessions."""
    if ENABLE_AUTH:
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token or token in jwt_blacklist:
            return jsonify({'error': 'Invalid or missing token'}), 403
    global alerts, sniffer, db_service
    try:
        # Clear in-memory alerts
        with alerts_lock:
            alerts.clear()
        # Clear sniffing data
        if sniffer:
            sniffer.captured_packets.clear()
            sniffer.devices.clear()
            sniffer.active_devices.clear()
        # Clear persistent storage tables
        if db_service and FEATURES['persistent_storage']:
            with db_service.get_session() as session:
                session.query(AlertRecord).delete()
                session.query(DeviceRecord).delete()
                session.query(PacketRecord).delete()
                session.query(UserSessionRecord).delete()
                session.commit()
        add_log('info', 'API', 'All data cleared via /api/clear_all')
        return jsonify({'message': 'All data cleared'}), 200
    except Exception as e:
        logger.error(f"Error clearing all data: {str(e)}")
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
    'alert_threshold': 5,
    'data_retention_days': 7
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
    db_status = None
    if db_service:
        try:
            db_status = db_service.get_status()
        except Exception:
            db_status = {'ready': False}

    return jsonify({
        'status': 'healthy',
        'uptime': time.time() - start_time if 'start_time' in globals() else 0,
        'version': '2.0.0',
        'sniffing': sniffing_state['is_running'],
        'database': db_status or {'ready': False},
        'auth_enabled': ENABLE_AUTH,
    })


@app.route('/api/system/health', methods=['GET'])
def api_system_health():
    """Get detailed real-time system health metrics"""
    try:
        import psutil
        import platform

        # CPU
        cpu_percent = psutil.cpu_percent(interval=0.5)
        cpu_per_core = psutil.cpu_percent(interval=0, percpu=True)
        cpu_freq = psutil.cpu_freq()
        load_avg = os.getloadavg() if hasattr(os, 'getloadavg') else [0, 0, 0]

        # Memory
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()

        # Disk
        disk = psutil.disk_usage('/')

        # Network I/O
        net_io = psutil.net_io_counters()

        # Process info
        process = psutil.Process()
        proc_mem = process.memory_info()

        # Uptime
        uptime_seconds = time.time() - start_time

        # Packet processor queue
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
                'packets_captured': len(sniffer.captured_packets) if sniffer else 0,
                'alerts_count': len(alerts),
                'devices_count': len(sniffer.active_devices) if sniffer else 0,
            },
            'uptime': uptime_seconds,
            'platform': platform.system(),
            'platform_version': platform.version(),
        })
    except Exception as e:
        logger.error(f"Error getting system health: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/traffic/flow', methods=['GET'])
def api_traffic_flow():
    """Get time-series traffic flow data for the D3 graph"""
    try:
        minutes = request.args.get('minutes', 30, type=int)
        bucket_count = request.args.get('buckets', 30, type=int)

        now = time.time()
        window = minutes * 60
        bucket_size = window / bucket_count

        # Initialize buckets
        buckets = []
        for i in range(bucket_count):
            bucket_start = now - window + (i * bucket_size)
            buckets.append({
                'timestamp': datetime.datetime.fromtimestamp(bucket_start).isoformat(),
                'time_label': datetime.datetime.fromtimestamp(bucket_start).strftime('%H:%M'),
                'tcp': 0,
                'udp': 0,
                'icmp': 0,
                'other': 0,
                'total': 0,
                'bytes': 0,
            })

        # Fill buckets from captured packets
        if sniffer and sniffer.captured_packets:
            for pkt in sniffer.captured_packets:
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

@app.route('/api/traffic/top-talkers', methods=['GET'])
def api_traffic_top_talkers():
    """Get top talkers (IPs with most traffic)"""
    try:
        limit = request.args.get('limit', 10, type=int)
        
        # Calculate from devices or sniffer
        talkers = []
        if sniffer:
            # We can use sniffer.devices which already has bytes_transferred
            sorted_devices = sorted(sniffer.devices.items(), key=lambda x: x[1].get('bytes_transferred', 0), reverse=True)[:limit]
            for ip, info in sorted_devices:
                talkers.append({
                    'ip': ip,
                    'packets': info.get('packet_count', 0),
                    'bytes': info.get('bytes_transferred', 0),
                    'mac': info.get('mac', 'Unknown'),
                    'vendor': info.get('vendor', 'Unknown')
                })
                
        return jsonify(talkers)
    except Exception as e:
        logger.error(f"Error fetching top talkers: {str(e)}")
        return jsonify({'error': str(e)}), 500

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

        if db_service and FEATURES['persistent_storage']:
            latest = db_service.get_traffic_stats(limit=1)
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

        if db_service and FEATURES['persistent_storage']:
            latest = db_service.get_traffic_stats(limit=1)
            if latest:
                row = latest[0]
                total = row.get('total_packets', 1) or 1
                return jsonify({
                    'distribution': [
                        {'name': 'TCP', 'value': row.get('tcp_packets', 0), 'percentage': round(row.get('tcp_packets', 0) / total * 100, 2)},
                        {'name': 'UDP', 'value': row.get('udp_packets', 0), 'percentage': round(row.get('udp_packets', 0) / total * 100, 2)},
                        {'name': 'ICMP', 'value': row.get('icmp_packets', 0), 'percentage': round(row.get('icmp_packets', 0) / total * 100, 2)},
                        {'name': 'Other', 'value': 0, 'percentage': 0},
                    ]
                })

        return jsonify({'distribution': []})
    except Exception as e:
        logger.error(f"Error getting protocol distribution: {str(e)}")
        return jsonify({'distribution': []}), 200

@app.route('/api/analytics/top-talkers', methods=['GET'])
def api_analytics_top_talkers():
    """Get top talking devices"""
    try:
        limit = request.args.get('limit', 10, type=int)
        devices = []
        if db_service and FEATURES['persistent_storage']:
            devices = db_service.get_devices(limit=1000)
        elif sniffer:
            devices = _collect_device_snapshot()

        if devices:
            def _packets_total(device):
                return (
                    (device.get('packets_in') or device.get('packetsIn') or 0) +
                    (device.get('packets_out') or device.get('packetsOut') or 0) +
                    (device.get('packetsCaptured') or 0)
                )

            sorted_devices = sorted(devices, key=_packets_total, reverse=True)
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
        if db_service and FEATURES['persistent_storage']:
            return jsonify(db_service.get_bandwidth_history(hours=hours))

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
        if db_service and FEATURES['persistent_storage']:
            latest = db_service.get_traffic_stats(limit=1)
            if latest:
                return jsonify(latest[0])

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

            payload, error_code = auth_service.verify_token(token)
            if error_code:
                logger.warning(f"[Socket] Unauthorized connection attempt: {error_code}")
                return False

            logger.info(f"[OK] Authenticated socket connection for user: {payload.get('sub')}")

        logger.info("[OK] Client connected")
        emit('connection_status', {
            'status': 'connected',
            'auth_required': ENABLE_AUTH,
        })
        
        with alerts_lock:
            if alerts:
                emit('alerts_sync', list(alerts))
        
        if sniffer:
            emit('update_statistics', sniffer.get_statistics())
    
    except Exception as e:
        logger.error(f"Error in connect handler: {str(e)}")

@socketio.on('disconnect')
def handle_disconnect(data=None):
    """Handle client disconnection"""
    logger.info("[Socket] Client disconnected")

@socketio.on('get_logs')
def handle_get_logs(data=None):
    """Send logs to client"""
    with logs_lock:
        emit('logs_list', list(logs))

@socketio.on('clear_logs')
def handle_clear_logs(data=None):
    """Clear logs"""
    with logs_lock:
        logs.clear()
    add_log('info', 'System', 'Logs cleared')
    with logs_lock:
        emit('logs_list', list(logs))

@socketio.on('get_processor_stats')
def handle_processor_stats(data=None):
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
def handle_stop_sniffing(data=None):
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
def handle_scan_devices(data=None):
    """Handle device scan request from WebSocket"""
    try:
        if sniffer:
            # Use the same snapshot logic as the periodic update loop to include packet stats and filter gateways.
            devices = _collect_device_snapshot()
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
        
        # Register packet processor callback if async is enabled
        if ASYNC_PROCESSING:
            processor = get_packet_processor()
            processor.register_callback(packet_callback)
            processor.start()
            sniffer.set_callback(processor.put_packet)
            logger.info("[Processor] Async packet processor started")
        else:
            sniffer.set_callback(packet_callback)
        
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

    if ENABLE_AUTH and JWT_SECRET.startswith('change'):
        logger.warning('[Security] ENABLE_AUTH is on with default JWT_SECRET. Set JWT_SECRET in your environment.')
    
    add_log('info', 'System', "Packet Peeper backend starting")
    
    # Start sniffing in background thread
    if AUTO_START_SNIFFING:
        sniffing_thread = threading.Thread(
            target=start_sniffing,
            args=(interface,),
            daemon=True,
            name="PacketSnifferThread"
        )
        sniffing_thread.start()
    else:
        logger.info("[Capture] Auto-start disabled; waiting for user to start capture.")
    
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

    cleanup_thread = threading.Thread(
        target=database_cleanup_loop,
        daemon=True,
        name="DatabaseCleanupThread"
    )
    cleanup_thread.start()
    
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