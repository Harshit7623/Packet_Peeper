"""
Packet Peeper - Flask Backend Application (Blueprint Refactored)

This version uses Flask blueprints for modularity.
The old monolithic app.py is preserved as app.py.old during transition.
"""

import sys
import os
import time
import threading
import logging
import logging.handlers
from pathlib import Path
from datetime import datetime

from flask import Flask, request, jsonify, g
from flask_socketio import SocketIO
from flask_cors import CORS

# ============== PATH SETUP ==============
if getattr(sys, 'frozen', False):
    base_dir = sys._MEIPASS
    if base_dir not in sys.path:
        sys.path.insert(0, base_dir)
    exe_dir = os.path.dirname(sys.executable)
    if exe_dir not in sys.path:
        sys.path.insert(0, exe_dir)

# ============== CONFIG ==============
from config.config import (
    FLASK_ENV, FLASK_DEBUG, SECRET_KEY, HOST, PORT,
    LOG_LEVEL, LOG_FILE, LOG_FORMAT, LOG_MAX_BYTES, LOG_BACKUP_COUNT,
    SOCKETIO_PING_TIMEOUT, SOCKETIO_PING_INTERVAL, SOCKETIO_TRANSPORTS,
    SOCKETIO_ASYNC_MODE,
    ENABLE_AUTH, FEATURES,
    DEVICE_UPDATE_INTERVAL, TRAFFIC_UPDATE_INTERVAL,
    DB_CLEANUP_INTERVAL_HOURS,
    AUTO_START_SNIFFING, CAPTURE_INTERFACE,
    ASYNC_PROCESSING,
)

# ============== LOGGING ==============
log_dir = Path(LOG_FILE).parent
log_dir.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger('packet_peeper')
logger.setLevel(getattr(logging, LOG_LEVEL))

file_handler = logging.handlers.RotatingFileHandler(
    LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT
)
file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
logger.addHandler(console_handler)

# ============== FLASK + CORS + SOCKETIO ==============
PROJECT_ROOT = Path(__file__).resolve().parent.parent

_FRONTEND_CANDIDATES = [
    PROJECT_ROOT / 'frontend' / 'dist',
    Path(os.getcwd()) / '..' / 'frontend',
    Path(os.getcwd()).parent / 'frontend',
    Path(__file__).resolve().parent / '..' / '..' / 'frontend',
]
FRONTEND_DIST_DIR = None
for _cand in _FRONTEND_CANDIDATES:
    _cand = _cand.resolve()
    if (_cand / 'index.html').exists():
        FRONTEND_DIST_DIR = _cand
        break
if FRONTEND_DIST_DIR is None:
    FRONTEND_DIST_DIR = PROJECT_ROOT / 'frontend' / 'dist'

if FRONTEND_DIST_DIR.exists():
    app = Flask(__name__, static_folder=str(FRONTEND_DIST_DIR), static_url_path='')
else:
    app = Flask(__name__)

app.config['SECRET_KEY'] = SECRET_KEY
app.config['ENV'] = FLASK_ENV
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv("MAX_REQUEST_BYTES", str(2 * 1024 * 1024)))

RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_MAX_REQUESTS = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "300"))

ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "*").split(",")
    if origin.strip()
]
CORS_ORIGINS = "*" if ALLOWED_ORIGINS == ["*"] else ALLOWED_ORIGINS

CORS(app,
     resources={r"/*": {"origins": CORS_ORIGINS}},
     supports_credentials=False,
     allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     expose_headers=["Content-Type", "Authorization"])

socketio = SocketIO(
    app,
    cors_allowed_origins=CORS_ORIGINS,
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

# ============== EXTENSIONS (Global State) ==============
import extensions as ext
ext.start_time = time.time()
ext.socketio = socketio

# ============== INIT SERVICES ==============
from services.database_services import get_database_service
from services.auth_service import AuthService
from services.packet_processor import init_packet_processor, get_packet_processor
from config.config import JWT_SECRET, AUTH_TOKEN_EXPIRY

try:
    ext.db_service = get_database_service()
    logger.info("[OK] Database service initialized")
except Exception as e:
    logger.warning(f"[WARN] Database initialization failed: {str(e)}")

try:
    ext.auth_service = AuthService(jwt_secret=JWT_SECRET, db_service=ext.db_service, token_expiry=AUTH_TOKEN_EXPIRY)
    logger.info("[OK] Authentication service initialized")
except Exception as e:
    ext.auth_service = None
    logger.warning(f"[WARN] Authentication service initialization failed: {str(e)}")

try:
    init_packet_processor()
    logger.info("[OK] Packet processor initialized")
except Exception as e:
    logger.error(f"[ERROR] Packet processor initialization failed: {str(e)}")

# ============== BEFORE / AFTER REQUEST HOOKS ==============
@app.before_request
def handle_preflight_and_guards():
    ext._cleanup_expired_sessions()
    g.auth_service = ext.auth_service

    if request.method == "OPTIONS":
        response = app.make_default_options_response()
        response.headers['Access-Control-Allow-Origin'] = ext._resolve_cors_origin()
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        response.headers['Access-Control-Max-Age'] = '600'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response

    if not request.path.startswith('/api/'):
        return None

    allowed, retry_after = ext._check_rate_limit('api', RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECONDS)
    if not allowed:
        return jsonify({
            'error': 'Rate limit exceeded',
            'retry_after_seconds': retry_after,
        }), 429

    if ENABLE_AUTH and request.path not in ext.PUBLIC_API_PATHS:
        if not ext.auth_service:
            return jsonify({'error': 'Authentication service unavailable'}), 500

        token = ext._extract_token_from_request()
        payload, error_code = ext.auth_service.verify_token(token)
        if error_code:
            return jsonify({'error': 'Authentication required', 'code': error_code}), 401

        g.current_user = payload.get('sub')
        g.current_user_id = payload.get('uid')
        g.current_role = payload.get('role')
        g.current_session_id = payload.get('sid')

    return None


@app.after_request
def after_request(response):
    response.headers['Access-Control-Allow-Origin'] = ext._resolve_cors_origin()
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

# ============== REGISTER BLUEPRINTS ==============
from blueprints import auth, profile, alerts, packets, devices, sniffing, analytics, system, logs, detection, history, search

blueprints = [
    auth.bp,
    profile.bp,
    alerts.bp,
    packets.bp,
    devices.bp,
    sniffing.bp,
    analytics.bp,
    system.bp,
    logs.bp,
    detection.bp,
    history.bp,
    search.bp,
]

for bp in blueprints:
    app.register_blueprint(bp)

# ============== SOCKET.IO EVENTS ==============
from blueprints.events import register_events
register_events(socketio)

# ============== BACKGROUND THREADS ==============
def device_update_loop():
    while True:
        try:
            if ext.sniffer:
                all_devices = ext._collect_device_snapshot()
                socketio.emit('devices_update', {
                    'devices': all_devices,
                    'timestamp': time.time(),
                    'totalDevices': len(all_devices),
                }, namespace='/')
                if ext.db_service and FEATURES['persistent_storage']:
                    for device in all_devices:
                        ext.db_service.update_device(device)
            time.sleep(DEVICE_UPDATE_INTERVAL)
        except Exception as e:
            logger.error(f"Error in device update loop: {str(e)}")
            time.sleep(5)


def traffic_update_loop():
    while True:
        try:
            if ext.sniffer:
                stats = ext.sniffer.get_statistics()
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
            ext._persist_traffic_stats(stats)
            ext._persist_traffic_features(stats)
            time.sleep(TRAFFIC_UPDATE_INTERVAL)
        except Exception as e:
            logger.error(f"Error in traffic update loop: {type(e).__name__}: {str(e)}", exc_info=True)
            time.sleep(5)


def database_cleanup_loop():
    interval_seconds = max(1, DB_CLEANUP_INTERVAL_HOURS) * 3600
    while True:
        try:
            if ext.db_service and FEATURES['persistent_storage']:
                retention_days = ext.app_settings.get('data_retention_days', 7)
                ext.db_service.cleanup_old_records(days=retention_days)
            time.sleep(interval_seconds)
        except Exception as e:
            logger.error(f"Error in database cleanup loop: {str(e)}")
            time.sleep(300)

# ============== SPA ROUTING ==============
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_spa(path=''):
    if path.startswith('api/'):
        return jsonify({'error': 'API endpoint not found'}), 404
    if not app.static_folder or not Path(app.static_folder).exists():
        return jsonify({'error': 'Frontend build not found. Build frontend/dist first.'}), 404
    if path and ('.' in path or path.startswith('assets/')):
        from flask import send_from_directory
        try:
            return send_from_directory(app.static_folder, path)
        except Exception:
            pass
    try:
        from flask import send_from_directory
        return send_from_directory(app.static_folder, 'index.html')
    except Exception:
        return jsonify({'error': 'Frontend not found'}), 404

# ============== MAIN ==============
if __name__ == '__main__':
    interface = sys.argv[1] if len(sys.argv) >= 2 else CAPTURE_INTERFACE

    logger.info("[Server] Packet Peeper Backend Starting")
    logger.info(f"[Server] Environment: {FLASK_ENV}")
    logger.info(f"[Server] Database: {FEATURES['persistent_storage']}")
    logger.info(f"[Server] Async Processing: {ASYNC_PROCESSING}")
    logger.info(f"[Server] Capture interface: {interface}")

    if ENABLE_AUTH and JWT_SECRET.startswith('change'):
        logger.warning('[Security] ENABLE_AUTH is on with default JWT_SECRET. Set JWT_SECRET in your environment.')

    ext.add_log('info', 'System', "Packet Peeper backend starting")

    if AUTO_START_SNIFFING:
        from blueprints.sniffing import start_sniffing
        sniffing_thread = threading.Thread(
            target=start_sniffing,
            args=(interface,),
            daemon=True,
            name="PacketSnifferThread",
        )
        sniffing_thread.start()
    else:
        logger.info("[Capture] Auto-start disabled; waiting for user to start capture.")

    device_thread = threading.Thread(
        target=device_update_loop,
        daemon=True,
        name="DeviceUpdateThread",
    )
    device_thread.start()

    traffic_thread = threading.Thread(
        target=traffic_update_loop,
        daemon=True,
        name="TrafficUpdateThread",
    )
    traffic_thread.start()

    cleanup_thread = threading.Thread(
        target=database_cleanup_loop,
        daemon=True,
        name="DatabaseCleanupThread",
    )
    cleanup_thread.start()

    logger.info(f"[Server] Starting Flask server on {HOST}:{PORT}")
    try:
        socketio.run(app, host=HOST, port=PORT, debug=False, use_reloader=False, allow_unsafe_werkzeug=True)
    except Exception as e:
        logger.error(f"[Server] Flask server crashed with error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        logger.info("[Server] Flask server shutting down")
