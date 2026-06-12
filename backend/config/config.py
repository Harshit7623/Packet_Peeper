"""
Packet Peeper Configuration Module
Centralized settings for all subsystems
"""

import os
import sys
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables from .env file
load_dotenv()

# Desktop distribution hint (set by Electron launcher)
PACKET_PEEPER_DESKTOP = os.getenv("PACKET_PEEPER_DESKTOP", "False").lower() == "true"

# ============== PROJECT PATHS ==============
BASE_DIR = Path(__file__).parent.parent

if PACKET_PEEPER_DESKTOP:
    desktop_data_root = os.getenv("PACKET_PEEPER_DATA_DIR")
    if not desktop_data_root:
        if sys.platform == "win32":
            desktop_data_root = str(Path(os.getenv("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "PacketPeeper")
        elif sys.platform == "darwin":
            desktop_data_root = str(Path.home() / "Library" / "Application Support" / "PacketPeeper")
        else:
            desktop_data_root = str(Path(os.getenv("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "packet-peeper")
    DATA_ROOT = Path(desktop_data_root)
else:
    DATA_ROOT = BASE_DIR

CONFIG_DIR = BASE_DIR / "config"
LOGS_DIR = DATA_ROOT / "logs"
DATA_DIR = DATA_ROOT / "data"
REPORTS_DIR = DATA_DIR / "reports"

# Create directories if they don't exist
for dir_path in [LOGS_DIR, DATA_DIR, REPORTS_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)

# ============== FLASK & SOCKETIO ==============
FLASK_ENV = os.getenv("FLASK_ENV", "development")
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "False").lower() == "true"
SECRET_KEY = os.getenv("SECRET_KEY", "dev-key-change-in-production")
HOST = os.getenv("FLASK_HOST", "0.0.0.0")
PORT = int(os.getenv("FLASK_PORT", 5000))

# ============== DATABASE ==============
# PostgreSQL connection (optional; fall back to in-memory if unavailable)
_db_engine_env = os.getenv("DB_ENGINE")
if _db_engine_env is None and PACKET_PEEPER_DESKTOP:
    DB_ENGINE = "sqlite"
else:
    DB_ENGINE = _db_engine_env or "postgresql"  # "postgresql" or "sqlite"
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", 5432))
DB_USER = os.getenv("DB_USER", "packet_peeper_user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "secure_password_change_me")
DB_NAME = os.getenv("DB_NAME", "packet_peeper_db")
DB_DRIVER = os.getenv("DB_DRIVER", "auto")  # auto, psycopg2, psycopg
DB_CLEANUP_INTERVAL_HOURS = int(os.getenv("DB_CLEANUP_INTERVAL_HOURS", 6))

# SQLite fallback
SQLITE_PATH = DATA_DIR / "packet_peeper.db"

# Database URL builder
if DB_ENGINE == "postgresql":
    if DB_DRIVER == "auto":
        DB_DRIVER = "psycopg" if sys.version_info >= (3, 14) else "psycopg2"

    if DB_DRIVER in {"psycopg2", "psycopg"}:
        DATABASE_URL = f"postgresql+{DB_DRIVER}://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    else:
        DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
else:
    DATABASE_URL = f"sqlite:///{SQLITE_PATH}"

# ============== PACKET CAPTURE ==============
CAPTURE_INTERFACE = os.getenv("CAPTURE_INTERFACE", "auto")  # Default; overridden by CLI arg
CAPTURE_MODE = os.getenv("CAPTURE_MODE", "full").lower()  # full, lite
AUTO_START_SNIFFING = os.getenv("AUTO_START_SNIFFING", "True").lower() == "true"
ENABLE_VENDOR_LOOKUP = os.getenv("ENABLE_VENDOR_LOOKUP", "True").lower() == "true"
PACKET_BUFFER_SIZE = int(os.getenv("PACKET_BUFFER_SIZE", 10000))
MAX_PACKET_HISTORY = int(os.getenv("MAX_PACKET_HISTORY", 100000))
MAX_CATEGORY_HISTORY = int(os.getenv("MAX_CATEGORY_HISTORY", 500))
MAX_SECURITY_ALERTS = int(os.getenv("MAX_SECURITY_ALERTS", 200))
PACKET_TIMEOUT = int(os.getenv("PACKET_TIMEOUT", 300))  # seconds
PACKET_HASH_MAX_BYTES = int(os.getenv("PACKET_HASH_MAX_BYTES", 2048))
PACKET_DEDUP_WINDOW_SECONDS = int(os.getenv("PACKET_DEDUP_WINDOW_SECONDS", 5))
PACKET_DEDUP_MAX = int(os.getenv("PACKET_DEDUP_MAX", 5000))

# BPF Filter (Berkeley Packet Filter)
BPF_FILTER = os.getenv("BPF_FILTER", 
    "(tcp or udp) and not arp and not (udp and (port 67 or 68 or 5353 or 1900 or 123))"
)

# ============== SERVICE CLASSIFICATION ==============
SERVICE_MAP_PATH = CONFIG_DIR / "service_map.json"
DNS_TTL_DEFAULT = int(os.getenv("DNS_TTL_DEFAULT", 300))
SERVICE_CACHE_MAX = int(os.getenv("SERVICE_CACHE_MAX", 5000))

# ============== SECURITY & ALERTS ==============
ALERT_MAX_STORED = int(os.getenv("ALERT_MAX_STORED", 20))  # Reduced from 100 to 20
ALERT_COOLDOWN_SECONDS = int(os.getenv("ALERT_COOLDOWN_SECONDS", 60))  # Increased from 10 to 60

# ============== DETECTION TUNING ==============
DETECTION_PROFILE = os.getenv("DETECTION_PROFILE", "balanced")  # strict, balanced, sensitive, test
DETECTION_DEBUG = os.getenv("DETECTION_DEBUG", "False").lower() == "true"

# ============== DETECTION RUNTIME SETTINGS ==============
# Warm‑up period before any detection runs (seconds). Allows the system to settle after start.
DETECTION_WARMUP_SECONDS = int(os.getenv("DETECTION_WARMUP_SECONDS", "120"))
# Prefix‑based overrides for any NetworkSecurityMonitor threshold, e.g. NSM_SYN_FLOOD_RATE=30
NSM_OVERRIDES = {k[4:]: int(v) for k, v in os.environ.items() if k.startswith("NSM_")}
CAPTURE_DEBUG = os.getenv("CAPTURE_DEBUG", "False").lower() == "true"
AI_DEBUG = os.getenv("AI_DEBUG", "False").lower() == "true"

# Threat detection thresholds
THREAT_THRESHOLDS = {
    "port_scan": {
        "unique_ports": int(os.getenv("THREAT_PORT_SCAN_PORTS", 5)),
        "time_window": int(os.getenv("THREAT_PORT_SCAN_WINDOW", 60)),  # seconds
    },
    "ddos": {
        "packets_per_sec": int(os.getenv("THREAT_DDOS_PPS", 100)),
        "time_window": 10,  # seconds
    },
    "brute_force": {
        "attempts_per_minute": int(os.getenv("THREAT_BF_ATTEMPTS", 20)),
        "ports": [22, 3389, 23],  # SSH, RDP, Telnet
    },
    "dns_tunneling": {
        "query_size_threshold": int(os.getenv("THREAT_DNS_SIZE", 255)),
        "queries_per_min": int(os.getenv("THREAT_DNS_QPS", 50)),
    },
}

# ============== SECURITY & TLS ==============
USE_HTTPS = os.getenv("USE_HTTPS", "False").lower() == "true"
TLS_CERT_PATH = os.getenv("TLS_CERT_PATH", None)
TLS_KEY_PATH = os.getenv("TLS_KEY_PATH", None)

# ============== AUTHENTICATION ==============
# Authentication is forcibly disabled for this deployment
ENABLE_AUTH = os.getenv("ENABLE_AUTH", "True").lower() == "true"
AUTH_TOKEN_EXPIRY = int(os.getenv("AUTH_TOKEN_EXPIRY", 1800))  # seconds
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-in-production")

# ============== AI ASSISTANT ==============
AI_PROVIDER = os.getenv("AI_PROVIDER", "auto")  # "openai", "anthropic", "ollama", "auto", "fallback"
AI_API_KEY = os.getenv("AI_API_KEY") or os.getenv("OPENAI_API_KEY")
AI_MODEL = os.getenv("AI_MODEL", "gpt-4o-mini")  # Model to use for OpenAI/Anthropic
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")
AI_CACHE_TTL = int(os.getenv("AI_CACHE_TTL", 3600))  # Cache AI responses for 1 hour
AI_CACHE_MAX = int(os.getenv("AI_CACHE_MAX", 500))

# ============== LOGGING ==============
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_FILE = LOGS_DIR / "packet_peeper.log"
LOG_MAX_BYTES = int(os.getenv("LOG_MAX_BYTES", 10485760))  # 10MB
LOG_BACKUP_COUNT = int(os.getenv("LOG_BACKUP_COUNT", 5))
LOG_MAX_STORED = int(os.getenv("LOG_MAX_STORED", 1000))

# ============== PERFORMANCE ==============
ASYNC_PROCESSING = os.getenv("ASYNC_PROCESSING", "True").lower() == "true"
WORKER_THREADS = int(os.getenv("WORKER_THREADS", 4))
PACKET_QUEUE_SIZE = int(os.getenv("PACKET_QUEUE_SIZE", 1000))
TRAFFIC_STATS_INTERVAL = int(os.getenv("TRAFFIC_STATS_INTERVAL", 10))
TRAFFIC_STATS_RETENTION_DAYS = int(os.getenv("TRAFFIC_STATS_RETENTION_DAYS", 30))
TRAFFIC_FEATURE_INTERVAL = int(os.getenv("TRAFFIC_FEATURE_INTERVAL", 60))

# ============== ML ANOMALY DETECTION ==============
ANOMALY_SCORE_THRESHOLD = float(os.getenv("ANOMALY_SCORE_THRESHOLD", -0.3))
ANOMALY_TRAINING_WINDOW_HOURS = int(os.getenv("ANOMALY_TRAINING_WINDOW_HOURS", 168))
ANOMALY_CHECK_INTERVAL = int(os.getenv("ANOMALY_CHECK_INTERVAL", 300))
ANOMALY_MIN_TRAINING_SAMPLES = int(os.getenv("ANOMALY_MIN_TRAINING_SAMPLES", 100))
ML_MODEL_DIR = DATA_DIR / "models"
ML_MODEL_DIR.mkdir(parents=True, exist_ok=True)

# ============== WEBSOCKET ==============
SOCKETIO_ASYNC_MODE = os.getenv("SOCKETIO_ASYNC_MODE", "threading")
SOCKETIO_PING_TIMEOUT = int(os.getenv("SOCKETIO_PING_TIMEOUT", 60))
SOCKETIO_PING_INTERVAL = int(os.getenv("SOCKETIO_PING_INTERVAL", 25))
SOCKETIO_TRANSPORTS = ["websocket", "polling"]
DEVICE_UPDATE_INTERVAL = float(os.getenv("DEVICE_UPDATE_INTERVAL", 2.0))
TRAFFIC_UPDATE_INTERVAL = float(os.getenv("TRAFFIC_UPDATE_INTERVAL", 1.0))

# ============== REPORTING ==============
REPORT_FORMATS = ["pdf", "csv", "json"]
REPORT_RETENTION_DAYS = int(os.getenv("REPORT_RETENTION_DAYS", 30))
PDF_REPORT_LOGO_PATH = os.getenv("PDF_REPORT_LOGO_PATH", None)
SCHEDULED_REPORT_INTERVAL = int(os.getenv("SCHEDULED_REPORT_INTERVAL", 3600))

# ============== MOBILE (Android) ==============
MOBILE_API_ENABLED = os.getenv("MOBILE_API_ENABLED", "True").lower() == "true"
MOBILE_API_KEY = os.getenv("MOBILE_API_KEY", "change-me-in-production")
VPN_SERVICE_PORT = int(os.getenv("VPN_SERVICE_PORT", 5001))

# ============== FEATURE FLAGS ==============
FEATURES = {
    "persistent_storage": os.getenv("FEATURE_PERSISTENT_STORAGE", "True").lower() == "true",
    "threat_detection": os.getenv("FEATURE_THREAT_DETECTION", "True").lower() == "true",
    "pdf_reports": os.getenv("FEATURE_PDF_REPORTS", "True").lower() == "true",
    "mobile_support": os.getenv("FEATURE_MOBILE_SUPPORT", "False").lower() == "true",
    "electron_desktop": os.getenv("FEATURE_ELECTRON_DESKTOP", "False").lower() == "true",
    "ai_assistant": os.getenv("FEATURE_AI_ASSISTANT", "True").lower() == "true",
    "ml_anomaly_detection": os.getenv("FEATURE_ML_ANOMALY_DETECTION", "True").lower() == "true",
}

# ============== VALIDATION ==============
if CAPTURE_MODE not in {"full", "lite"}:
    CAPTURE_MODE = "full"

if SOCKETIO_ASYNC_MODE not in {"threading", "eventlet", "gevent"}:
    SOCKETIO_ASYNC_MODE = "threading"

def validate_config():
    """Validate critical configuration values."""
    errors = []
    
    if not TLS_CERT_PATH and USE_HTTPS:
        errors.append("USE_HTTPS=True but TLS_CERT_PATH not set")
    if not TLS_KEY_PATH and USE_HTTPS:
        errors.append("USE_HTTPS=True but TLS_KEY_PATH not set")
    if ENABLE_AUTH and not JWT_SECRET.startswith("change"):
        pass  # Allow if changed
    else:
        if ENABLE_AUTH:
            errors.append("ENABLE_AUTH=True but JWT_SECRET is default")
    
    if errors:
        print("\n[WARN] Configuration Warnings:")
        for error in errors:
            print(f"  - {error}")
    
    return len(errors) == 0

if __name__ == "__main__":
    # When run directly, print configuration for debugging
    print("[Config] Packet Peeper Configuration")
    print(f"Environment: {FLASK_ENV}")
    print(f"Database: {DB_ENGINE} @ {DB_HOST}:{DB_PORT}")
    print(f"Capture Interface: {CAPTURE_INTERFACE}")
    print(f"Features: {FEATURES}")
    validate_config()