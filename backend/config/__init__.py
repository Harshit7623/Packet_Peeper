"""
Packet Peeper Configuration Package
Exports all configuration and utility functions
"""

from config.config import (
    BASE_DIR,
    CONFIG_DIR,
    LOGS_DIR,
    DATA_DIR,
    REPORTS_DIR,
    FLASK_ENV,
    FLASK_DEBUG,
    SECRET_KEY,
    HOST,
    PORT,
    DATABASE_URL,
    DB_ENGINE,
    CAPTURE_INTERFACE,
    BPF_FILTER,
    SERVICE_MAP_PATH,
    ALERT_MAX_STORED,
    THREAT_THRESHOLDS,
    LOG_LEVEL,
    LOG_FILE,
    FEATURES,
    validate_config,
)

__all__ = [
    'BASE_DIR',
    'CONFIG_DIR',
    'LOGS_DIR',
    'DATA_DIR',
    'REPORTS_DIR',
    'FLASK_ENV',
    'FLASK_DEBUG',
    'SECRET_KEY',
    'HOST',
    'PORT',
    'DATABASE_URL',
    'DB_ENGINE',
    'CAPTURE_INTERFACE',
    'BPF_FILTER',
    'SERVICE_MAP_PATH',
    'ALERT_MAX_STORED',
    'THREAT_THRESHOLDS',
    'LOG_LEVEL',
    'LOG_FILE',
    'FEATURES',
    'validate_config',
]

# Validate on import
if not validate_config():
    import warnings
    warnings.warn("[WARN] Configuration validation found issues. Check logs.", UserWarning)