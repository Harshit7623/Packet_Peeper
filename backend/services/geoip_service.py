"""
GeoIP Service for Packet Peeper
Looks up IP addresses against a MaxMind GeoLite2 database (.mmdb).
Gracefully degrades when maxminddb is not installed or no DB file is found.
"""

import logging
import os
import threading
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger('packet_peeper')

_MAXMIND_DB_PATH = os.environ.get(
    'GEOLITE2_CITY_DB',
    os.path.join(os.path.dirname(__file__), '..', 'data', 'GeoLite2-City.mmdb'),
)

_geoip_reader = None
_geoip_lock = threading.Lock()
_geoip_available = False


def _init_reader():
    global _geoip_reader, _geoip_available
    try:
        import maxminddb
        db_path = _MAXMIND_DB_PATH
        if os.path.isfile(db_path):
            _geoip_reader = maxminddb.open_database(db_path)
            _geoip_available = True
            logger.info(f"[GeoIP] Loaded MaxMind database: {db_path}")
        else:
            logger.info(f"[GeoIP] No GeoLite2-City.mmdb found at {db_path} — geo lookups disabled")
            _geoip_available = False
    except ImportError:
        logger.info("[GeoIP] maxminddb package not installed — geo lookups disabled")
        _geoip_available = False
    except Exception as e:
        logger.warning(f"[GeoIP] Failed to open MaxMind DB: {e}")
        _geoip_available = False


def reload(db_path: Optional[str] = None):
    global _MAXMIND_DB_PATH, _geoip_reader, _geoip_available
    with _geoip_lock:
        if _geoip_reader:
            try:
                _geoip_reader.close()
            except Exception:
                pass
            _geoip_reader = None
        if db_path:
            _MAXMIND_DB_PATH = db_path
        _init_reader()


def is_available() -> bool:
    return _geoip_available


def lookup(ip: str) -> Optional[Dict]:
    if not _geoip_available or not _geoip_reader:
        return None
    try:
        result = _geoip_reader.get(ip)
        if not result:
            return None
        city = result.get('city', {})
        country = result.get('country', {})
        subdiv = result.get('subdivisions', [{}])
        loc = result.get('location', {})
        return {
            'ip': ip,
            'city': city.get('names', {}).get('en'),
            'country': country.get('names', {}).get('en'),
            'country_code': country.get('iso_code'),
            'subdivision': subdiv[0].get('names', {}).get('en') if subdiv else None,
            'latitude': loc.get('latitude'),
            'longitude': loc.get('longitude'),
            'accuracy_radius': loc.get('accuracy_radius'),
            'timezone': loc.get('time_zone'),
        }
    except Exception:
        return None


def batch_lookup(ips: List[str]) -> Dict[str, Dict]:
    results = {}
    for ip in ips:
        info = lookup(ip)
        if info:
            results[ip] = info
    return results


_init_reader()
