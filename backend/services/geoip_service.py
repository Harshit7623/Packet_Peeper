"""
GeoIP Service for Packet Peeper
Looks up IP addresses against a MaxMind GeoLite2 database (.mmdb).
Falls back to ip-api.com free HTTP API when no local database is available.
Gracefully degrades when neither source is usable.
"""

import logging
import os
import time
import threading
from typing import Dict, List, Optional

from utils.network_utils import is_reserved_ip

logger = logging.getLogger('packet_peeper')

_MAXMIND_DB_PATH = os.environ.get(
    'GEOLITE2_CITY_DB',
    os.path.join(os.path.dirname(__file__), '..', 'data', 'GeoLite2-City.mmdb'),
)

_geoip_reader = None
_geoip_lock = threading.Lock()
_geoip_available = False

# ========== ip-api.com rate limiter (45 req/min free tier) ==========
_IP_API_CACHE: Dict[str, Optional[Dict]] = {}
_IP_API_CACHE_TTL = 600  # 10 minutes
_IP_API_TIMESTAMPS: Dict[str, float] = {}
_ip_api_lock = threading.Lock()
_ip_api_last_request = 0.0
_IP_API_MIN_INTERVAL = 1.5  # ~40 req/min to stay under 45 limit


def _init_reader():
    global _geoip_reader, _geoip_available
    try:
        import maxminddb
        db_path = _MAXMIND_DB_PATH
        if not os.path.isfile(db_path):
            # Check unpacked directory fallback
            alt_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'GeoLite2-City_20260626', 'GeoLite2-City.mmdb')
            if os.path.isfile(alt_path):
                db_path = alt_path

        if os.path.isfile(db_path):
            _geoip_reader = maxminddb.open_database(db_path)
            _geoip_available = True
            logger.info(f"[GeoIP] Loaded MaxMind database: {db_path}")
        else:
            logger.info(f"[GeoIP] No GeoLite2-City.mmdb found at {db_path} — will use ip-api.com fallback")
            _geoip_available = False
    except ImportError:
        logger.info("[GeoIP] maxminddb package not installed — will use ip-api.com fallback")
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
    """Returns True if either MaxMind DB or ip-api.com fallback can be used."""
    return _geoip_available or True  # ip-api.com is always available as fallback


def _is_private_ip(ip: str) -> bool:
    """Check if IP is private/reserved (not resolvable via GeoIP).

    Delegates to the shared is_reserved_ip utility which covers
    RFC 1918, loopback, multicast, link-local, and other reserved ranges.
    """
    return is_reserved_ip(ip)


# NAT64 prefix that many ISPs use (RFC 6052)
_NAT64_PREFIXES = ['64:ff9b::', '64:ff9b:1::', '2001:db8::']


def _normalize_ip(ip: str) -> str:
    """
    Normalise an IP address for GeoIP lookup:
    - Strips NAT64-embedded IPv4 (64:ff9b::a.b.c.d) -> 'a.b.c.d'
    - Returns the input unchanged otherwise.
    """
    if not ip or ':' not in ip:
        return ip
    # Detect NAT64 64:ff9b:: prefix (most common)
    lower = ip.lower()
    for prefix in _NAT64_PREFIXES:
        if lower.startswith(prefix):
            # The last 32 bits are the embedded IPv4
            # e.g. 64:ff9b::2236:546e -> decode last two groups as IPv4
            try:
                import ipaddress
                addr = ipaddress.IPv6Address(ip)
                # Extract last 4 bytes as IPv4
                packed = addr.packed
                ipv4 = '.'.join(str(b) for b in packed[-4:])
                return ipv4
            except Exception:
                pass
    # Plain IPv4-mapped IPv6 (::ffff:a.b.c.d)
    if lower.startswith('::ffff:'):
        return ip[7:]
    return ip


def _lookup_maxmind(ip: str) -> Optional[Dict]:
    """Lookup via local MaxMind database."""
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
            'source': 'maxmind',
        }
    except Exception:
        return None


def _lookup_ip_api(ip: str) -> Optional[Dict]:
    """Lookup via ip-api.com free HTTP API (rate-limited to 45 req/min)."""
    global _ip_api_last_request

    if _is_private_ip(ip):
        return None

    # Check cache first
    now = time.time()
    with _ip_api_lock:
        if ip in _IP_API_CACHE:
            cache_time = _IP_API_TIMESTAMPS.get(ip, 0)
            if now - cache_time < _IP_API_CACHE_TTL:
                return _IP_API_CACHE[ip]
            else:
                # Expired — remove
                del _IP_API_CACHE[ip]
                _IP_API_TIMESTAMPS.pop(ip, None)

    # Rate limit
    with _ip_api_lock:
        elapsed = now - _ip_api_last_request
        if elapsed < _IP_API_MIN_INTERVAL:
            return None  # Skip this lookup to stay under rate limit

    try:
        import requests
        with _ip_api_lock:
            _ip_api_last_request = time.time()
        
        resp = requests.get(
            f'http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,timezone,isp,org',
            timeout=3
        )
        if resp.status_code != 200:
            return None

        data = resp.json()
        if data.get('status') != 'success':
            # Cache the failure to avoid retrying
            with _ip_api_lock:
                _IP_API_CACHE[ip] = None
                _IP_API_TIMESTAMPS[ip] = time.time()
            return None

        result = {
            'ip': ip,
            'city': data.get('city'),
            'country': data.get('country'),
            'country_code': data.get('countryCode'),
            'subdivision': data.get('regionName'),
            'latitude': data.get('lat'),
            'longitude': data.get('lon'),
            'timezone': data.get('timezone'),
            'isp': data.get('isp'),
            'org': data.get('org'),
            'source': 'ip-api.com',
        }

        # Cache the result
        with _ip_api_lock:
            _IP_API_CACHE[ip] = result
            _IP_API_TIMESTAMPS[ip] = time.time()
            # Prune cache if too large
            if len(_IP_API_CACHE) > 500:
                oldest_ip = min(_IP_API_TIMESTAMPS, key=_IP_API_TIMESTAMPS.get)
                del _IP_API_CACHE[oldest_ip]
                del _IP_API_TIMESTAMPS[oldest_ip]

        return result

    except ImportError:
        logger.warning("[GeoIP] requests package not installed — ip-api.com fallback unavailable")
        return None
    except Exception as e:
        logger.debug(f"[GeoIP] ip-api.com lookup failed for {ip}: {e}")
        return None


def lookup(ip: str) -> Optional[Dict]:
    """Look up IP geolocation. Normalises NAT64 first, then tries MaxMind → ip-api.com."""
    if not ip:
        return None

    # Normalise NAT64 / IPv4-mapped IPv6 to plain IPv4 for lookup
    normalised = _normalize_ip(ip)

    if _is_private_ip(normalised):
        return None

    # Try MaxMind first (fast, offline)
    result = _lookup_maxmind(normalised)
    if result:
        # Tag with original IP so frontend can match
        result['original_ip'] = ip
        return result

    # Fallback to ip-api.com (online, rate-limited)
    result = _lookup_ip_api(normalised)
    if result:
        result['original_ip'] = ip
    return result


def batch_lookup(ips: List[str]) -> Dict[str, Dict]:
    """Batch lookup for multiple IPs."""
    results = {}
    for ip in ips:
        info = lookup(ip)
        if info:
            results[ip] = info
    return results


def get_cache_stats() -> Dict:
    """Return cache statistics for diagnostics."""
    return {
        'maxmind_available': _geoip_available,
        'ip_api_cache_size': len(_IP_API_CACHE),
        'ip_api_cache_ttl': _IP_API_CACHE_TTL,
    }


_init_reader()
