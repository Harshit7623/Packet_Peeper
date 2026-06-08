"""
extensions.py - Centralized global state for Packet Peeper.

All globals that were previously module-level in app.py are moved here
to avoid circular imports between app.py and blueprints.
"""

import threading
import datetime
import time
import logging
from collections import defaultdict, deque

from flask import request

from config.config import (
    ALERT_MAX_STORED, FEATURES, TRAFFIC_STATS_INTERVAL,
    LOG_MAX_STORED, PACKET_DEDUP_WINDOW_SECONDS, PACKET_DEDUP_MAX,
    TRAFFIC_FEATURE_INTERVAL,
)

logger = logging.getLogger('packet_peeper')

# Global state objects (initialized in app.py)
sniffer = None
db_service = None
auth_service = None
alerts = []
jwt_blacklist = set()
logs = []
rate_limit_state = defaultdict(list)
last_traffic_persist_ts = 0.0
alerts_lock = threading.Lock()
logs_lock = threading.Lock()
feature_lock = threading.Lock()
recent_packet_hashes = deque()
recent_packet_hash_set = set()
start_time = None

_traffic_feature_window = {
    'window_start': None,
    'total_packets': 0,
    'total_bytes': 0,
    'tcp_packets': 0,
    'udp_packets': 0,
    'icmp_packets': 0,
    'other_packets': 0,
    'syn_count': 0,
    'dns_queries': 0,
    'arp_packets': 0,
    'src_ips': set(),
    'dst_ips': set(),
    'dst_ports': set(),
}
last_feature_persist_ts = 0.0

sniffing_state = {
    'is_running': False,
    'interface': None,
    'start_time': None,
    'thread': None,
    'last_error': None,
}

app_settings = {
    'auto_blocking': True,
    'real_time_alerts': True,
    'desktop_notifications': True,
    'sound_alerts': False,
    'capture_filter': '',
    'max_packets': 10000,
    'alert_threshold': 5,
    'data_retention_days': 7,
}

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

# Will be set by app.py after SocketIO is created
socketio = None


def add_log(level: str, source: str, message: str):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {
        'timestamp': timestamp,
        'level': level,
        'source': source,
        'message': message,
    }

    with logs_lock:
        logs.append(log_entry)
        while len(logs) > LOG_MAX_STORED:
            logs.pop(0)

    log_method = getattr(logger, level.lower(), logger.info)
    log_method(f"[{source}] {message}")

    if socketio:
        socketio.emit('new_log', log_entry, namespace='/')


def _get_cors_origins():
    import os
    allowed = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",") if o.strip()]
    return "*" if allowed == ["*"] else allowed


def _resolve_cors_origin() -> str:
    cors_origins = _get_cors_origins()
    if cors_origins == '*':
        return '*'
    request_origin = request.headers.get('Origin', '')
    if request_origin and request_origin in cors_origins:
        return request_origin
    if cors_origins:
        return cors_origins[0]
    return '*'


def _get_client_ip() -> str:
    forwarded_for = request.headers.get('X-Forwarded-For', '')
    if forwarded_for:
        first_ip = forwarded_for.split(',')[0].strip()
        if first_ip:
            return first_ip
    return request.remote_addr or 'unknown'


def _check_rate_limit(scope: str, max_requests: int, window_seconds: int):
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


def _accumulate_packet_feature(packet_info: dict) -> None:
    """Accumulate packet data into the current 1-minute feature window."""
    if not FEATURES['persistent_storage']:
        return
    with feature_lock:
        now = datetime.datetime.utcnow()
        if _traffic_feature_window['window_start'] is None:
            minute_start = now.replace(second=0, microsecond=0)
            _traffic_feature_window['window_start'] = minute_start

        proto = (packet_info.get('protocol') or '').upper()
        pkt_len = packet_info.get('length', 0)
        _traffic_feature_window['total_packets'] += 1
        _traffic_feature_window['total_bytes'] += pkt_len

        if proto == 'TCP':
            _traffic_feature_window['tcp_packets'] += 1
            flags = packet_info.get('tcp_flags', 0)
            if flags and (flags & 0x02):
                _traffic_feature_window['syn_count'] += 1
        elif proto == 'UDP':
            _traffic_feature_window['udp_packets'] += 1
            dst_port = packet_info.get('dst_port')
            if dst_port == 53:
                _traffic_feature_window['dns_queries'] += 1
        elif proto == 'ICMP':
            _traffic_feature_window['icmp_packets'] += 1
        elif proto == 'ARP':
            _traffic_feature_window['arp_packets'] += 1
        else:
            _traffic_feature_window['other_packets'] += 1

        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        dst_port = packet_info.get('dst_port')
        if src_ip:
            _traffic_feature_window['src_ips'].add(src_ip)
        if dst_ip:
            _traffic_feature_window['dst_ips'].add(dst_ip)
        if dst_port:
            _traffic_feature_window['dst_ports'].add(dst_port)


def _persist_traffic_features(stats: dict) -> None:
    """Flush the current 1-minute feature window to DB if it has expired.

    Called from the traffic_update_loop in app.py.
    """
    global last_feature_persist_ts, _traffic_feature_window
    if not db_service or not FEATURES['persistent_storage']:
        return
    now = time.time()
    if now - last_feature_persist_ts < TRAFFIC_FEATURE_INTERVAL:
        return
    last_feature_persist_ts = now

    with feature_lock:
        window = _traffic_feature_window
        if window['window_start'] is None or window['total_packets'] == 0:
            return

        total_pkts = window['total_packets']
        total_bytes = window['total_bytes']
        syn_count = window['syn_count']
        tcp_count = window['tcp_packets']
        syn_ack_ratio = (syn_count / max(tcp_count, 1)) if tcp_count > 0 else 0.0

        feature = {
            'window_start': window['window_start'],
            'total_packets': total_pkts,
            'total_bytes': total_bytes,
            'tcp_packets': window['tcp_packets'],
            'udp_packets': window['udp_packets'],
            'icmp_packets': window['icmp_packets'],
            'other_packets': window['other_packets'],
            'avg_packet_size': round(total_bytes / max(total_pkts, 1), 2),
            'unique_src_ips': len(window['src_ips']),
            'unique_dst_ips': len(window['dst_ips']),
            'unique_dst_ports': len(window['dst_ports']),
            'syn_count': syn_count,
            'syn_ack_ratio': round(syn_ack_ratio, 4),
            'dns_queries': window['dns_queries'],
            'arp_packets': window['arp_packets'],
            'bandwidth_bps': stats.get('currentBandwidth', 0),
        }

        db_service.save_traffic_feature(feature)

        minute_start = datetime.datetime.utcnow().replace(second=0, microsecond=0)
        _traffic_feature_window = {
            'window_start': minute_start,
            'total_packets': 0,
            'total_bytes': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'other_packets': 0,
            'syn_count': 0,
            'dns_queries': 0,
            'arp_packets': 0,
            'src_ips': set(),
            'dst_ips': set(),
            'dst_ports': set(),
        }


def _extract_token_from_request() -> str:
    auth_header = request.headers.get('Authorization', '')
    if auth_header.lower().startswith('bearer '):
        return auth_header.split(' ', 1)[1].strip()
    return request.cookies.get('pp_auth_token', '').strip()


def broadcast_alert(alert_type: str, message: str, severity: str = 'medium',
                     source: str = 'System', additional_info: dict = None) -> bool:
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
            if db_service and FEATURES['persistent_storage']:
                db_service.save_alert(alert)
            if socketio:
                socketio.emit('new_alert', alert, namespace='/')
            logger.info(f"[ALERT] {severity.upper()} - {message}")
        return True
    except Exception as e:
        logger.error(f"Error broadcasting alert: {str(e)}")
        return False


def security_alert_callback(alert: dict):
    global alerts
    try:
        if alert is None:
            return
        alert = _normalize_alert(alert)
        alert_type = alert.get('type')
        with alerts_lock:
            existing_count = sum(1 for a in alerts[:20] if a.get('type') == alert_type)
            if existing_count >= 3:
                logger.debug(f"Skipping duplicate alert type: {alert_type} (already {existing_count})")
                return
            alerts.insert(0, alert)
            if len(alerts) > ALERT_MAX_STORED:
                alerts.pop()
            if db_service and FEATURES['persistent_storage']:
                try:
                    db_service.save_alert(alert)
                except Exception as e:
                    logger.error(f"Error saving alert to database: {e}")
            if socketio:
                socketio.emit('new_alert', alert, namespace='/')
                socketio.emit('security_alert', alert, namespace='/')
        logger.warning(f"[ALERT] [{alert.get('severity', 'medium').upper()}] {alert.get('title')}: {alert.get('description')}")
    except Exception as e:
        logger.error(f"Error in security alert callback: {e}")


def packet_callback(packet_info: dict):
    try:
        if packet_info.get('alert_type') == 'security':
            security_alert_callback(packet_info)
            return
        if socketio:
            socketio.emit('new_packet', packet_info, namespace='/')
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
            _accumulate_packet_feature(packet_info)
        if sniffer:
            stats = sniffer.get_statistics()
            if socketio:
                socketio.emit('update_statistics', stats, namespace='/')
        if logger.level == logging.DEBUG:
            add_log('debug', 'PacketSniffer',
                    f"Captured {packet_info.get('protocol')} packet: "
                    f"{packet_info.get('src_ip')} -> {packet_info.get('dst_ip')}")
    except Exception as e:
        logger.error(f"Error in packet callback: {type(e).__name__}: {str(e)}", exc_info=True)


def _collect_device_snapshot() -> list[dict]:
    if not sniffer:
        return []
    active_devices = list(getattr(sniffer, 'active_devices', {}).values())
    interface_devices = sniffer.get_devices() if hasattr(sniffer, 'get_devices') else []
    merged = []
    seen_ips = set()
    for device in active_devices:
        ip = device.get('ipAddress') or device.get('ip_address')
        if ip:
            seen_ips.add(ip)
            merged.append(device)
    for device in interface_devices:
        ip = device.get('ipAddress') or device.get('ip_address')
        if ip and ip in seen_ips:
            continue
        merged.append(device)
    if getattr(sniffer, 'default_gateway', None):
        merged = [d for d in merged if (d.get('ipAddress') or d.get('ip_address')) != sniffer.default_gateway]
    return merged
