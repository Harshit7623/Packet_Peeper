"""
GeoIP API
Endpoints for IP geolocation lookup and threat map data.
"""

from flask import Blueprint, request, jsonify, g
import extensions as ext
from extensions import cached_api

geoip_bp = Blueprint('geoip', __name__, url_prefix='/api/geoip')


@geoip_bp.route('/lookup/<path:ip>', methods=['GET'])
@cached_api(ttl_seconds=300)
def lookup_ip(ip):
    from services.geoip_service import lookup, is_available
    if not is_available():
        return jsonify({'error': 'GeoIP database not available', 'available': False}), 503
    result = lookup(ip)
    if not result:
        return jsonify({'ip': ip, 'found': False}), 404
    return jsonify(result)


@geoip_bp.route('/batch', methods=['POST'])
def batch_lookup():
    from services.geoip_service import batch_lookup, is_available
    if not is_available():
        return jsonify({'error': 'GeoIP database not available', 'available': False}), 503
    data = request.get_json(silent=True) or {}
    ips = data.get('ips', [])
    if len(ips) > 100:
        return jsonify({'error': 'Maximum 100 IPs per batch'}), 400
    results = batch_lookup(ips)
    return jsonify({'results': results, 'count': len(results)})


@geoip_bp.route('/threat-map', methods=['GET'])
@cached_api(ttl_seconds=60)
def threat_map():
    from services.geoip_service import lookup, is_available
    if not is_available():
        return jsonify({'error': 'GeoIP database not available', 'available': False}), 503

    org_id = getattr(g, 'org_id', None) if hasattr(g, 'org_id') else None
    threat_points = []
    source_ips = set()

    with ext.alerts_lock:
        for alert in ext.alerts:
            src = alert.get('source') or alert.get('source_ip')
            if src and src not in source_ips:
                source_ips.add(src)

    if hasattr(ext, 'sniffer') and ext.sniffer:
        try:
            with ext.sniffer._lock:
                if hasattr(ext.sniffer, 'active_devices'):
                    for ip, dev in ext.sniffer.active_devices.items():
                        if ip and not dev.get('isLocal'):
                            source_ips.add(ip)
                if hasattr(ext.sniffer, 'captured_packets'):
                    for pkt in ext.sniffer.captured_packets:
                        for ip_field in ('src_ip', 'dst_ip'):
                            ip = pkt.get(ip_field)
                            if ip and not ext.sniffer.is_local_ip(ip) and not ext.sniffer._is_infrastructure_ip(ip):
                                source_ips.add(ip)
        except Exception:
            pass

    if ext.db_service and ext.FEATURES.get('persistent_storage'):
        try:
            # get_alerts returns (records, total_count) tuple — unpack correctly
            if org_id is not None and hasattr(ext.db_service, 'get_alerts_for_org'):
                alert_records, _ = ext.db_service.get_alerts_for_org(org_id, limit=200)
            else:
                alert_records, _ = ext.db_service.get_alerts(limit=200)
            for a in alert_records:
                src = a.get('source_ip')
                if src:
                    source_ips.add(src)
        except Exception:
            pass

    for ip in source_ips:
        geo = lookup(ip)
        if geo and geo.get('latitude') is not None and geo.get('longitude') is not None:
            alert_count = 0
            with ext.alerts_lock:
                alert_count = sum(
                    1 for a in ext.alerts
                    if (a.get('source') or a.get('source_ip')) == ip
                )
            threat_points.append({
                'ip': ip,
                'latitude': geo['latitude'],
                'longitude': geo['longitude'],
                'city': geo.get('city'),
                'country': geo.get('country'),
                'country_code': geo.get('country_code'),
                'alert_count': alert_count,
            })

    return jsonify({'threats': threat_points, 'total': len(threat_points)})


@geoip_bp.route('/status', methods=['GET'])
def geoip_status():
    from services.geoip_service import is_available, get_cache_stats
    stats = get_cache_stats()
    return jsonify({
        'available': is_available(),
        'maxmind_available': stats.get('maxmind_available', False),
        'fallback': 'ip-api.com',
        'cache_size': stats.get('ip_api_cache_size', 0),
    })
