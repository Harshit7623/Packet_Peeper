"""
History Blueprint
Historical data analysis endpoints for time-series queries,
trend analysis, and historical summaries.
"""

import logging
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify

from config.config import FEATURES

import extensions as ext

bp = Blueprint('history', __name__, url_prefix='/api/history')
logger = logging.getLogger('packet_peeper')

_TIME_RANGE_MAP = {
    '1h':  timedelta(hours=1),
    '6h':  timedelta(hours=6),
    '24h': timedelta(hours=24),
    '7d':  timedelta(days=7),
    '30d': timedelta(days=30),
    '90d': timedelta(days=90),
}

_BUCKET_MAP = {
    '1h':   1,
    '6h':   5,
    '24h':  15,
    '7d':   60,
    '30d':  360,
    '90d':  1440,
}


def _parse_time_range():
    """Parse start/end/bucket from query params, with sensible defaults."""
    time_range = request.args.get('range', '24h')
    start_str = request.args.get('start')
    end_str = request.args.get('end')
    bucket_minutes = request.args.get('bucket', type=int)

    if start_str and end_str:
        start = ext._parse_iso_datetime(start_str)
        end = ext._parse_iso_datetime(end_str)
        if not start or not end:
            return None, None, None, 'Invalid start/end datetime format'
    else:
        delta = _TIME_RANGE_MAP.get(time_range, timedelta(hours=24))
        end = datetime.utcnow()
        start = end - delta

    if bucket_minutes is None:
        bucket_minutes = _BUCKET_MAP.get(time_range, 15)

    return start, end, bucket_minutes, None


@bp.route('/timeseries', methods=['GET'])
@ext.cached_api(ttl_seconds=60)
def api_history_timeseries():
    """GET /api/history/timeseries?range=24h&bucket=60

    Returns time-bucketed traffic features for charting.
    Supports custom date range: ?start=2025-01-01T00:00:00&end=2025-01-02T00:00:00
    """
    if not ext.db_service or not FEATURES['persistent_storage']:
        return jsonify({'error': 'Persistent storage not available'}), 503

    start, end, bucket_minutes, err = _parse_time_range()
    if err:
        return jsonify({'error': err}), 400

    try:
        data = ext.db_service.get_traffic_features_aggregated(
            start_time=start,
            end_time=end,
            bucket_minutes=bucket_minutes,
        )
        return jsonify({
            'data': data,
            'start': start.isoformat(),
            'end': end.isoformat(),
            'bucket_minutes': bucket_minutes,
            'count': len(data),
        })
    except Exception as e:
        logger.error(f"Error fetching historical timeseries: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@bp.route('/summary', methods=['GET'])
@ext.cached_api(ttl_seconds=60)
def api_history_summary():
    """GET /api/history/summary?range=7d

    Returns aggregate summary statistics for a time range.
    """
    if not ext.db_service or not FEATURES['persistent_storage']:
        return jsonify({'error': 'Persistent storage not available'}), 503

    start, end, _, err = _parse_time_range()
    if err:
        return jsonify({'error': err}), 400

    try:
        summary = ext.db_service.get_historical_summary(
            start_time=start,
            end_time=end,
        )
        return jsonify(summary)
    except Exception as e:
        logger.error(f"Error fetching historical summary: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@bp.route('/protocols', methods=['GET'])
@ext.cached_api(ttl_seconds=60)
def api_history_protocols():
    """GET /api/history/protocols?range=7d&bucket=60

    Returns protocol distribution over time for stacked area charts.
    """
    if not ext.db_service or not FEATURES['persistent_storage']:
        return jsonify({'error': 'Persistent storage not available'}), 503

    start, end, bucket_minutes, err = _parse_time_range()
    if err:
        return jsonify({'error': err}), 400

    try:
        data = ext.db_service.get_protocol_trend(
            start_time=start,
            end_time=end,
            bucket_minutes=bucket_minutes,
        )
        return jsonify({
            'data': data,
            'start': start.isoformat(),
            'end': end.isoformat(),
            'bucket_minutes': bucket_minutes,
            'count': len(data),
        })
    except Exception as e:
        logger.error(f"Error fetching protocol trend: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@bp.route('/top-talkers', methods=['GET'])
@ext.cached_api(ttl_seconds=60)
def api_history_top_talkers():
    """GET /api/history/top-talkers?range=7d&limit=10

    Returns top talkers by byte count within a time range.
    """
    if not ext.db_service or not FEATURES['persistent_storage']:
        return jsonify({'error': 'Persistent storage not available'}), 503

    start, end, _, err = _parse_time_range()
    if err:
        return jsonify({'error': err}), 400

    limit = request.args.get('limit', 10, type=int)

    try:
        data = ext.db_service.get_top_talkers_history(
            start_time=start,
            end_time=end,
            limit=limit,
        )
        return jsonify({
            'data': data,
            'start': start.isoformat(),
            'end': end.isoformat(),
            'count': len(data),
        })
    except Exception as e:
        logger.error(f"Error fetching historical top talkers: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@bp.route('/alerts', methods=['GET'])
def api_history_alerts():
    """GET /api/history/alerts?range=7d&severity=high

    Returns alerts within a time range with optional severity filter.
    """
    if not ext.db_service or not FEATURES['persistent_storage']:
        return jsonify({'error': 'Persistent storage not available'}), 503

    start, end, _, err = _parse_time_range()
    if err:
        return jsonify({'error': err}), 400

    severity = request.args.get('severity')
    limit = request.args.get('limit', 100, type=int)

    try:
        data, _ = ext.db_service.get_alerts(
            start_time=start,
            end_time=end,
            severity=severity,
            limit=limit,
        )
        return jsonify({
            'data': data,
            'start': start.isoformat(),
            'end': end.isoformat(),
            'count': len(data),
        })
    except Exception as e:
        logger.error(f"Error fetching historical alerts: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@bp.route('/bandwidth', methods=['GET'])
@ext.cached_api(ttl_seconds=60)
def api_history_bandwidth():
    """GET /api/history/bandwidth?range=7d

    Returns bandwidth time-series derived from traffic features.
    """
    if not ext.db_service or not FEATURES['persistent_storage']:
        return jsonify({'error': 'Persistent storage not available'}), 503

    start, end, bucket_minutes, err = _parse_time_range()
    if err:
        return jsonify({'error': err}), 400

    try:
        data = ext.db_service.get_traffic_features_aggregated(
            start_time=start,
            end_time=end,
            bucket_minutes=bucket_minutes,
        )
        bandwidth = [
            {
                'timestamp': row['window_start'],
                'bandwidth_bps': row['bandwidth_bps'],
                'total_packets': row['total_packets'],
                'total_bytes': row['total_bytes'],
            }
            for row in data
        ]
        return jsonify({
            'data': bandwidth,
            'start': start.isoformat(),
            'end': end.isoformat(),
            'bucket_minutes': bucket_minutes,
            'count': len(bandwidth),
        })
    except Exception as e:
        logger.error(f"Error fetching historical bandwidth: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@bp.route('/raw', methods=['GET'])
def api_history_raw():
    """GET /api/history/raw?range=1h&limit=60

    Returns raw 1-minute feature records for detailed inspection.
    """
    if not ext.db_service or not FEATURES['persistent_storage']:
        return jsonify({'error': 'Persistent storage not available'}), 503

    start, end, _, err = _parse_time_range()
    if err:
        return jsonify({'error': err}), 400

    limit = request.args.get('limit', 1440, type=int)

    try:
        data = ext.db_service.get_traffic_features(
            start_time=start,
            end_time=end,
            limit=limit,
        )
        return jsonify({
            'data': data,
            'start': start.isoformat(),
            'end': end.isoformat(),
            'count': len(data),
        })
    except Exception as e:
        logger.error(f"Error fetching raw traffic features: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500
