"""
GeoIP Service Tests
Tests lookup, batch lookup, graceful degradation when no DB available.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unittest.mock import patch, MagicMock


def test_lookup_returns_none_for_private_ip_when_unavailable():
    from services.geoip_service import lookup
    result = lookup('192.168.1.1')
    assert result is None


def test_is_available_always_true_with_fallback():
    from services.geoip_service import is_available
    assert is_available() is True


def test_batch_lookup_private_ips():
    from services.geoip_service import batch_lookup
    result = batch_lookup(['192.168.1.1', '10.0.0.1'])
    assert result == {}


def test_lookup_with_mock_reader():
    from services import geoip_service
    original_reader = geoip_service._geoip_reader
    original_available = geoip_service._geoip_available

    mock_reader = MagicMock()
    mock_reader.get.return_value = {
        'city': {'names': {'en': 'Mountain View'}},
        'country': {'names': {'en': 'United States'}, 'iso_code': 'US'},
        'subdivisions': [{'names': {'en': 'California'}}],
        'location': {
            'latitude': 37.386,
            'longitude': -122.0838,
            'accuracy_radius': 1000,
            'time_zone': 'America/Los_Angeles',
        },
    }

    geoip_service._geoip_reader = mock_reader
    geoip_service._geoip_available = True

    try:
        result = geoip_service.lookup('8.8.8.8')
        assert result is not None
        assert result['ip'] == '8.8.8.8'
        assert result['city'] == 'Mountain View'
        assert result['country'] == 'United States'
        assert result['country_code'] == 'US'
        assert result['latitude'] == 37.386
        assert result['longitude'] == -122.0838
        assert result['timezone'] == 'America/Los_Angeles'
    finally:
        geoip_service._geoip_reader = original_reader
        geoip_service._geoip_available = original_available


def test_lookup_not_found():
    from services import geoip_service
    original_reader = geoip_service._geoip_reader
    original_available = geoip_service._geoip_available

    mock_reader = MagicMock()
    mock_reader.get.return_value = None

    geoip_service._geoip_reader = mock_reader
    geoip_service._geoip_available = True

    try:
        result = geoip_service.lookup('0.0.0.0')
        assert result is None
    finally:
        geoip_service._geoip_reader = original_reader
        geoip_service._geoip_available = original_available


def test_batch_lookup_with_mock():
    from services import geoip_service
    original_reader = geoip_service._geoip_reader
    original_available = geoip_service._geoip_available

    mock_reader = MagicMock()
    mock_reader.get.side_effect = [
        {
            'city': {'names': {'en': 'Mountain View'}},
            'country': {'names': {'en': 'United States'}, 'iso_code': 'US'},
            'location': {'latitude': 37.386, 'longitude': -122.0838},
        },
        None,
        {
            'city': {'names': {'en': 'Sydney'}},
            'country': {'names': {'en': 'Australia'}, 'iso_code': 'AU'},
            'location': {'latitude': -33.87, 'longitude': 151.21},
        },
    ]

    geoip_service._geoip_reader = mock_reader
    geoip_service._geoip_available = True

    try:
        result = geoip_service.batch_lookup(['8.8.8.8', '192.168.1.1', '1.1.1.1'])
        assert len(result) == 2
        assert '8.8.8.8' in result
        assert '1.1.1.1' in result
        assert '192.168.1.1' not in result
        assert result['8.8.8.8']['country_code'] == 'US'
        assert result['1.1.1.1']['country_code'] == 'AU'
    finally:
        geoip_service._geoip_reader = original_reader
        geoip_service._geoip_available = original_available


def test_lookup_exception_returns_none():
    from services import geoip_service
    original_reader = geoip_service._geoip_reader
    original_available = geoip_service._geoip_available

    mock_reader = MagicMock()
    mock_reader.get.side_effect = ValueError("test error")

    geoip_service._geoip_reader = mock_reader
    geoip_service._geoip_available = True

    try:
        result = geoip_service.lookup('8.8.8.8')
        assert result is None
    finally:
        geoip_service._geoip_reader = original_reader
        geoip_service._geoip_available = original_available


def test_reload_nonexistent_path():
    from services import geoip_service
    original_reader = geoip_service._geoip_reader
    original_available = geoip_service._geoip_available

    geoip_service.reload('/nonexistent/path/to/db.mmdb')

    assert geoip_service._geoip_available is False
    assert geoip_service._geoip_reader is None

    geoip_service._geoip_reader = original_reader
    geoip_service._geoip_available = original_available
