"""
Detection Blueprint
Handles detection profile get/set for attack sensitivity tuning.
"""

import logging

from flask import Blueprint, request, jsonify

import extensions as ext

bp = Blueprint('detection', __name__, url_prefix='/api/detection')
logger = logging.getLogger('packet_peeper')


@bp.route('/profile', methods=['GET', 'POST'])
def api_detection_profile():
    try:
        if request.method == 'GET':
            if ext.sniffer and hasattr(ext.sniffer, 'security_monitor') and ext.sniffer.security_monitor:
                monitor = ext.sniffer.security_monitor
                return jsonify({
                    'current_profile': monitor.get_profile(),
                    'available_profiles': ['strict', 'balanced', 'sensitive', 'test'],
                    'current_thresholds': monitor.get_thresholds(),
                    'description': {
                        'strict': 'High bar for alerts - fewer false positives, may miss subtle attacks',
                        'balanced': 'Default tuning - balanced between sensitivity and false positive rate',
                        'sensitive': 'Low bar for alerts - catches more potential attacks, more false positives',
                        'test': 'Very low bar - for testing, expects many alerts even from normal traffic',
                    },
                })
            else:
                return jsonify({'error': 'Sniffer not running'}), 400

        elif request.method == 'POST':
            data = request.get_json() or {}
            profile = data.get('profile', 'balanced')

            if ext.sniffer and hasattr(ext.sniffer, 'security_monitor') and ext.sniffer.security_monitor:
                monitor = ext.sniffer.security_monitor
                new_profile = monitor.set_profile(profile)
                ext.add_log('info', 'API', f'Detection profile changed to: {new_profile}')
                return jsonify({
                    'message': f'Profile changed to {new_profile}',
                    'current_profile': new_profile,
                    'current_thresholds': monitor.get_thresholds(),
                })
            else:
                return jsonify({'error': 'Sniffer not running'}), 400

    except Exception as e:
        logger.error(f"Error managing detection profile: {str(e)}")
        return jsonify({'error': str(e)}), 500
