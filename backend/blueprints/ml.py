"""
ML Anomaly Detection Blueprint.

REST endpoints for model status, anomaly scores, retraining, and config.
"""

from flask import Blueprint, request, jsonify
import extensions as ext
from config.config import FEATURES

bp = Blueprint('ml', __name__, url_prefix='/api/ml')


def _ml_available():
    if not FEATURES.get('ml_anomaly_detection', False):
        return False
    return ext.ml_service is not None


@bp.route('/status', methods=['GET'])
def ml_status():
    if not _ml_available():
        return jsonify({'error': 'ML anomaly detection is disabled', 'enabled': False}), 404
    return jsonify(ext.ml_service.get_status())


@bp.route('/scores', methods=['GET'])
def ml_scores():
    if not _ml_available():
        return jsonify({'error': 'ML anomaly detection is disabled', 'enabled': False}), 404
    limit = request.args.get('limit', 200, type=int)
    scores = ext.ml_service.get_scores(limit=min(limit, 1000))
    return jsonify({'scores': scores, 'count': len(scores)})


@bp.route('/retrain', methods=['POST'])
def ml_retrain():
    if not _ml_available():
        return jsonify({'error': 'ML anomaly detection is disabled', 'enabled': False}), 404

    body = request.get_json(silent=True) or {}
    window_hours = body.get('window_hours', ext.ml_service.training_window_hours)

    if not ext.db_service:
        return jsonify({'error': 'Database service unavailable'}), 503

    try:
        result = ext.ml_service.train(db_service=ext.db_service)
    except ImportError as e:
        return jsonify({'success': False, 'error': f'ML dependency missing: {e.name}. Install scikit-learn.'}), 503
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

    if result.get('success'):
        return jsonify(result), 200
    else:
        return jsonify(result), 400


@bp.route('/config', methods=['GET'])
def ml_config():
    if not _ml_available():
        return jsonify({'error': 'ML anomaly detection is disabled', 'enabled': False}), 404
    return jsonify({
        'score_threshold': ext.ml_service.score_threshold,
        'training_window_hours': ext.ml_service.training_window_hours,
        'min_training_samples': ext.ml_service.min_training_samples,
        'feature_columns': ext.ml_service.__class__.FEATURE_COLUMNS if hasattr(ext.ml_service.__class__, 'FEATURE_COLUMNS') else [],
    })


@bp.route('/config', methods=['POST'])
def ml_update_config():
    if not _ml_available():
        return jsonify({'error': 'ML anomaly detection is disabled', 'enabled': False}), 404

    body = request.get_json(silent=True) or {}

    if 'score_threshold' in body:
        result = ext.ml_service.update_threshold(float(body['score_threshold']))
        if not result.get('success'):
            return jsonify(result), 400

    return jsonify(ext.ml_service.get_status())
