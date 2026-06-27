"""
ML Anomaly Detection Service for Packet Peeper.

Uses Isolation Forest on 1-minute TrafficFeatureRecord windows
to detect network anomalies in real-time.

Training data: last N hours of TrafficFeatureRecord rows (16 features each).
Scoring: each new 1-min window is scored; scores below threshold -> anomaly alert.
Model persistence: joblib to DATA_DIR/models/.
"""

import datetime
import logging
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger('packet_peeper')

FEATURE_COLUMNS = [
    'total_packets', 'total_bytes',
    'tcp_packets', 'udp_packets', 'icmp_packets', 'other_packets',
    'avg_packet_size',
    'unique_src_ips', 'unique_dst_ips', 'unique_dst_ports',
    'syn_count', 'syn_ack_ratio',
    'dns_queries', 'arp_packets',
    'bandwidth_bps',
]

NUM_FEATURES = len(FEATURE_COLUMNS)


class MLAnomalyService:
    def __init__(self, model_dir: Path, score_threshold: float = -0.3,
                 training_window_hours: int = 168,
                 min_training_samples: int = 100):
        self.model_dir = model_dir
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.model_path = model_dir / 'anomaly_detector.joblib'

        self.score_threshold = score_threshold
        self.training_window_hours = training_window_hours
        self.min_training_samples = min_training_samples

        self.model = None
        self.scaler = None
        self._lock = threading.Lock()

        self._last_trained = None
        self._training_samples = 0
        self._last_score_time = None

        self._score_history: List[Dict] = []
        self._max_score_history = 1440

        self._anomaly_count = 0
        self._total_scores = 0

        self._load_model()

    # ==================== Feature Extraction ====================

    @staticmethod
    def feature_vector_from_dict(feature: Dict) -> Optional[np.ndarray]:
        vec = []
        for col in FEATURE_COLUMNS:
            val = feature.get(col, 0)
            if val is None:
                val = 0
            try:
                vec.append(float(val))
            except (TypeError, ValueError):
                vec.append(0.0)
        arr = np.array(vec, dtype=np.float64)
        if not np.isfinite(arr).all():
            return None
        return arr

    @staticmethod
    def features_from_db_rows(rows: List[Dict]) -> np.ndarray:
        vectors = []
        for row in rows:
            vec = MLAnomalyService.feature_vector_from_dict(row)
            if vec is not None:
                vectors.append(vec)
        if not vectors:
            return np.empty((0, NUM_FEATURES), dtype=np.float64)
        return np.vstack(vectors)

    # ==================== Training ====================

    def train(self, db_service, start_time: Optional[datetime.datetime] = None,
              end_time: Optional[datetime.datetime] = None) -> Dict:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler

        if end_time is None:
            end_time = datetime.datetime.utcnow()
        if start_time is None:
            start_time = end_time - datetime.timedelta(hours=self.training_window_hours)

        rows = db_service.get_traffic_features(
            start_time=start_time, end_time=end_time,
            limit=max(20000, self.min_training_samples * 2),
        )

        if len(rows) < self.min_training_samples:
            return {
                'success': False,
                'error': f'Insufficient training data: {len(rows)} rows (need {self.min_training_samples})',
                'samples': len(rows),
            }

        X = self.features_from_db_rows(rows)
        if X.shape[0] < self.min_training_samples:
            return {
                'success': False,
                'error': f'Usable feature vectors after cleanup: {X.shape[0]} (need {self.min_training_samples})',
                'samples': X.shape[0],
            }

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        contamination = max(0.01, min(0.15, 1.0 / (X_scaled.shape[0] ** 0.3)))

        model = IsolationForest(
            n_estimators=100,
            max_samples='auto',
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
            bootstrap=False,
        )
        model.fit(X_scaled)

        with self._lock:
            self.model = model
            self.scaler = scaler
            self._last_trained = datetime.datetime.utcnow().isoformat()
            self._training_samples = X_scaled.shape[0]
            self._anomaly_count = 0
            self._total_scores = 0

        self._save_model()

        logger.info(
            f"[ML] Isolation Forest trained on {X_scaled.shape[0]} samples "
            f"({start_time.isoformat()} to {end_time.isoformat()}), "
            f"contamination={contamination:.4f}"
        )

        return {
            'success': True,
            'samples': X_scaled.shape[0],
            'contamination': round(contamination, 4),
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'trained_at': self._last_trained,
        }

    # ==================== Scoring ====================

    def score(self, feature: Dict) -> Optional[Dict]:
        with self._lock:
            if self.model is None or self.scaler is None:
                return None
            model = self.model
            scaler = self.scaler

        vec = self.feature_vector_from_dict(feature)
        if vec is None:
            return None

        X = vec.reshape(1, -1)
        X_scaled = scaler.transform(X)

        decision_score = float(model.decision_function(X_scaled)[0])
        prediction = int(model.predict(X_scaled)[0])

        is_anomaly = decision_score < self.score_threshold

        with self._lock:
            self._total_scores += 1
            self._last_score_time = datetime.datetime.utcnow().isoformat()
            if is_anomaly:
                self._anomaly_count += 1

        result = {
            'score': round(decision_score, 6),
            'prediction': prediction,
            'is_anomaly': is_anomaly,
            'threshold': self.score_threshold,
            'window_start': feature.get('window_start'),
            'features': {k: feature.get(k, 0) for k in FEATURE_COLUMNS},
        }

        self._append_score_history(result)

        return result

    def batch_score(self, features: List[Dict]) -> List[Dict]:
        with self._lock:
            if self.model is None or self.scaler is None:
                return []
            model = self.model
            scaler = self.scaler

        vectors = []
        valid_indices = []
        for i, f in enumerate(features):
            vec = self.feature_vector_from_dict(f)
            if vec is not None:
                vectors.append(vec)
                valid_indices.append(i)

        if not vectors:
            return []

        X = np.vstack(vectors)
        X_scaled = scaler.transform(X)

        scores = model.decision_function(X_scaled)
        predictions = model.predict(X_scaled)

        results = []
        for j, idx in enumerate(valid_indices):
            s = float(scores[j])
            p = int(predictions[j])
            is_anomaly = s < self.score_threshold

            with self._lock:
                self._total_scores += 1
                if is_anomaly:
                    self._anomaly_count += 1

            result = {
                'score': round(s, 6),
                'prediction': p,
                'is_anomaly': is_anomaly,
                'threshold': self.score_threshold,
                'window_start': features[idx].get('window_start'),
                'features': {k: features[idx].get(k, 0) for k in FEATURE_COLUMNS},
            }
            results.append(result)
            self._append_score_history(result)

        with self._lock:
            self._last_score_time = datetime.datetime.utcnow().isoformat()

        return results

    # ==================== Status ====================

    def get_status(self) -> Dict:
        with self._lock:
            return {
                'model_loaded': self.model is not None,
                'last_trained': self._last_trained,
                'training_samples': self._training_samples,
                'score_threshold': self.score_threshold,
                'training_window_hours': self.training_window_hours,
                'min_training_samples': self.min_training_samples,
                'total_scores': self._total_scores,
                'anomaly_count': self._anomaly_count,
                'last_score_time': self._last_score_time,
                'model_path': str(self.model_path),
            }

    def get_scores(self, limit: int = 200) -> List[Dict]:
        return list(reversed(self._score_history[-limit:]))

    def update_threshold(self, threshold: float) -> Dict:
        if not -1.0 <= threshold <= 0.5:
            return {'success': False, 'error': 'Threshold must be between -1.0 and 0.5'}
        self.score_threshold = threshold
        logger.info(f"[ML] Anomaly score threshold updated to {threshold}")
        return {'success': True, 'threshold': threshold}

    # ==================== Model Persistence ====================

    def _save_model(self) -> None:
        try:
            import joblib
            payload = {
                'model': self.model,
                'scaler': self.scaler,
                'last_trained': self._last_trained,
                'training_samples': self._training_samples,
                'score_threshold': self.score_threshold,
            }
            joblib.dump(payload, self.model_path)
            logger.info(f"[ML] Model saved to {self.model_path}")
        except Exception as e:
            logger.error(f"[ML] Failed to save model: {e}")

    def _load_model(self) -> bool:
        try:
            import joblib
            if not self.model_path.exists():
                logger.info("[ML] No saved model found; will train on first opportunity")
                return False
            payload = joblib.load(self.model_path)
            self.model = payload.get('model')
            self.scaler = payload.get('scaler')
            self._last_trained = payload.get('last_trained')
            self._training_samples = payload.get('training_samples', 0)
            saved_threshold = payload.get('score_threshold')
            if saved_threshold is not None:
                self.score_threshold = saved_threshold
            logger.info(
                f"[ML] Model loaded from {self.model_path} "
                f"(trained {self._last_trained}, {self._training_samples} samples)"
            )
            return True
        except Exception as e:
            logger.warning(f"[ML] Failed to load model: {e}")
            self.model = None
            self.scaler = None
            return False

    # ==================== Score History ====================

    def _append_score_history(self, result: Dict) -> None:
        entry = {
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'score': result['score'],
            'is_anomaly': result['is_anomaly'],
            'threshold': result['threshold'],
            'window_start': result.get('window_start'),
        }
        self._score_history.append(entry)
        if len(self._score_history) > self._max_score_history:
            self._score_history = self._score_history[-self._max_score_history:]


_ml_service: Optional[MLAnomalyService] = None


def get_ml_service() -> Optional[MLAnomalyService]:
    global _ml_service
    return _ml_service


def _bg_init(service):
    import time
    import extensions as ext
    # Wait up to 15 seconds for db_service to become available
    for _ in range(15):
        if getattr(ext, 'db_service', None):
            break
        time.sleep(1)

    if not getattr(ext, 'db_service', None):
        return

    try:
        # 1. Load recent traffic features to populate score history
        rows = ext.db_service.get_traffic_features(limit=100)
        if rows:
            # Batch score them to populate _score_history
            service.batch_score(rows)
            logger.info(f"[ML] Populated initial score history with {len(rows)} recent windows")
            
        # 2. Automatically check if we can retrain on startup
        train_rows = ext.db_service.get_traffic_features(limit=service.min_training_samples * 2)
        if len(train_rows) >= service.min_training_samples:
            logger.info("[ML] Automatically initiating startup model retraining...")
            res = service.train(ext.db_service)
            logger.info(f"[ML] Startup retrain result: {res}")
    except Exception as e:
        logger.warning(f"[ML] Background init task failed: {e}")


def init_ml_service(model_dir: Path, score_threshold: float = -0.3,
                    training_window_hours: int = 168,
                    min_training_samples: int = 100) -> MLAnomalyService:
    global _ml_service
    if _ml_service is None:
        _ml_service = MLAnomalyService(
            model_dir=model_dir,
            score_threshold=score_threshold,
            training_window_hours=training_window_hours,
            min_training_samples=min_training_samples,
        )
        import threading
        threading.Thread(target=_bg_init, args=(_ml_service,), daemon=True, name="MLStartupInitThread").start()
    return _ml_service
