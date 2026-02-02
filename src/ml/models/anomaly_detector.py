"""
Anomaly Detector
Isolation Forest-based anomaly detection for network traffic.
"""

from pathlib import Path
from typing import Optional
import numpy as np
import joblib
import structlog

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from src.ml.models.base_model import BaseAnomalyDetector, PredictionResult

logger = structlog.get_logger(__name__)


class NetworkAnomalyDetector(BaseAnomalyDetector):
    """
    Isolation Forest-based anomaly detector for network traffic.

    Detects anomalous traffic patterns that may indicate attacks
    such as DDoS, port scanning, or unusual traffic flows.
    """

    def __init__(
        self,
        contamination: float = 0.1,
        n_estimators: int = 100,
        max_samples: str = "auto",
        random_state: int = 42,
    ):
        super().__init__(
            model_name="network_anomaly_detector",
            version="1.0.0",
            contamination=contamination,
        )
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.random_state = random_state

        self._model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            max_samples=max_samples,
            random_state=random_state,
            n_jobs=-1,
        )
        self._scaler = StandardScaler()

    def train(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> None:
        """
        Train the anomaly detector.

        Args:
            X: Feature matrix (n_samples, n_features)
            y: Ignored (unsupervised learning)
        """
        logger.info(
            "training_anomaly_detector",
            samples=X.shape[0],
            features=X.shape[1],
        )

        # Scale features
        X_scaled = self._scaler.fit_transform(X)

        # Train Isolation Forest
        self._model.fit(X_scaled)
        self.is_trained = True

        logger.info("anomaly_detector_trained")

    def predict(self, X: np.ndarray) -> list[PredictionResult]:
        """
        Predict anomalies in data.

        Args:
            X: Feature matrix (n_samples, n_features)

        Returns:
            List of PredictionResult objects
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained before prediction")

        X_scaled = self._scaler.transform(X)

        # Get predictions (-1 for anomaly, 1 for normal)
        predictions = self._model.predict(X_scaled)

        # Get anomaly scores (more negative = more anomalous)
        raw_scores = self._model.score_samples(X_scaled)

        # Normalize scores to [0, 1] where 1 = most anomalous
        scores = self._normalize_scores(raw_scores)

        results = []
        for i, (pred, score) in enumerate(zip(predictions, scores)):
            is_anomaly = pred == -1 or score > self.threshold
            confidence = min(1.0, abs(score - self.threshold) * 2 + 0.5)

            results.append(
                PredictionResult(
                    score=score,
                    is_anomaly=is_anomaly,
                    confidence=confidence,
                    label="anomaly" if is_anomaly else "normal",
                    details={
                        "raw_score": float(raw_scores[i]),
                        "isolation_prediction": int(pred),
                    },
                )
            )

        return results

    def predict_single(self, features: np.ndarray) -> PredictionResult:
        """
        Predict anomaly for a single sample.

        Args:
            features: Feature vector (n_features,)

        Returns:
            PredictionResult object
        """
        X = features.reshape(1, -1)
        results = self.predict(X)
        return results[0]

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """
        Get anomaly scores for samples.

        Args:
            X: Feature matrix (n_samples, n_features)

        Returns:
            Normalized anomaly scores (0 = normal, 1 = anomalous)
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained before scoring")

        X_scaled = self._scaler.transform(X)
        raw_scores = self._model.score_samples(X_scaled)
        return self._normalize_scores(raw_scores)

    def _normalize_scores(self, scores: np.ndarray) -> np.ndarray:
        """
        Normalize raw Isolation Forest scores to [0, 1].

        Isolation Forest returns more negative scores for anomalies.
        We invert and normalize to [0, 1] where 1 = most anomalous.
        """
        # Invert scores (make anomalies positive)
        inverted = -scores

        # Shift to positive range
        min_score = inverted.min()
        max_score = inverted.max()

        if max_score - min_score == 0:
            return np.zeros_like(inverted)

        # Normalize to [0, 1]
        normalized = (inverted - min_score) / (max_score - min_score)
        return normalized

    def save(self, path: Path) -> None:
        """Save model and scaler to disk."""
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)

        model_path = path / f"{self.model_name}_model.joblib"
        scaler_path = path / f"{self.model_name}_scaler.joblib"
        config_path = path / f"{self.model_name}_config.joblib"

        joblib.dump(self._model, model_path)
        joblib.dump(self._scaler, scaler_path)
        joblib.dump(
            {
                "contamination": self.contamination,
                "n_estimators": self.n_estimators,
                "max_samples": self.max_samples,
                "threshold": self.threshold,
                "version": self.version,
            },
            config_path,
        )

        logger.info("model_saved", path=str(path))

    def load(self, path: Path) -> None:
        """Load model and scaler from disk."""
        path = Path(path)

        model_path = path / f"{self.model_name}_model.joblib"
        scaler_path = path / f"{self.model_name}_scaler.joblib"
        config_path = path / f"{self.model_name}_config.joblib"

        self._model = joblib.load(model_path)
        self._scaler = joblib.load(scaler_path)
        config = joblib.load(config_path)

        self.contamination = config["contamination"]
        self.n_estimators = config["n_estimators"]
        self.max_samples = config["max_samples"]
        self.threshold = config["threshold"]
        self.version = config["version"]
        self.is_trained = True

        logger.info("model_loaded", path=str(path))

    def get_feature_importance(self) -> Optional[np.ndarray]:
        """
        Get feature importance scores.

        Isolation Forest doesn't directly provide feature importance,
        but we can estimate it based on tree structure.
        """
        if not self.is_trained:
            return None

        # Average path length contribution per feature
        n_features = self._model.n_features_in_
        importances = np.zeros(n_features)

        for tree in self._model.estimators_:
            tree_importances = tree.feature_importances_
            importances += tree_importances

        importances /= len(self._model.estimators_)
        return importances


class TrafficVolumeDetector(BaseAnomalyDetector):
    """
    Simple threshold-based detector for traffic volume anomalies.

    Detects sudden spikes in traffic that may indicate DDoS attacks.
    """

    def __init__(
        self,
        window_size: int = 60,
        spike_threshold: float = 3.0,
    ):
        super().__init__(
            model_name="traffic_volume_detector",
            version="1.0.0",
            contamination=0.1,
        )
        self.window_size = window_size
        self.spike_threshold = spike_threshold
        self._baseline_mean: Optional[float] = None
        self._baseline_std: Optional[float] = None

    def train(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> None:
        """
        Train by computing baseline statistics.

        Args:
            X: Traffic volume data (n_samples,) or (n_samples, 1)
        """
        X = X.flatten()
        self._baseline_mean = np.mean(X)
        self._baseline_std = np.std(X)

        if self._baseline_std == 0:
            self._baseline_std = 1.0

        self.is_trained = True
        logger.info(
            "traffic_volume_detector_trained",
            mean=self._baseline_mean,
            std=self._baseline_std,
        )

    def predict(self, X: np.ndarray) -> list[PredictionResult]:
        """
        Predict traffic volume anomalies.

        Args:
            X: Traffic volume data (n_samples,) or (n_samples, 1)

        Returns:
            List of PredictionResult objects
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained before prediction")

        X = X.flatten()
        results = []

        for value in X:
            z_score = (value - self._baseline_mean) / self._baseline_std
            score = min(1.0, abs(z_score) / (self.spike_threshold * 2))
            is_anomaly = abs(z_score) > self.spike_threshold

            confidence = min(1.0, abs(z_score) / self.spike_threshold)

            results.append(
                PredictionResult(
                    score=score,
                    is_anomaly=is_anomaly,
                    confidence=confidence,
                    label="spike" if is_anomaly else "normal",
                    details={
                        "z_score": float(z_score),
                        "value": float(value),
                        "baseline_mean": self._baseline_mean,
                        "baseline_std": self._baseline_std,
                    },
                )
            )

        return results

    def predict_single(self, features: np.ndarray) -> PredictionResult:
        """Predict for single sample."""
        return self.predict(features)[0]

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Get anomaly scores."""
        X = X.flatten()
        z_scores = np.abs((X - self._baseline_mean) / self._baseline_std)
        return np.minimum(1.0, z_scores / (self.spike_threshold * 2))

    def save(self, path: Path) -> None:
        """Save detector state."""
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)

        config_path = path / f"{self.model_name}_config.joblib"
        joblib.dump(
            {
                "baseline_mean": self._baseline_mean,
                "baseline_std": self._baseline_std,
                "window_size": self.window_size,
                "spike_threshold": self.spike_threshold,
            },
            config_path,
        )

    def load(self, path: Path) -> None:
        """Load detector state."""
        path = Path(path)
        config_path = path / f"{self.model_name}_config.joblib"
        config = joblib.load(config_path)

        self._baseline_mean = config["baseline_mean"]
        self._baseline_std = config["baseline_std"]
        self.window_size = config["window_size"]
        self.spike_threshold = config["spike_threshold"]
        self.is_trained = True
