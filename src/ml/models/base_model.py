"""
Base ML Model Interface
Abstract base class for all detection models.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional
from pathlib import Path
import numpy as np


@dataclass
class PredictionResult:
    """Result from a model prediction."""

    score: float  # Anomaly/threat score (0.0 - 1.0)
    is_anomaly: bool  # Binary classification
    confidence: float  # Model confidence (0.0 - 1.0)
    label: Optional[str] = None  # Optional class label
    details: dict = None  # Additional prediction details

    def __post_init__(self):
        if self.details is None:
            self.details = {}

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "score": self.score,
            "is_anomaly": self.is_anomaly,
            "confidence": self.confidence,
            "label": self.label,
            "details": self.details,
        }


class BaseDetector(ABC):
    """
    Abstract base class for all detection models.

    All ML models must implement this interface to ensure
    consistent behavior across the detection pipeline.
    """

    def __init__(self, model_name: str, version: str = "1.0.0"):
        self.model_name = model_name
        self.version = version
        self.is_trained = False
        self.threshold = 0.5
        self._model: Any = None

    @property
    def model(self) -> Any:
        """Get the underlying model."""
        return self._model

    @abstractmethod
    def train(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> None:
        """
        Train the model on data.

        Args:
            X: Feature matrix (n_samples, n_features)
            y: Optional labels for supervised learning
        """
        pass

    @abstractmethod
    def predict(self, X: np.ndarray) -> list[PredictionResult]:
        """
        Make predictions on data.

        Args:
            X: Feature matrix (n_samples, n_features)

        Returns:
            List of PredictionResult objects
        """
        pass

    @abstractmethod
    def predict_single(self, features: np.ndarray) -> PredictionResult:
        """
        Make prediction on a single sample.

        Args:
            features: Feature vector (n_features,)

        Returns:
            PredictionResult object
        """
        pass

    def fit_predict(
        self,
        X: np.ndarray,
        y: Optional[np.ndarray] = None,
    ) -> list[PredictionResult]:
        """Train and predict in one step."""
        self.train(X, y)
        return self.predict(X)

    @abstractmethod
    def save(self, path: Path) -> None:
        """
        Save model to disk.

        Args:
            path: Directory path to save model
        """
        pass

    @abstractmethod
    def load(self, path: Path) -> None:
        """
        Load model from disk.

        Args:
            path: Directory path to load model from
        """
        pass

    def set_threshold(self, threshold: float) -> None:
        """
        Set the decision threshold.

        Args:
            threshold: New threshold value (0.0 - 1.0)
        """
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("Threshold must be between 0.0 and 1.0")
        self.threshold = threshold

    def get_model_info(self) -> dict:
        """Get model information."""
        return {
            "model_name": self.model_name,
            "version": self.version,
            "is_trained": self.is_trained,
            "threshold": self.threshold,
        }

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.model_name}, version={self.version})"


class BaseClassifier(BaseDetector):
    """Base class for classification models."""

    @abstractmethod
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Get probability predictions.

        Args:
            X: Feature matrix (n_samples, n_features)

        Returns:
            Probability matrix (n_samples, n_classes)
        """
        pass

    @abstractmethod
    def get_classes(self) -> list[str]:
        """Get list of class labels."""
        pass


class BaseAnomalyDetector(BaseDetector):
    """Base class for anomaly detection models."""

    def __init__(
        self,
        model_name: str,
        version: str = "1.0.0",
        contamination: float = 0.1,
    ):
        super().__init__(model_name, version)
        self.contamination = contamination

    @abstractmethod
    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """
        Get anomaly scores for samples.

        Higher scores indicate higher anomaly likelihood.

        Args:
            X: Feature matrix (n_samples, n_features)

        Returns:
            Anomaly scores (n_samples,)
        """
        pass

    def get_model_info(self) -> dict:
        """Get model information with contamination."""
        info = super().get_model_info()
        info["contamination"] = self.contamination
        return info
