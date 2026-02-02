"""
ML Predictor Service
Main inference service for threat detection.
"""

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from datetime import datetime
import numpy as np
import structlog

from src.ml.models.base_model import PredictionResult
from src.ml.models.anomaly_detector import NetworkAnomalyDetector, TrafficVolumeDetector
from src.ml.features.extractor import FeatureExtractor, TrafficFeatures
from src.domain.entities.traffic_event import TrafficEvent
from src.domain.value_objects.threat_level import ThreatLevel
from src.domain.value_objects.attack_signature import AttackSignature, AttackType, AttackProtocol

logger = structlog.get_logger(__name__)


@dataclass
class ThreatPrediction:
    """Combined threat prediction from multiple models."""

    threat_level: ThreatLevel
    attack_signature: Optional[AttackSignature]
    source_ip: str
    predictions: dict[str, PredictionResult]
    features: TrafficFeatures
    timestamp: datetime

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "threat_level": self.threat_level.to_dict(),
            "attack_signature": self.attack_signature.to_dict() if self.attack_signature else None,
            "source_ip": self.source_ip,
            "predictions": {k: v.to_dict() for k, v in self.predictions.items()},
            "timestamp": self.timestamp.isoformat(),
        }


class ThreatPredictor:
    """
    Main prediction service combining multiple ML models.

    Orchestrates anomaly detection, pattern matching, and
    threat level assessment.
    """

    def __init__(
        self,
        weights_path: Optional[Path] = None,
        anomaly_threshold: float = 0.7,
        volume_threshold: float = 0.8,
    ):
        self.weights_path = weights_path or Path("src/ml/weights")
        self.anomaly_threshold = anomaly_threshold
        self.volume_threshold = volume_threshold

        # Initialize models
        self.anomaly_detector = NetworkAnomalyDetector(
            contamination=0.1,
            n_estimators=100,
        )
        self.anomaly_detector.set_threshold(anomaly_threshold)

        self.volume_detector = TrafficVolumeDetector(
            window_size=60,
            spike_threshold=3.0,
        )

        # Feature extractor
        self.feature_extractor = FeatureExtractor(window_seconds=60)

        # Model weights for ensemble
        self.model_weights = {
            "anomaly": 0.5,
            "volume": 0.3,
            "pattern": 0.2,
        }

        self._is_initialized = False

    async def initialize(self) -> None:
        """Initialize predictor and load models."""
        logger.info("initializing_threat_predictor")

        # Load pre-trained models if available
        if self.weights_path.exists():
            try:
                anomaly_path = self.weights_path / "anomaly"
                if anomaly_path.exists():
                    self.anomaly_detector.load(anomaly_path)
                    logger.info("loaded_anomaly_detector")

                volume_path = self.weights_path / "volume"
                if volume_path.exists():
                    self.volume_detector.load(volume_path)
                    logger.info("loaded_volume_detector")
            except Exception as e:
                logger.warning("failed_to_load_models", error=str(e))

        self._is_initialized = True
        logger.info("threat_predictor_initialized")

    async def train_baseline(self, events: list[TrafficEvent]) -> None:
        """
        Train models on baseline traffic.

        Args:
            events: List of normal traffic events for training
        """
        logger.info("training_baseline", event_count=len(events))

        # Extract features
        features_list = self.feature_extractor.extract_windowed(events)
        if not features_list:
            logger.warning("no_features_extracted")
            return

        X = self.feature_extractor.to_matrix(features_list)

        # Train anomaly detector
        self.anomaly_detector.train(X)

        # Train volume detector on packet rates
        volumes = np.array([f.packets_per_second for f in features_list])
        self.volume_detector.train(volumes)

        # Save models
        self.weights_path.mkdir(parents=True, exist_ok=True)
        self.anomaly_detector.save(self.weights_path / "anomaly")
        self.volume_detector.save(self.weights_path / "volume")

        logger.info("baseline_training_complete")

    async def predict(
        self,
        events: list[TrafficEvent],
    ) -> list[ThreatPrediction]:
        """
        Predict threats from traffic events.

        Args:
            events: List of TrafficEvent objects

        Returns:
            List of ThreatPrediction objects
        """
        if not self._is_initialized:
            await self.initialize()

        if not events:
            return []

        # Extract features per source IP
        ip_features = self.feature_extractor.extract_per_source(events)

        predictions = []
        for source_ip, features in ip_features.items():
            prediction = await self._predict_single_source(
                source_ip=source_ip,
                features=features,
                events=[e for e in events if e.source_ip_str == source_ip],
            )
            if prediction.threat_level.is_actionable():
                predictions.append(prediction)

        return predictions

    async def _predict_single_source(
        self,
        source_ip: str,
        features: TrafficFeatures,
        events: list[TrafficEvent],
    ) -> ThreatPrediction:
        """
        Predict threat for a single source IP.

        Args:
            source_ip: Source IP address
            features: Extracted features
            events: Traffic events from this source

        Returns:
            ThreatPrediction object
        """
        predictions: dict[str, PredictionResult] = {}
        feature_vector = features.to_vector().reshape(1, -1)

        # Anomaly detection
        if self.anomaly_detector.is_trained:
            try:
                anomaly_result = self.anomaly_detector.predict_single(feature_vector.flatten())
                predictions["anomaly"] = anomaly_result
            except Exception as e:
                logger.error("anomaly_prediction_failed", error=str(e))
                predictions["anomaly"] = PredictionResult(
                    score=0.0, is_anomaly=False, confidence=0.0
                )

        # Volume detection
        if self.volume_detector.is_trained:
            try:
                volume_result = self.volume_detector.predict_single(
                    np.array([features.packets_per_second])
                )
                predictions["volume"] = volume_result
            except Exception as e:
                logger.error("volume_prediction_failed", error=str(e))
                predictions["volume"] = PredictionResult(
                    score=0.0, is_anomaly=False, confidence=0.0
                )

        # Pattern-based detection
        pattern_result = self._detect_patterns(features, events)
        predictions["pattern"] = pattern_result

        # Calculate ensemble score
        ensemble_score = self._calculate_ensemble_score(predictions)

        # Determine threat level
        threat_level = ThreatLevel.from_score(
            score=ensemble_score,
            confidence=self._calculate_confidence(predictions),
        )

        # Identify attack signature
        attack_signature = self._identify_attack_signature(features, predictions)

        return ThreatPrediction(
            threat_level=threat_level,
            attack_signature=attack_signature,
            source_ip=source_ip,
            predictions=predictions,
            features=features,
            timestamp=datetime.utcnow(),
        )

    # Authentication ports for brute force detection
    AUTH_PORTS = {22, 21, 23, 3389, 25, 110, 143, 993, 995, 3306, 5432, 1433, 5900}

    def _detect_patterns(
        self,
        features: TrafficFeatures,
        events: list[TrafficEvent],
    ) -> PredictionResult:
        """
        Pattern-based threat detection.

        Analyzes traffic patterns for known attack signatures.
        Detection order matters - more specific attacks checked first.
        """
        indicators = []
        score = 0.0

        # ==========================================
        # APPLICATION-LAYER ATTACKS (most specific)
        # Check these FIRST - payload-based detection
        # ==========================================

        # SQL injection detection: HTTP traffic with SQL patterns
        if features.has_sql_indicators:
            indicators.append("sql_injection_pattern")
            score = max(score, 0.85)

        # XSS attack detection: HTTP traffic with XSS patterns
        if features.has_xss_indicators:
            indicators.append("xss_attack_pattern")
            score = max(score, 0.80)

        # Brute force detection: single IP, many connections, auth port
        if features.has_brute_force_indicators:
            indicators.append("brute_force_pattern")
            score = max(score, 0.80)
        elif (features.top_source_ip_ratio > 0.95 and
              features.connection_count > 30 and
              features.primary_target_port in self.AUTH_PORTS):
            indicators.append("brute_force_pattern")
            score = max(score, 0.75)

        # ==========================================
        # NETWORK-LAYER ATTACKS (specific patterns)
        # ==========================================

        # SYN flood detection
        if features.syn_ratio > 0.8 and features.syn_ack_ratio < 0.1:
            indicators.append("syn_flood_pattern")
            score = max(score, 0.9)

        # Port scan detection (lowered threshold from 0.6 to 0.4)
        if features.port_scan_score > 0.4:
            indicators.append("port_scan_pattern")
            score = max(score, 0.7)

        # Slowloris detection (many connections, low bandwidth)
        if features.connection_count > 50 and features.avg_packet_size < 100:
            indicators.append("slowloris_pattern")
            score = max(score, 0.7)

        # ==========================================
        # VOLUMETRIC ATTACKS (generic patterns)
        # Check last - these are catch-all patterns
        # ==========================================

        # DDoS indicators (large scale)
        if features.unique_source_ips > 100 and features.packets_per_second > 1000:
            indicators.append("ddos_pattern")
            score = max(score, 0.95)

        # Smaller-scale DDoS (only if no more specific attack detected)
        if not indicators and features.unique_source_ips > 20 and features.packets_per_second > 200:
            indicators.append("ddos_pattern")
            score = max(score, 0.75)

        # Source IP concentration (only if no other pattern detected)
        if not indicators and features.top_source_ip_ratio > 0.9:
            indicators.append("single_source_flood")
            score = max(score, 0.6)

        # Suspicious HTTP traffic (fallback for undetected app-layer)
        if not indicators and (features.primary_protocol in ["http", "https"] and
              features.avg_packet_size > 200 and
              features.top_source_ip_ratio > 0.8):
            indicators.append("suspicious_http_pattern")
            score = max(score, 0.55)

        return PredictionResult(
            score=score,
            is_anomaly=score > 0.5,
            confidence=min(1.0, len(indicators) * 0.3),
            label=indicators[0] if indicators else "normal",
            details={"indicators": indicators},
        )

    def _calculate_ensemble_score(
        self,
        predictions: dict[str, PredictionResult],
    ) -> float:
        """Calculate weighted ensemble score."""
        total_weight = 0.0
        weighted_sum = 0.0

        for model_name, result in predictions.items():
            weight = self.model_weights.get(model_name, 0.1)
            weighted_sum += result.score * weight * result.confidence
            total_weight += weight * result.confidence

        if total_weight == 0:
            return 0.0

        return weighted_sum / total_weight

    def _calculate_confidence(
        self,
        predictions: dict[str, PredictionResult],
    ) -> float:
        """Calculate overall prediction confidence."""
        if not predictions:
            return 0.0

        # Average confidence weighted by model importance
        total_weight = 0.0
        weighted_conf = 0.0

        for model_name, result in predictions.items():
            weight = self.model_weights.get(model_name, 0.1)
            weighted_conf += result.confidence * weight
            total_weight += weight

        return weighted_conf / total_weight if total_weight > 0 else 0.0

    def _identify_attack_signature(
        self,
        features: TrafficFeatures,
        predictions: dict[str, PredictionResult],
    ) -> Optional[AttackSignature]:
        """Identify the most likely attack signature."""
        pattern_result = predictions.get("pattern")
        if not pattern_result or not pattern_result.is_anomaly:
            return None

        indicators = pattern_result.details.get("indicators", [])
        if not indicators:
            return None

        # Map indicators to attack types
        indicator_map = {
            "syn_flood_pattern": (AttackType.SYN_FLOOD, AttackProtocol.TCP),
            "port_scan_pattern": (AttackType.PORT_SCAN, AttackProtocol.TCP),
            "ddos_pattern": (AttackType.DDOS, AttackProtocol.TCP),
            "slowloris_pattern": (AttackType.SLOWLORIS, AttackProtocol.HTTP),
            "single_source_flood": (AttackType.DDOS, AttackProtocol.TCP),
            "brute_force_pattern": (AttackType.BRUTE_FORCE, AttackProtocol.TCP),
            "sql_injection_pattern": (AttackType.SQL_INJECTION, AttackProtocol.HTTP),
            "xss_attack_pattern": (AttackType.XSS_ATTACK, AttackProtocol.HTTP),
            "suspicious_http_pattern": (AttackType.ANOMALY, AttackProtocol.HTTP),
        }

        primary_indicator = indicators[0]
        if primary_indicator in indicator_map:
            attack_type, protocol = indicator_map[primary_indicator]
            return AttackSignature.create(
                attack_type=attack_type,
                protocol=protocol,
                indicators=indicators,
                description=f"Detected {attack_type.value} attack pattern",
                severity_weight=pattern_result.score,
            )

        return AttackSignature.create(
            attack_type=AttackType.ANOMALY,
            protocol=AttackProtocol.UNKNOWN,
            indicators=indicators,
            description="Unknown anomalous traffic pattern",
            severity_weight=pattern_result.score,
        )


# Entry point for running as service
async def main():
    """Main entry point for ML service."""
    from src.infrastructure.persistence.redis_client import init_redis, close_redis

    logger.info("starting_ml_service")

    predictor = ThreatPredictor()
    await predictor.initialize()

    # Initialize Redis for heartbeat
    redis_client = None
    try:
        redis_client = await init_redis()
        logger.info("ml_service_redis_connected")
    except Exception as e:
        logger.warning("ml_service_redis_connection_failed", error=str(e))

    # Keep service running and record heartbeats
    heartbeat_key = "cybershield:heartbeat:ml_service"
    while True:
        try:
            if redis_client and redis_client._client:
                from datetime import datetime
                await redis_client._client.set(
                    heartbeat_key,
                    datetime.utcnow().isoformat(),
                    ex=120  # 2 minute TTL
                )
        except Exception as e:
            logger.warning("ml_service_heartbeat_failed", error=str(e))
        await asyncio.sleep(30)  # Heartbeat every 30 seconds


if __name__ == "__main__":
    asyncio.run(main())
