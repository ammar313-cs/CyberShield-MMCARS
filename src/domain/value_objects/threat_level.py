"""
Threat Level Value Object
Immutable representation of threat severity levels.
"""

from enum import Enum
from dataclasses import dataclass
from typing import ClassVar


class ThreatSeverity(str, Enum):
    """Enumeration of threat severity levels."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class ThreatLevel:
    """
    Value object representing a threat level with score and severity.

    Attributes:
        score: Numeric threat score (0.0 - 1.0)
        severity: Categorical severity level
        confidence: Confidence in the assessment (0.0 - 1.0)
    """

    score: float
    severity: ThreatSeverity
    confidence: float

    # Threshold constants
    LOW_THRESHOLD: ClassVar[float] = 0.25
    MEDIUM_THRESHOLD: ClassVar[float] = 0.50
    HIGH_THRESHOLD: ClassVar[float] = 0.75
    CRITICAL_THRESHOLD: ClassVar[float] = 0.90

    def __post_init__(self) -> None:
        """Validate threat level values."""
        if not 0.0 <= self.score <= 1.0:
            raise ValueError(f"Score must be between 0.0 and 1.0, got {self.score}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                f"Confidence must be between 0.0 and 1.0, got {self.confidence}"
            )

    @classmethod
    def from_score(cls, score: float, confidence: float = 1.0) -> "ThreatLevel":
        """
        Create ThreatLevel from a numeric score.

        Args:
            score: Threat score (0.0 - 1.0)
            confidence: Confidence level (0.0 - 1.0)

        Returns:
            ThreatLevel instance with appropriate severity
        """
        if score >= cls.CRITICAL_THRESHOLD:
            severity = ThreatSeverity.CRITICAL
        elif score >= cls.HIGH_THRESHOLD:
            severity = ThreatSeverity.HIGH
        elif score >= cls.MEDIUM_THRESHOLD:
            severity = ThreatSeverity.MEDIUM
        elif score >= cls.LOW_THRESHOLD:
            severity = ThreatSeverity.LOW
        else:
            severity = ThreatSeverity.NONE

        return cls(score=score, severity=severity, confidence=confidence)

    @classmethod
    def none(cls) -> "ThreatLevel":
        """Create a no-threat level."""
        return cls(score=0.0, severity=ThreatSeverity.NONE, confidence=1.0)

    @classmethod
    def critical(cls, confidence: float = 1.0) -> "ThreatLevel":
        """Create a critical threat level."""
        return cls(score=1.0, severity=ThreatSeverity.CRITICAL, confidence=confidence)

    def is_actionable(self) -> bool:
        """Check if threat level requires action."""
        return self.severity in (
            ThreatSeverity.MEDIUM,
            ThreatSeverity.HIGH,
            ThreatSeverity.CRITICAL,
        )

    def requires_immediate_response(self) -> bool:
        """Check if threat requires immediate response."""
        return self.severity in (ThreatSeverity.HIGH, ThreatSeverity.CRITICAL)

    def __gt__(self, other: "ThreatLevel") -> bool:
        """Compare threat levels by score."""
        return self.score > other.score

    def __lt__(self, other: "ThreatLevel") -> bool:
        """Compare threat levels by score."""
        return self.score < other.score

    def __ge__(self, other: "ThreatLevel") -> bool:
        """Compare threat levels by score."""
        return self.score >= other.score

    def __le__(self, other: "ThreatLevel") -> bool:
        """Compare threat levels by score."""
        return self.score <= other.score

    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        return {
            "score": self.score,
            "severity": self.severity.value,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ThreatLevel":
        """Create from dictionary representation."""
        return cls(
            score=data["score"],
            severity=ThreatSeverity(data["severity"]),
            confidence=data["confidence"],
        )
