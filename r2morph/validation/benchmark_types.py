"""Data types for the validation/benchmark framework.

Enums and dataclasses describing benchmark categories, severities, metrics,
test samples and results. A pure leaf -- the ValidationFramework in benchmark
depends on these; they depend on nothing in that module.
"""

import hashlib
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any


class BenchmarkCategory(Enum):
    """Categories for benchmark testing."""

    DETECTION = "detection"
    DEVIRTUALIZATION = "devirtualization"
    DEOBFUSCATION = "deobfuscation"
    BYPASS = "bypass"
    FULL_PIPELINE = "full_pipeline"


class TestSeverity(Enum):
    """Test severity levels."""

    # Domain enum, not a pytest test class. The ``Test`` prefix collides
    # with pytest's default ``python_classes`` pattern; without this,
    # pytest tries to collect it and emits a PytestCollectionWarning
    # that `-W error` (CLAUDE.md s.3) turns into a fatal collection
    # error wherever this class is imported into a test module.
    __test__ = False

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class PerformanceMetrics:
    """Performance metrics for analysis operations."""

    execution_time: float
    memory_usage_mb: float
    cpu_usage_percent: float
    peak_memory_mb: float
    success: bool
    error_message: str | None = None


@dataclass
class AccuracyMetrics:
    """Accuracy metrics for analysis results."""

    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    accuracy: float


@dataclass
class TestSample:
    """Represents a test sample with known characteristics."""

    # Not a pytest test class: see TestSeverity above. The bare (un
    # annotated) assignment is a plain class attribute, so @dataclass
    # does not treat it as a field.
    __test__ = False

    file_path: str
    sample_hash: str
    expected_packer: str | None
    expected_vm_protection: bool
    expected_anti_analysis: bool
    expected_cfo: bool
    expected_mba: bool
    severity: TestSeverity
    description: str
    source: str  # Where the sample came from

    @property
    def file_exists(self) -> bool:
        """Check if the test file exists."""
        return Path(self.file_path).exists()

    def verify_hash(self) -> bool:
        """Verify the sample's hash."""
        if not self.file_exists:
            return False

        try:
            with open(self.file_path, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
                return file_hash == self.sample_hash
        except Exception:
            return False


@dataclass
class BenchmarkResult:
    """Result of a benchmark test."""

    sample: TestSample
    category: BenchmarkCategory
    performance: PerformanceMetrics
    accuracy: AccuracyMetrics | None
    analysis_result: dict[str, Any]
    timestamp: str
    r2morph_version: str
