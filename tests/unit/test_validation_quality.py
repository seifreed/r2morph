"""
Tests for validation quality features: Fuzzer integration,
Continuous fuzzing, Performance regression, and Memory leak detection.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch
import tempfile
import os

from r2morph.validation.mutation_fuzzer import (
    FuzzConfig,
    FuzzTestCase,
    FuzzResult,
    FuzzCampaignResult,
    MutationPassFuzzer,
    ContinuousFuzzer,
    create_fuzzer,
    create_continuous_fuzzer,
)
from r2morph.validation.performance_regression import (
    PerformanceMetric,
    PerformanceSnapshot,
    PerformanceRegression,
    BenchmarkConfig,
    PerformanceBenchmark,
    PerformanceRegressionSuite,
    create_benchmark,
)
from r2morph.validation.leak_detection import (
    MemorySnapshot,
    MemoryLeak,
    LeakDetectionResult,
    ObjectTracker,
    MemoryLeakDetector,
    ResourceLeak,
    ResourceLeakTestResult,
    ResourceLeakDetector,
    create_memory_detector,
)


class TestFuzzConfig:
    """Tests for FuzzConfig."""

    def test_default_config(self):
        """Test default configuration."""
        config = FuzzConfig()

        assert config.num_tests == 100
        assert config.timeout == 5
        assert config.seed is None
        assert "random" in config.input_types
        assert "ascii" in config.input_types

    def test_custom_config(self):
        """Test custom configuration."""
        config = FuzzConfig(
            num_tests=50,
            timeout=10,
            seed=42,
            input_types=["random", "binary"],
        )

        assert config.num_tests == 50
        assert config.timeout == 10
        assert config.seed == 42
        assert len(config.input_types) == 2


class TestFuzzTestCase:
    """Tests for FuzzTestCase."""

    def test_test_case_creation(self):
        """Test creating a fuzz test case."""
        test_case = FuzzTestCase(
            test_id="test_001",
            input_data=b"test input",
            input_type="ascii",
            args=["arg1", "arg2"],
            env={"TEST": "value"},
            description="Test case description",
        )

        assert test_case.test_id == "test_001"
        assert test_case.input_data == b"test input"
        assert test_case.input_type == "ascii"
        assert len(test_case.args) == 2
        assert test_case.env["TEST"] == "value"


class TestFuzzResult:
    """Tests for FuzzResult."""

    def test_passed_result(self):
        """Test a passed result."""
        result = FuzzResult(
            test_id="test_001",
            passed=True,
            original_exit_code=0,
            mutated_exit_code=0,
            original_output_hash="abcd1234",
            mutated_output_hash="abcd1234",
            original_error=None,
            mutated_error=None,
            execution_time_ms=100.0,
            crash=False,
            timeout=False,
            mutation_count=5,
            mutation_names=["nop", "substitute"],
        )

        assert result.passed is True
        assert result.crash is False
        assert result.timeout is False

    def test_crash_result(self):
        """Test a crash result."""
        result = FuzzResult(
            test_id="test_002",
            passed=False,
            original_exit_code=0,
            mutated_exit_code=-11,
            original_output_hash="abcd1234",
            mutated_output_hash="efgh5678",
            original_error=None,
            mutated_error="Segmentation fault",
            execution_time_ms=50.0,
            crash=True,
            timeout=False,
            mutation_count=5,
            mutation_names=["nop", "substitute"],
        )

        assert result.passed is False
        assert result.crash is True


class TestFuzzCampaignResult:
    """Tests for FuzzCampaignResult."""

    def test_campaign_result(self):
        """Test campaign result."""
        result = FuzzCampaignResult(
            total_tests=100,
            passed=95,
            failed=5,
            crashes=2,
            timeouts=1,
            results=[],
            seed=42,
            config=FuzzConfig(),
            start_time="2024-01-01T00:00:00",
            end_time="2024-01-01T00:05:00",
            duration_seconds=300.0,
        )

        assert result.total_tests == 100
        assert result.success_rate == 95.0

    def test_to_dict(self):
        """Test converting to dictionary."""
        result = FuzzCampaignResult(
            total_tests=10,
            passed=9,
            failed=1,
            crashes=0,
            timeouts=0,
            results=[],
            seed=123,
            config=FuzzConfig(),
            start_time="2024-01-01T00:00:00",
            end_time="2024-01-01T00:01:00",
            duration_seconds=60.0,
        )

        data = result.to_dict()

        assert data["total_tests"] == 10
        assert data["passed"] == 9
        assert data["seed"] == 123


class TestMutationPassFuzzer:
    """Tests for MutationPassFuzzer."""

    def test_initialization(self):
        """Test fuzzer initialization."""
        fuzzer = MutationPassFuzzer()

        assert fuzzer.config.num_tests == 100
        assert fuzzer.config.timeout == 5

    def test_initialization_with_config(self):
        """Test fuzzer with custom config."""
        config = FuzzConfig(num_tests=50, timeout=10, seed=42)
        fuzzer = MutationPassFuzzer(config)

        assert fuzzer.config.num_tests == 50
        assert fuzzer.config.timeout == 10
        assert fuzzer.config.seed == 42

    def test_generate_random_input(self):
        """Test random input generation."""
        config = FuzzConfig(seed=42)
        fuzzer = MutationPassFuzzer(config)

        input_data = fuzzer._generate_random_input(100)

        assert len(input_data) <= 100
        assert isinstance(input_data, bytes)

    def test_generate_ascii_input(self):
        """Test ASCII input generation."""
        config = FuzzConfig(seed=42)
        fuzzer = MutationPassFuzzer(config)

        input_data = fuzzer._generate_ascii_input(100)
        decoded = input_data.decode("ascii", errors="replace")

        assert all(c.isprintable() or c in "\n\r\t\x0b\x0c" for c in decoded)

    def test_generate_binary_input(self):
        """Test binary input generation."""
        config = FuzzConfig(seed=42)
        fuzzer = MutationPassFuzzer(config)

        input_data = fuzzer._generate_binary_input(100)

        assert isinstance(input_data, bytes)
        assert len(input_data) == 100

    def test_generate_structured_input(self):
        """Test structured input generation."""
        config = FuzzConfig(seed=42)
        fuzzer = MutationPassFuzzer(config)

        input_data = fuzzer._generate_structured_input(100)

        assert isinstance(input_data, bytes)
        assert len(input_data) > 0

    def test_generate_edge_case_input(self):
        """Test edge case input generation."""
        config = FuzzConfig(seed=42)
        fuzzer = MutationPassFuzzer(config)

        input_data = fuzzer._generate_edge_case_input(100)

        assert isinstance(input_data, bytes)

    def test_generate_test_case(self):
        """Test test case generation."""
        config = FuzzConfig(seed=42)
        fuzzer = MutationPassFuzzer(config)

        test_case = fuzzer.generate_test_case(0)

        assert test_case.test_id == "fuzz_0000"
        assert isinstance(test_case.input_data, bytes)
        assert isinstance(test_case.args, list)


class TestContinuousFuzzer:
    """Tests for ContinuousFuzzer."""

    def test_initialization(self):
        """Test continuous fuzzer initialization."""
        fuzzer = ContinuousFuzzer()

        assert fuzzer.config.num_tests == 100
        assert len(fuzzer.campaign_history) == 0

    def test_get_statistics(self):
        """Test getting statistics."""
        fuzzer = ContinuousFuzzer()

        stats = fuzzer.get_statistics()

        assert stats["campaigns"] == 0
        assert "avg_success_rate" not in stats or stats.get("avg_success_rate", 0) == 0


class TestPerformanceBenchmark:
    """Tests for PerformanceBenchmark."""

    def test_initialization(self):
        """Test benchmark initialization."""
        benchmark = PerformanceBenchmark()

        assert benchmark.config.warmup_runs == 3
        assert benchmark.config.measured_runs == 10
        assert benchmark.baseline_dir.exists()

    def test_custom_config(self):
        """Test benchmark with custom config."""
        config = BenchmarkConfig(
            warmup_runs=2,
            measured_runs=5,
            regression_threshold_percent=15.0,
        )
        benchmark = PerformanceBenchmark(config)

        assert benchmark.config.warmup_runs == 2
        assert benchmark.config.measured_runs == 5

    def test_get_environment_info(self):
        """Test environment info extraction."""
        benchmark = PerformanceBenchmark()

        env = benchmark._get_environment_info()

        assert "python_version" in env
        assert "platform" in env
        assert "cpu_count" in env


class TestPerformanceSnapshot:
    """Tests for PerformanceSnapshot."""

    def test_snapshot_creation(self):
        """Test creating a snapshot."""
        snapshot = PerformanceSnapshot(
            commit_hash="abc123",
            timestamp="2024-01-01T00:00:00",
            metrics={
                "execution_time_ms_mean": 100.5,
                "peak_memory_mb": 50.2,
            },
            environment={"platform": "linux"},
            metadata={"test": "value"},
        )

        assert snapshot.commit_hash == "abc123"
        assert "execution_time_ms_mean" in snapshot.metrics
        assert snapshot.metadata["test"] == "value"

    def test_to_dict(self):
        """Test converting to dictionary."""
        snapshot = PerformanceSnapshot(
            commit_hash="abc123",
            timestamp="2024-01-01T00:00:00",
            metrics={"time": 100.0},
            environment={"platform": "linux"},
        )

        data = snapshot.to_dict()

        assert data["commit_hash"] == "abc123"
        assert "metrics" in data


class TestMemoryLeakDetector:
    """Tests for MemoryLeakDetector."""

    def test_initialization(self):
        """Test detector initialization."""
        detector = MemoryLeakDetector()

        assert detector.threshold_mb == 10.0
        assert detector.object_growth_threshold == 1000

    def test_custom_thresholds(self):
        """Test detector with custom thresholds."""
        detector = MemoryLeakDetector(
            threshold_mb=50.0,
            object_growth_threshold=500,
        )

        assert detector.threshold_mb == 50.0
        assert detector.object_growth_threshold == 500

    def test_take_snapshot(self):
        """Test taking a memory snapshot."""
        detector = MemoryLeakDetector(enable_tracing=False)

        snapshot = detector._take_snapshot()

        assert snapshot.timestamp > 0
        assert isinstance(snapshot.object_count, int)
        assert isinstance(snapshot.gc_gen0, int)

    def test_detect_no_leaks(self):
        """Test detecting no leaks."""
        detector = MemoryLeakDetector()

        snapshots = [
            MemorySnapshot(
                timestamp=1.0,
                current_memory_bytes=1000000,
                peak_memory_bytes=1500000,
                object_count=1000,
                gc_gen0=100,
                gc_gen1=50,
                gc_gen2=10,
                tracer_running=False,
            ),
            MemorySnapshot(
                timestamp=2.0,
                current_memory_bytes=1100000,
                peak_memory_bytes=1600000,
                object_count=1050,
                gc_gen0=105,
                gc_gen1=52,
                gc_gen2=11,
                tracer_running=False,
            ),
        ]

        result = detector.detect_leaks(snapshots, "test_func")

        assert result.passed is True
        assert result.leaks_detected == 0

    def test_detect_memory_leak(self):
        """Test detecting memory leak."""
        detector = MemoryLeakDetector(threshold_mb=1.0)

        snapshots = [
            MemorySnapshot(
                timestamp=1.0,
                current_memory_bytes=1000000,
                peak_memory_bytes=1500000,
                object_count=1000,
                gc_gen0=100,
                gc_gen1=50,
                gc_gen2=10,
                tracer_running=False,
            ),
            MemorySnapshot(
                timestamp=2.0,
                current_memory_bytes=5000000,
                peak_memory_bytes=5500000,
                object_count=1050,
                gc_gen0=105,
                gc_gen1=52,
                gc_gen2=11,
                tracer_running=False,
            ),
        ]

        result = detector.detect_leaks(snapshots, "test_func")

        assert result.passed is False
        assert result.leaks_detected > 0


class TestObjectTracker:
    """Tests for ObjectTracker."""

    def test_track_objects(self):
        """Test tracking objects."""
        tracker = ObjectTracker()
        tracker.start_tracking()

        class TestObject:
            pass

        obj = TestObject()
        tracker.track_object(obj)

        count = tracker.get_tracked_count()

        tracker.stop_tracking()

        assert count >= 0


class TestResourceLeakDetector:
    """Tests for ResourceLeakDetector."""

    def test_initialization(self):
        """Test resource leak detector initialization."""
        detector = ResourceLeakDetector()

        assert detector._initial_resources == {}
        assert detector._final_resources == {}

    def test_no_resource_leaks(self):
        """Test when there are no resource leaks."""
        detector = ResourceLeakDetector()

        def clean_function():
            pass

        detector.start_monitoring()
        clean_function()
        result = detector.stop_monitoring()

        critical_leaks = [
            l
            for l in result.resource_leaks
            if l.resource_type in ("file_descriptors", "open_files", "open_connections")
        ]
        assert len(critical_leaks) == 0 or all(l.leaked_count <= 10 for l in critical_leaks)


class TestDataclasses:
    """Tests for dataclass structures."""

    def test_performance_metric(self):
        """Test PerformanceMetric dataclass."""
        metric = PerformanceMetric(
            name="execution_time",
            value=100.5,
            unit="ms",
            timestamp="2024-01-01T00:00:00",
            sample_size=10,
        )

        assert metric.name == "execution_time"
        assert metric.value == 100.5
        assert metric.unit == "ms"

    def test_performance_regression(self):
        """Test PerformanceRegression dataclass."""
        regression = PerformanceRegression(
            metric_name="execution_time",
            baseline_value=100.0,
            current_value=150.0,
            threshold=20.0,
            percentage_change=50.0,
            severity="major",
        )

        assert regression.metric_name == "execution_time"
        assert regression.severity == "major"

    def test_memory_leak(self):
        """Test MemoryLeak dataclass."""
        leak = MemoryLeak(
            leak_type="memory_growth",
            description="Memory leak detected",
            initial_memory_mb=10.0,
            final_memory_mb=50.0,
            memory_growth_mb=40.0,
            initial_objects=1000,
            final_objects=5000,
            object_growth=4000,
        )

        assert leak.leak_type == "memory_growth"
        assert leak.memory_growth_mb == 40.0

    def test_resource_leak(self):
        """Test ResourceLeak dataclass."""
        leak = ResourceLeak(
            resource_type="file_descriptors",
            description="File descriptor leak",
            initial_count=10,
            final_count=15,
            leaked_count=5,
        )

        assert leak.resource_type == "file_descriptors"
        assert leak.leaked_count == 5


class TestFactoryFunctions:
    """Tests for factory functions."""

    def test_create_fuzzer(self):
        """Test fuzzer factory function."""
        fuzzer = create_fuzzer(num_tests=50, timeout=10, seed=42)

        assert fuzzer.config.num_tests == 50
        assert fuzzer.config.timeout == 10
        assert fuzzer.config.seed == 42

    def test_create_continuous_fuzzer(self):
        """Test continuous fuzzer factory function."""
        fuzzer = create_continuous_fuzzer(num_tests=50, timeout=10)

        assert fuzzer.config.num_tests == 50
        assert fuzzer.config.timeout == 10

    def test_create_benchmark(self):
        """Test benchmark factory function."""
        benchmark = create_benchmark(
            warmup_runs=2,
            measured_runs=5,
            regression_threshold=15.0,
        )

        assert benchmark.config.warmup_runs == 2
        assert benchmark.config.measured_runs == 5
        assert benchmark.config.regression_threshold_percent == 15.0

    def test_create_memory_detector(self):
        """Test memory detector factory function."""
        detector = create_memory_detector(threshold_mb=20.0, object_threshold=500)

        assert detector.threshold_mb == 20.0
        assert detector.object_growth_threshold == 500
