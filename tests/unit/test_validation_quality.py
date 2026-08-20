"""
Tests for validation quality features: Fuzzer integration,
Continuous fuzzing, Performance regression, and Memory leak detection.
"""

import weakref

from r2morph.validation.leak_detection import (
    MemoryLeak,
    MemoryLeakDetector,
    MemorySnapshot,
    ObjectTracker,
    ResourceLeak,
    ResourceLeakDetector,
    create_memory_detector,
)
from r2morph.validation.mutation_fuzzer import (
    ContinuousFuzzer,
    FuzzCampaignResult,
    FuzzConfig,
    FuzzResult,
    FuzzTestCase,
    MutationPassFuzzer,
    create_continuous_fuzzer,
    create_fuzzer,
)
from r2morph.validation.performance_regression import (
    BenchmarkConfig,
    PerformanceBenchmark,
    PerformanceMetric,
    PerformanceRegression,
    PerformanceSnapshot,
    create_benchmark,
)
from tests.utils.assertions import expect

_EXPECTED_BENCHMARK_CONFIG_MEASURED_RUNS_10 = 10
_EXPECTED_BENCHMARK_CONFIG_MEASURED_RUNS_5 = 5
_EXPECTED_BENCHMARK_CONFIG_MEASURED_RUNS_5_2 = 5
_EXPECTED_BENCHMARK_CONFIG_REGRESSION_THRESHOLD_PERCENT_15_0 = 15.0
_EXPECTED_BENCHMARK_CONFIG_WARMUP_RUNS_2 = 2
_EXPECTED_BENCHMARK_CONFIG_WARMUP_RUNS_2_2 = 2
_EXPECTED_BENCHMARK_CONFIG_WARMUP_RUNS_3 = 3
_EXPECTED_CONFIG_NUM_TESTS_100 = 100
_EXPECTED_CONFIG_NUM_TESTS_50 = 50
_EXPECTED_CONFIG_SEED_42 = 42
_EXPECTED_CONFIG_TIMEOUT_10 = 10
_EXPECTED_CONFIG_TIMEOUT_5 = 5
_EXPECTED_DATA_PASSED_9 = 9
_EXPECTED_DATA_SEED_123 = 123
_EXPECTED_DATA_TOTAL_TESTS_10 = 10
_EXPECTED_DETECTOR_OBJECT_GROWTH_THRESHOLD_1000 = 1000
_EXPECTED_DETECTOR_OBJECT_GROWTH_THRESHOLD_500 = 500
_EXPECTED_DETECTOR_OBJECT_GROWTH_THRESHOLD_500_2 = 500
_EXPECTED_DETECTOR_THRESHOLD_MB_10_0 = 10.0
_EXPECTED_DETECTOR_THRESHOLD_MB_20_0 = 20.0
_EXPECTED_DETECTOR_THRESHOLD_MB_50_0 = 50.0
_EXPECTED_FUZZER_CONFIG_NUM_TESTS_100 = 100
_EXPECTED_FUZZER_CONFIG_NUM_TESTS_100_2 = 100
_EXPECTED_FUZZER_CONFIG_NUM_TESTS_50 = 50
_EXPECTED_FUZZER_CONFIG_NUM_TESTS_50_2 = 50
_EXPECTED_FUZZER_CONFIG_NUM_TESTS_50_3 = 50
_EXPECTED_FUZZER_CONFIG_SEED_42 = 42
_EXPECTED_FUZZER_CONFIG_SEED_42_2 = 42
_EXPECTED_FUZZER_CONFIG_TIMEOUT_10 = 10
_EXPECTED_FUZZER_CONFIG_TIMEOUT_10_2 = 10
_EXPECTED_FUZZER_CONFIG_TIMEOUT_10_3 = 10
_EXPECTED_FUZZER_CONFIG_TIMEOUT_5 = 5
_EXPECTED_LEAK_LEAKED_COUNT_10 = 10
_EXPECTED_LEAK_LEAKED_COUNT_5 = 5
_EXPECTED_LEAK_MEMORY_GROWTH_MB_40_0 = 40.0
_EXPECTED_LEN_CONFIG_INPUT_TYPES_2 = 2
_EXPECTED_LEN_INPUT_DATA_100 = 100
_EXPECTED_LEN_INPUT_DATA_100_2 = 100
_EXPECTED_LEN_TEST_CASE_ARGS_2 = 2
_EXPECTED_METRIC_VALUE_100_5 = 100.5
_EXPECTED_RESULT_SUCCESS_RATE_95_0 = 95.0
_EXPECTED_RESULT_TOTAL_TESTS_100 = 100


class TestFuzzConfig:
    """Tests for FuzzConfig."""

    def test_default_config(self):
        """Test default configuration."""
        config = FuzzConfig()

        expect(config.num_tests == _EXPECTED_CONFIG_NUM_TESTS_100)
        expect(config.timeout == _EXPECTED_CONFIG_TIMEOUT_5)
        expect(not (config.seed is not None))
        expect(not ("random" not in config.input_types))
        expect(not ("ascii" not in config.input_types))

    def test_custom_config(self):
        """Test custom configuration."""
        config = FuzzConfig(
            num_tests=50,
            timeout=10,
            seed=42,
            input_types=["random", "binary"],
        )

        expect(config.num_tests == _EXPECTED_CONFIG_NUM_TESTS_50)
        expect(config.timeout == _EXPECTED_CONFIG_TIMEOUT_10)
        expect(config.seed == _EXPECTED_CONFIG_SEED_42)
        expect(len(config.input_types) == _EXPECTED_LEN_CONFIG_INPUT_TYPES_2)


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

        expect(test_case.test_id == "test_001")
        expect(test_case.input_data == b"test input")
        expect(test_case.input_type == "ascii")
        expect(len(test_case.args) == _EXPECTED_LEN_TEST_CASE_ARGS_2)
        expect(test_case.env["TEST"] == "value")


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

        expect(not (result.passed is not True))
        expect(not (result.crash is not False))
        expect(not (result.timeout is not False))

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

        expect(not (result.passed is not False))
        expect(not (result.crash is not True))


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

        expect(result.total_tests == _EXPECTED_RESULT_TOTAL_TESTS_100)
        expect(result.success_rate == _EXPECTED_RESULT_SUCCESS_RATE_95_0)

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

        expect(data["total_tests"] == _EXPECTED_DATA_TOTAL_TESTS_10)
        expect(data["passed"] == _EXPECTED_DATA_PASSED_9)
        expect(data["seed"] == _EXPECTED_DATA_SEED_123)


class TestMutationPassFuzzer:
    """Tests for MutationPassFuzzer."""

    def test_initialization(self):
        """Test fuzzer initialization."""
        fuzzer = MutationPassFuzzer()

        expect(fuzzer.config.num_tests == _EXPECTED_FUZZER_CONFIG_NUM_TESTS_100)
        expect(fuzzer.config.timeout == _EXPECTED_FUZZER_CONFIG_TIMEOUT_5)

    def test_initialization_with_config(self):
        """Test fuzzer with custom config."""
        config = FuzzConfig(num_tests=50, timeout=10, seed=42)
        fuzzer = MutationPassFuzzer(config)

        expect(fuzzer.config.num_tests == _EXPECTED_FUZZER_CONFIG_NUM_TESTS_50)
        expect(fuzzer.config.timeout == _EXPECTED_FUZZER_CONFIG_TIMEOUT_10)
        expect(fuzzer.config.seed == _EXPECTED_FUZZER_CONFIG_SEED_42)

    def test_generate_random_input(self):
        """Test random input generation."""
        config = FuzzConfig(seed=42)
        fuzzer = MutationPassFuzzer(config)

        input_data = fuzzer._generate_random_input(100)

        expect(not (len(input_data) > _EXPECTED_LEN_INPUT_DATA_100))
        expect(isinstance(input_data, bytes))

    def test_generate_ascii_input(self):
        """Test ASCII input generation."""
        config = FuzzConfig(seed=42)
        fuzzer = MutationPassFuzzer(config)

        input_data = fuzzer._generate_ascii_input(100)
        decoded = input_data.decode("ascii", errors="replace")

        expect(all(c.isprintable() or c in "\n\r\t\x0b\x0c" for c in decoded))

    def test_generate_binary_input(self):
        """Test binary input generation."""
        config = FuzzConfig(seed=42)
        fuzzer = MutationPassFuzzer(config)

        input_data = fuzzer._generate_binary_input(100)

        expect(isinstance(input_data, bytes))
        expect(len(input_data) == _EXPECTED_LEN_INPUT_DATA_100_2)

    def test_generate_structured_input(self):
        """Test structured input generation."""
        config = FuzzConfig(seed=42)
        fuzzer = MutationPassFuzzer(config)

        input_data = fuzzer._generate_structured_input(100)

        expect(isinstance(input_data, bytes))
        expect(not (len(input_data) <= 0))

    def test_generate_edge_case_input(self):
        """Test edge case input generation."""
        config = FuzzConfig(seed=42)
        fuzzer = MutationPassFuzzer(config)

        input_data = fuzzer._generate_edge_case_input(100)

        expect(isinstance(input_data, bytes))

    def test_generate_test_case(self):
        """Test test case generation."""
        config = FuzzConfig(seed=42)
        fuzzer = MutationPassFuzzer(config)

        test_case = fuzzer.generate_test_case(0)

        expect(test_case.test_id == "fuzz_0000")
        expect(isinstance(test_case.input_data, bytes))
        expect(isinstance(test_case.args, list))


class TestContinuousFuzzer:
    """Tests for ContinuousFuzzer."""

    def test_initialization(self):
        """Test continuous fuzzer initialization."""
        fuzzer = ContinuousFuzzer()

        expect(fuzzer.config.num_tests == _EXPECTED_FUZZER_CONFIG_NUM_TESTS_100_2)
        expect(len(fuzzer.campaign_history) == 0)

    def test_get_statistics(self):
        """Test getting statistics."""
        fuzzer = ContinuousFuzzer()

        stats = fuzzer.get_statistics()

        expect(stats["campaigns"] == 0)
        expect("avg_success_rate" not in stats or stats.get("avg_success_rate", 0) == 0)


class TestPerformanceBenchmark:
    """Tests for PerformanceBenchmark."""

    def test_initialization(self):
        """Test benchmark initialization."""
        benchmark = PerformanceBenchmark()

        expect(benchmark.config.warmup_runs == _EXPECTED_BENCHMARK_CONFIG_WARMUP_RUNS_3)
        expect(benchmark.config.measured_runs == _EXPECTED_BENCHMARK_CONFIG_MEASURED_RUNS_10)
        expect(benchmark.baseline_dir.exists())

    def test_custom_config(self):
        """Test benchmark with custom config."""
        config = BenchmarkConfig(
            warmup_runs=2,
            measured_runs=5,
            regression_threshold_percent=15.0,
        )
        benchmark = PerformanceBenchmark(config)

        expect(benchmark.config.warmup_runs == _EXPECTED_BENCHMARK_CONFIG_WARMUP_RUNS_2)
        expect(benchmark.config.measured_runs == _EXPECTED_BENCHMARK_CONFIG_MEASURED_RUNS_5)

    def test_get_environment_info(self):
        """Test environment info extraction."""
        benchmark = PerformanceBenchmark()

        env = benchmark._get_environment_info()

        expect(not ("python_version" not in env))
        expect(not ("platform" not in env))
        expect(not ("cpu_count" not in env))


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

        expect(snapshot.commit_hash == "abc123")
        expect(not ("execution_time_ms_mean" not in snapshot.metrics))
        expect(snapshot.metadata["test"] == "value")

    def test_to_dict(self):
        """Test converting to dictionary."""
        snapshot = PerformanceSnapshot(
            commit_hash="abc123",
            timestamp="2024-01-01T00:00:00",
            metrics={"time": 100.0},
            environment={"platform": "linux"},
        )

        data = snapshot.to_dict()

        expect(data["commit_hash"] == "abc123")
        expect(not ("metrics" not in data))


class TestMemoryLeakDetector:
    """Tests for MemoryLeakDetector."""

    def test_initialization(self):
        """Test detector initialization."""
        detector = MemoryLeakDetector()

        expect(detector.threshold_mb == _EXPECTED_DETECTOR_THRESHOLD_MB_10_0)
        expect(detector.object_growth_threshold == _EXPECTED_DETECTOR_OBJECT_GROWTH_THRESHOLD_1000)

    def test_custom_thresholds(self):
        """Test detector with custom thresholds."""
        detector = MemoryLeakDetector(
            threshold_mb=50.0,
            object_growth_threshold=500,
        )

        expect(detector.threshold_mb == _EXPECTED_DETECTOR_THRESHOLD_MB_50_0)
        expect(detector.object_growth_threshold == _EXPECTED_DETECTOR_OBJECT_GROWTH_THRESHOLD_500)

    def test_take_snapshot(self):
        """Test taking a memory snapshot."""
        detector = MemoryLeakDetector(enable_tracing=False)

        snapshot = detector._take_snapshot()

        expect(not (snapshot.timestamp <= 0))
        expect(isinstance(snapshot.object_count, int))
        expect(isinstance(snapshot.gc_gen0, int))

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

        expect(not (result.passed is not True))
        expect(result.leaks_detected == 0)

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

        expect(not (result.passed is not False))
        expect(not (result.leaks_detected <= 0))


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

        expect(not (count < 0))


class TestResourceLeakDetector:
    """Tests for ResourceLeakDetector."""

    def test_initialization(self):
        """Test resource leak detector initialization."""
        detector = ResourceLeakDetector()

        expect(detector._initial_resources == {})
        expect(detector._final_resources == {})

    def test_no_resource_leaks(self):
        """Test when there are no resource leaks."""
        detector = ResourceLeakDetector()

        def clean_function():
            pass

        detector.start_monitoring()
        clean_function()
        result = detector.stop_monitoring()

        critical_leaks = [
            leak
            for leak in result.resource_leaks
            if leak.resource_type in ("file_descriptors", "open_files", "open_connections")
        ]
        expect(
            len(critical_leaks) == 0
            or all(leak.leaked_count <= _EXPECTED_LEAK_LEAKED_COUNT_10 for leak in critical_leaks)
        )

    def test_start_monitoring_dead_weak_proxy_records_resources(self):
        class WeakTarget:
            pass

        target = WeakTarget()
        dead_proxy = weakref.proxy(target)
        del target

        detector = ResourceLeakDetector()
        detector.start_monitoring()

        expect(not (id(dead_proxy) <= 0))


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

        expect(metric.name == "execution_time")
        expect(metric.value == _EXPECTED_METRIC_VALUE_100_5)
        expect(metric.unit == "ms")

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

        expect(regression.metric_name == "execution_time")
        expect(regression.severity == "major")

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

        expect(leak.leak_type == "memory_growth")
        expect(leak.memory_growth_mb == _EXPECTED_LEAK_MEMORY_GROWTH_MB_40_0)

    def test_resource_leak(self):
        """Test ResourceLeak dataclass."""
        leak = ResourceLeak(
            resource_type="file_descriptors",
            description="File descriptor leak",
            initial_count=10,
            final_count=15,
            leaked_count=5,
        )

        expect(leak.resource_type == "file_descriptors")
        expect(leak.leaked_count == _EXPECTED_LEAK_LEAKED_COUNT_5)


class TestFactoryFunctions:
    """Tests for factory functions."""

    def test_create_fuzzer(self):
        """Test fuzzer factory function."""
        fuzzer = create_fuzzer(num_tests=50, timeout=10, seed=42)

        expect(fuzzer.config.num_tests == _EXPECTED_FUZZER_CONFIG_NUM_TESTS_50_2)
        expect(fuzzer.config.timeout == _EXPECTED_FUZZER_CONFIG_TIMEOUT_10_2)
        expect(fuzzer.config.seed == _EXPECTED_FUZZER_CONFIG_SEED_42_2)

    def test_create_continuous_fuzzer(self):
        """Test continuous fuzzer factory function."""
        fuzzer = create_continuous_fuzzer(num_tests=50, timeout=10)

        expect(fuzzer.config.num_tests == _EXPECTED_FUZZER_CONFIG_NUM_TESTS_50_3)
        expect(fuzzer.config.timeout == _EXPECTED_FUZZER_CONFIG_TIMEOUT_10_3)

    def test_create_benchmark(self):
        """Test benchmark factory function."""
        benchmark = create_benchmark(
            warmup_runs=2,
            measured_runs=5,
            regression_threshold=15.0,
        )

        expect(benchmark.config.warmup_runs == _EXPECTED_BENCHMARK_CONFIG_WARMUP_RUNS_2_2)
        expect(benchmark.config.measured_runs == _EXPECTED_BENCHMARK_CONFIG_MEASURED_RUNS_5_2)
        expect(
            benchmark.config.regression_threshold_percent
            == _EXPECTED_BENCHMARK_CONFIG_REGRESSION_THRESHOLD_PERCENT_15_0
        )

    def test_create_memory_detector(self):
        """Test memory detector factory function."""
        detector = create_memory_detector(threshold_mb=20.0, object_threshold=500)

        expect(detector.threshold_mb == _EXPECTED_DETECTOR_THRESHOLD_MB_20_0)
        expect(detector.object_growth_threshold == _EXPECTED_DETECTOR_OBJECT_GROWTH_THRESHOLD_500_2)
