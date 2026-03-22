"""
Fuzzer integration with mutation passes.

Provides fuzz testing capabilities integrated with the mutation pipeline
to discover edge cases and validate mutation correctness.
"""

import hashlib
import json
import logging
import random
import statistics
import tempfile
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class FuzzConfig:
    """Configuration for fuzzer."""

    num_tests: int = 100
    timeout: int = 5
    seed: int | None = None
    input_types: list[str] = field(default_factory=lambda: ["random", "ascii", "structured"])
    max_input_size: int = 4096
    min_input_size: int = 0
    crash_on_error: bool = False
    save_failing_cases: bool = True
    output_dir: str = "fuzz_results"


@dataclass
class FuzzTestCase:
    """A single fuzz test case."""

    test_id: str
    input_data: bytes
    input_type: str
    args: list[str]
    env: dict[str, str]
    description: str


@dataclass
class FuzzResult:
    """Result of a single fuzz test."""

    test_id: str
    passed: bool
    original_exit_code: int
    mutated_exit_code: int
    original_output_hash: str
    mutated_output_hash: str
    original_error: str | None
    mutated_error: str | None
    execution_time_ms: float
    crash: bool
    timeout: bool
    mutation_count: int
    mutation_names: list[str]


@dataclass
class FuzzCampaignResult:
    """Result of a complete fuzz campaign."""

    total_tests: int
    passed: int
    failed: int
    crashes: int
    timeouts: int
    results: list[FuzzResult]
    seed: int
    config: FuzzConfig
    start_time: str
    end_time: str
    duration_seconds: float

    @property
    def success_rate(self) -> float:
        return (self.passed / self.total_tests * 100) if self.total_tests > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_tests": self.total_tests,
            "passed": self.passed,
            "failed": self.failed,
            "crashes": self.crashes,
            "timeouts": self.timeouts,
            "success_rate": f"{self.success_rate:.2f}%",
            "seed": self.seed,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "results": [asdict(r) for r in self.results],
        }


class MutationPassFuzzer:
    """
    Fuzz testing integrated with mutation passes.

    Generates random inputs and validates that mutations preserve
    program behavior for each input.
    """

    def __init__(self, config: FuzzConfig | None = None) -> None:
        """
        Initialize the mutation pass fuzzer.

        Args:
            config: Fuzzer configuration
        """
        self.config = config or FuzzConfig()

        if self.config.seed is not None:
            random.seed(self.config.seed)

        self.test_case_generators = {
            "random": self._generate_random_input,
            "ascii": self._generate_ascii_input,
            "binary": self._generate_binary_input,
            "structured": self._generate_structured_input,
            "edge_case": self._generate_edge_case_input,
            "format_string": self._generate_format_string_input,
            "path_like": self._generate_path_like_input,
        }

    def _generate_random_input(self, size_hint: int) -> bytes:
        """Generate random binary input."""
        size = size_hint or random.randint(self.config.min_input_size, self.config.max_input_size)
        return bytes(random.randint(0, 255) for _ in range(size))

    def _generate_ascii_input(self, size_hint: int) -> bytes:
        """Generate printable ASCII input."""
        import string

        size = size_hint or random.randint(self.config.min_input_size, min(self.config.max_input_size, 1024))
        chars = string.printable
        return "".join(random.choice(chars) for _ in range(size)).encode()

    def _generate_binary_input(self, size_hint: int) -> bytes:
        """Generate structured binary input."""
        size = size_hint or random.randint(self.config.min_input_size, min(self.config.max_input_size, 512))

        result = bytearray()

        while len(result) < size:
            pattern_type = random.choice(["zeros", "ones", "random", "sequence"])

            if pattern_type == "zeros":
                chunk_size = random.randint(1, min(64, size - len(result)))
                result.extend(b"\x00" * chunk_size)
            elif pattern_type == "ones":
                chunk_size = random.randint(1, min(64, size - len(result)))
                result.extend(b"\xff" * chunk_size)
            elif pattern_type == "sequence":
                chunk_size = random.randint(1, min(64, size - len(result)))
                result.extend(bytes(range(chunk_size)))
            else:
                chunk_size = min(64, size - len(result))
                result.extend(bytes(random.randint(0, 255) for _ in range(chunk_size)))

        return bytes(result[:size])

    def _generate_structured_input(self, size_hint: int) -> bytes:
        """Generate structured input (JSON-like)."""
        structures = [
            lambda: json.dumps({"value": random.randint(0, 1000000)}),
            lambda: json.dumps({"values": [random.randint(0, 100) for _ in range(random.randint(1, 10))]}),
            lambda: json.dumps({"nested": {"a": random.randint(0, 10), "b": random.choice(["x", "y", "z"])}}),
            lambda: json.dumps([random.choice(["a", "b", "c"]) for _ in range(random.randint(1, 5))]),
            lambda: str(random.randint(-1000000, 1000000)),
            lambda: " ".join(str(random.randint(0, 100)) for _ in range(random.randint(1, 10))),
            lambda: ",".join(str(random.random()) for _ in range(random.randint(1, 5))),
        ]

        return random.choice(structures)().encode()

    def _generate_edge_case_input(self, size_hint: int) -> bytes:
        """Generate edge case inputs."""
        edge_cases = [
            b"",
            b"\x00",
            b"\xff",
            b"\x00" * 1000,
            b"\xff" * 1000,
            b"a" * 10000,
            b"\n" * 100,
            b"\r\n" * 50,
            b"\x00\xff" * 500,
            bytes(range(256)),
            bytes(range(255, -1, -1)),
        ]

        return random.choice(edge_cases)

    def _generate_format_string_input(self, size_hint: int) -> bytes:
        """Generate format string inputs."""
        format_patterns = [
            "%s" * random.randint(1, 10),
            "%d" * random.randint(1, 10),
            "%x" * random.randint(1, 10),
            "%n" * random.randint(1, 5),
            "%{0}".format(random.randint(1, 1000)) + "s",
            "AAAA%08x.%08x.%08x.%08x",
            "%p" * random.randint(1, 5),
        ]

        return random.choice(format_patterns).encode()

    def _generate_path_like_input(self, size_hint: int) -> bytes:
        """Generate path-like inputs."""
        import string

        path_chars = string.ascii_letters + string.digits + "/\\._-"

        paths = [
            "/".join(
                "".join(random.choice(path_chars) for _ in range(random.randint(1, 10)))
                for _ in range(random.randint(1, 5))
            ),
            "\\".join(
                "".join(random.choice(path_chars) for _ in range(random.randint(1, 10)))
                for _ in range(random.randint(1, 5))
            ),
            "C:\\" + "".join(random.choice(path_chars) for _ in range(random.randint(5, 50))),
            tempfile.gettempdir() + "/" + "".join(random.choice(path_chars) for _ in range(random.randint(5, 30))),
            "." * random.randint(1, 10)
            + "/"
            + "".join(random.choice(path_chars) for _ in range(random.randint(5, 20))),
            ".." * random.randint(1, 20),
        ]

        return random.choice(paths).encode()

    def generate_test_case(self, index: int) -> FuzzTestCase:
        """
        Generate a fuzz test case.

        Args:
            index: Test case index

        Returns:
            FuzzTestCase
        """
        input_type = random.choice(list(self.test_case_generators.keys()))
        size_hint = random.randint(self.config.min_input_size, self.config.max_input_size)

        input_data = self.test_case_generators[input_type](size_hint)

        num_args = random.randint(0, 5)
        args = [
            "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(random.randint(1, 20)))
            for _ in range(num_args)
        ]

        env = {}
        if random.random() < 0.3:
            env["FUZZ_ENV"] = "test"

        return FuzzTestCase(
            test_id=f"fuzz_{index:04d}",
            input_data=input_data,
            input_type=input_type,
            args=args,
            env=env,
            description=f"Fuzz test case {index} ({input_type})",
        )

    def fuzz_mutations(
        self,
        original_path: Path,
        mutated_path: Path,
        mutation_names: list[str],
        output_dir: Path | None = None,
    ) -> FuzzCampaignResult:
        """
        Fuzz test mutations against original binary.

        Args:
            original_path: Path to original binary
            mutated_path: Path to mutated binary
            mutation_names: List of mutation pass names
            output_dir: Directory to save failing cases

        Returns:
            FuzzCampaignResult
        """
        import subprocess
        from r2morph.validation.validator import BinaryValidator

        start_time = time.time()
        results: list[FuzzResult] = []

        if output_dir is None and self.config.save_failing_cases:
            output_dir = Path(self.config.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)

        passed = 0
        failed = 0
        crashes = 0
        timeouts = 0

        seed = self.config.seed or random.randint(0, 2**32 - 1)
        random.seed(seed)

        logger.info(f"Starting fuzz campaign with seed {seed}, {self.config.num_tests} tests")

        for i in range(self.config.num_tests):
            test_case = self.generate_test_case(i)

            try:
                validator = BinaryValidator(timeout=self.config.timeout)
                validator.test_cases = []
                validator.add_test_case(
                    stdin=test_case.input_data.decode(errors="replace"),
                    args=test_case.args,
                    description=test_case.description,
                )

                start_exec = time.perf_counter()
                result = validator.validate(original_path, mutated_path)
                execution_time_ms = (time.perf_counter() - start_exec) * 1000

                fuzz_result = FuzzResult(
                    test_id=test_case.test_id,
                    passed=result.passed,
                    original_exit_code=result.original_exitcode,
                    mutated_exit_code=result.mutated_exitcode,
                    original_output_hash=hashlib.sha256(result.original_output.encode()).hexdigest()[:16],
                    mutated_output_hash=hashlib.sha256(result.mutated_output.encode()).hexdigest()[:16],
                    original_error=result.to_dict().get("original_error", ""),
                    mutated_error=result.to_dict().get("mutated_error", ""),
                    execution_time_ms=execution_time_ms,
                    crash=result.mutated_exitcode < 0 and "TIMEOUT" not in result.mutated_output,
                    timeout="TIMEOUT" in result.mutated_output,
                    mutation_count=len(mutation_names),
                    mutation_names=mutation_names,
                )

                if result.passed:
                    passed += 1
                else:
                    failed += 1

                    if self.config.save_failing_cases and output_dir:
                        self._save_failing_case(test_case, fuzz_result, output_dir)

                if fuzz_result.crash:
                    crashes += 1

                if fuzz_result.timeout:
                    timeouts += 1

                results.append(fuzz_result)

            except subprocess.TimeoutExpired:
                timeouts += 1
                failed += 1

                fuzz_result = FuzzResult(
                    test_id=test_case.test_id,
                    passed=False,
                    original_exit_code=-1,
                    mutated_exit_code=-1,
                    original_output_hash="",
                    mutated_output_hash="",
                    original_error="Timeout",
                    mutated_error="Timeout",
                    execution_time_ms=self.config.timeout * 1000,
                    crash=False,
                    timeout=True,
                    mutation_count=len(mutation_names),
                    mutation_names=mutation_names,
                )
                results.append(fuzz_result)

            except Exception as e:
                logger.error(f"Fuzz test {i} failed with exception: {e}")
                failed += 1

                fuzz_result = FuzzResult(
                    test_id=test_case.test_id,
                    passed=False,
                    original_exit_code=-1,
                    mutated_exit_code=-1,
                    original_output_hash="",
                    mutated_output_hash="",
                    original_error=str(e),
                    mutated_error=str(e),
                    execution_time_ms=0,
                    crash=True,
                    timeout=False,
                    mutation_count=len(mutation_names),
                    mutation_names=mutation_names,
                )
                results.append(fuzz_result)

            if (i + 1) % 10 == 0:
                logger.info(f"Progress: {i + 1}/{self.config.num_tests}, Pass rate: {passed}/{i + 1}")

        end_time = time.time()

        return FuzzCampaignResult(
            total_tests=self.config.num_tests,
            passed=passed,
            failed=failed,
            crashes=crashes,
            timeouts=timeouts,
            results=results,
            seed=seed,
            config=self.config,
            start_time=datetime.fromtimestamp(start_time).isoformat(),
            end_time=datetime.fromtimestamp(end_time).isoformat(),
            duration_seconds=end_time - start_time,
        )

    def _save_failing_case(self, test_case: FuzzTestCase, result: FuzzResult, output_dir: Path) -> None:
        """Save a failing test case for later analysis."""
        case_file = output_dir / f"{test_case.test_id}_failure.json"

        failure_data = {
            "test_case": asdict(test_case),
            "result": asdict(result),
        }

        with open(case_file, "w") as f:
            json.dump(failure_data, f, indent=2, default=str)

        logger.debug(f"Saved failing case: {case_file}")


class ContinuousFuzzer:
    """
    Continuous fuzzing framework for regression testing.

    Runs fuzz campaigns periodically and tracks results over time.
    """

    def __init__(self, config: FuzzConfig | None = None) -> None:
        self.config = config or FuzzConfig()
        self.fuzzer = MutationPassFuzzer(self.config)
        self.campaign_history: list[FuzzCampaignResult] = []
        self.regression_threshold = 0.95

    def run_regression_check(
        self,
        original_path: Path,
        mutated_path: Path,
        mutation_names: list[str],
        baseline_result: FuzzCampaignResult | None = None,
    ) -> tuple[bool, FuzzCampaignResult]:
        """
        Run regression check comparing against baseline.

        Args:
            original_path: Original binary path
            mutated_path: Mutated binary path
            mutation_names: List of mutation names
            baseline_result: Optional baseline to compare against

        Returns:
            Tuple of (passed, current_result)
        """
        current_result = self.fuzzer.fuzz_mutations(original_path, mutated_path, mutation_names)

        self.campaign_history.append(current_result)

        if baseline_result is None:
            return True, current_result

        current_rate = current_result.success_rate
        baseline_rate = baseline_result.success_rate

        if current_rate < baseline_rate * self.regression_threshold:
            logger.warning(
                f"Regression detected: success rate dropped from {baseline_rate:.2f}% to {current_rate:.2f}%"
            )
            return False, current_result

        if current_result.crashes > baseline_result.crashes:
            logger.warning(f"More crashes detected: {current_result.crashes} vs baseline {baseline_result.crashes}")
            return False, current_result

        return True, current_result

    def get_statistics(self) -> dict[str, Any]:
        """Get statistics from campaign history."""
        if not self.campaign_history:
            return {"campaigns": 0}

        success_rates = [c.success_rate for c in self.campaign_history]
        crash_counts = [c.crashes for c in self.campaign_history]
        timeout_counts = [c.timeouts for c in self.campaign_history]

        return {
            "campaigns": len(self.campaign_history),
            "avg_success_rate": statistics.mean(success_rates),
            "min_success_rate": min(success_rates),
            "max_success_rate": max(success_rates),
            "total_crashes": sum(crash_counts),
            "total_timeouts": sum(timeout_counts),
            "avg_crashes_per_campaign": statistics.mean(crash_counts),
            "avg_timeouts_per_campaign": statistics.mean(timeout_counts),
            "seeds_used": [c.seed for c in self.campaign_history],
        }


def create_fuzzer(
    num_tests: int = 100,
    timeout: int = 5,
    seed: int | None = None,
) -> MutationPassFuzzer:
    """
    Create a configured mutation pass fuzzer.

    Args:
        num_tests: Number of tests to run
        timeout: Timeout per test in seconds
        seed: Random seed for reproducibility

    Returns:
        MutationPassFuzzer instance
    """
    config = FuzzConfig(
        num_tests=num_tests,
        timeout=timeout,
        seed=seed,
    )
    return MutationPassFuzzer(config)


def create_continuous_fuzzer(
    num_tests: int = 100,
    timeout: int = 5,
) -> ContinuousFuzzer:
    """
    Create a continuous fuzzer for regression testing.

    Args:
        num_tests: Number of tests per campaign
        timeout: Timeout per test in seconds

    Returns:
        ContinuousFuzzer instance
    """
    config = FuzzConfig(num_tests=num_tests, timeout=timeout)
    return ContinuousFuzzer(config)
