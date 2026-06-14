"""
Fuzzer integration with mutation passes.

Provides fuzz testing capabilities integrated with the mutation pipeline
to discover edge cases and validate mutation correctness.
"""

import logging
import random
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from r2morph.validation.mutation_fuzzer_campaign import (
    build_campaign_result,
    build_exception_fuzz_result,
    build_success_fuzz_result,
    build_timeout_fuzz_result,
    save_failing_case,
)
from r2morph.validation.mutation_fuzzer_inputs import (
    generate_ascii_input,
    generate_binary_input,
    generate_edge_case_input,
    generate_format_string_input,
    generate_path_like_input,
    generate_random_input,
    generate_structured_input,
    generate_test_case,
)
from r2morph.validation.mutation_fuzzer_types import (
    FuzzCampaignResult,
    FuzzConfig,
    FuzzResult,
    FuzzTestCase,
)

logger = logging.getLogger(__name__)


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
            "random": lambda size_hint, _self=self: _self._generate_random_input(size_hint),
            "ascii": lambda size_hint, _self=self: _self._generate_ascii_input(size_hint),
            "binary": lambda size_hint, _self=self: _self._generate_binary_input(size_hint),
            "structured": lambda size_hint, _self=self: _self._generate_structured_input(size_hint),
            "edge_case": lambda size_hint, _self=self: _self._generate_edge_case_input(size_hint),
            "format_string": lambda size_hint, _self=self: _self._generate_format_string_input(size_hint),
            "path_like": lambda size_hint, _self=self: _self._generate_path_like_input(size_hint),
        }

    def _generate_random_input(self, size_hint: int) -> bytes:
        """Generate random binary input."""
        return generate_random_input(self.config, size_hint)

    def _generate_ascii_input(self, size_hint: int) -> bytes:
        """Generate printable ASCII input."""
        return generate_ascii_input(self.config, size_hint)

    def _generate_binary_input(self, size_hint: int) -> bytes:
        """Generate structured binary input."""
        return generate_binary_input(self.config, size_hint)

    def _generate_structured_input(self, size_hint: int) -> bytes:
        """Generate structured input (JSON-like)."""
        return generate_structured_input(self.config, size_hint)

    def _generate_edge_case_input(self, size_hint: int) -> bytes:
        """Generate edge case inputs."""
        return generate_edge_case_input(self.config, size_hint)

    def _generate_format_string_input(self, size_hint: int) -> bytes:
        """Generate format string inputs."""
        return generate_format_string_input(self.config, size_hint)

    def _generate_path_like_input(self, size_hint: int) -> bytes:
        """Generate path-like inputs."""
        return generate_path_like_input(self.config, size_hint)

    def generate_test_case(self, index: int) -> FuzzTestCase:
        """
        Generate a fuzz test case.

        Args:
            index: Test case index

        Returns:
            FuzzTestCase
        """
        return generate_test_case(self.config, index)

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

                fuzz_result = build_success_fuzz_result(
                    test_case=test_case,
                    result=result,
                    execution_time_ms=execution_time_ms,
                    mutation_names=mutation_names,
                )

                if result.passed:
                    passed += 1
                else:
                    failed += 1

                    if self.config.save_failing_cases and output_dir:
                        save_failing_case(test_case, fuzz_result, output_dir)

                if fuzz_result.crash:
                    crashes += 1

                if fuzz_result.timeout:
                    timeouts += 1

                results.append(fuzz_result)

            except subprocess.TimeoutExpired:
                timeouts += 1
                failed += 1

                fuzz_result = build_timeout_fuzz_result(
                    test_case=test_case,
                    mutation_names=mutation_names,
                    timeout_seconds=self.config.timeout,
                )
                results.append(fuzz_result)

            except Exception as e:
                logger.error(f"Fuzz test {i} failed with exception: {e}")
                failed += 1

                fuzz_result = build_exception_fuzz_result(
                    test_case=test_case,
                    error=e,
                    mutation_names=mutation_names,
                )
                results.append(fuzz_result)

            if (i + 1) % 10 == 0:
                logger.info(f"Progress: {i + 1}/{self.config.num_tests}, Pass rate: {passed}/{i + 1}")

        end_time = time.time()

        return build_campaign_result(
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


def __getattr__(name: str) -> Any:
    if name == "ContinuousFuzzer":
        from r2morph.validation.mutation_fuzzer_continuous import ContinuousFuzzer as exported

        globals()[name] = exported
        return exported
    if name == "create_continuous_fuzzer":
        from r2morph.validation.mutation_fuzzer_continuous import create_continuous_fuzzer as exported

        globals()[name] = exported
        return exported
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
