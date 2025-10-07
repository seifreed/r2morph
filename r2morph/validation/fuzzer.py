"""
Fuzzer for testing mutated binaries with random inputs.
"""

import logging
import random
import string
from dataclasses import dataclass
from pathlib import Path

from r2morph.validation.validator import BinaryValidator, ValidationResult

logger = logging.getLogger(__name__)


@dataclass
class FuzzResult:
    """Result of fuzzing campaign."""

    total_tests: int
    passed: int
    failed: int
    crashes: int
    timeouts: int
    validation_results: list[ValidationResult]

    @property
    def success_rate(self) -> float:
        """Calculate success rate percentage."""
        return (self.passed / self.total_tests * 100) if self.total_tests > 0 else 0.0

    def __str__(self) -> str:
        return (
            f"Fuzz Results:\n"
            f"  Total: {self.total_tests}\n"
            f"  Passed: {self.passed} ({self.success_rate:.1f}%)\n"
            f"  Failed: {self.failed}\n"
            f"  Crashes: {self.crashes}\n"
            f"  Timeouts: {self.timeouts}"
        )


class MutationFuzzer:
    """
    Fuzzes mutated binaries to ensure robustness.

    Generates random inputs and compares behavior of original vs mutated.
    """

    def __init__(self, num_tests: int = 100, timeout: int = 5):
        """
        Initialize fuzzer.

        Args:
            num_tests: Number of fuzz tests to run
            timeout: Timeout per test (seconds)
        """
        self.num_tests = num_tests
        self.timeout = timeout
        self.validator = BinaryValidator(timeout=timeout)

    def fuzz(
        self, original_path: Path, mutated_path: Path, input_type: str = "random"
    ) -> FuzzResult:
        """
        Fuzz test the mutated binary.

        Args:
            original_path: Original binary
            mutated_path: Mutated binary
            input_type: Type of inputs ("random", "ascii", "binary", "structured")

        Returns:
            FuzzResult with statistics
        """
        logger.info(f"Fuzzing {mutated_path.name} with {self.num_tests} tests")

        validation_results = []
        passed = 0
        failed = 0
        crashes = 0
        timeouts = 0

        for i in range(self.num_tests):
            test_input = self._generate_input(input_type)

            self.validator.test_cases = []

            self.validator.add_test_case(stdin=test_input, description=f"Fuzz test {i + 1}")

            result = self.validator.validate(original_path, mutated_path)
            validation_results.append(result)

            if result.passed:
                passed += 1
            else:
                failed += 1

            if result.mutated_exitcode < 0:
                if "TIMEOUT" in result.mutated_output:
                    timeouts += 1
                else:
                    crashes += 1

            if (i + 1) % 10 == 0:
                logger.debug(f"Progress: {i + 1}/{self.num_tests} tests")

        fuzz_result = FuzzResult(
            total_tests=self.num_tests,
            passed=passed,
            failed=failed,
            crashes=crashes,
            timeouts=timeouts,
            validation_results=validation_results,
        )

        logger.info(f"Fuzzing complete: {fuzz_result}")
        return fuzz_result

    def _generate_input(self, input_type: str) -> str:
        """
        Generate fuzz input based on type.

        Args:
            input_type: Type of input to generate

        Returns:
            Generated input string
        """
        length = random.randint(0, 1000)

        if input_type == "random":
            return "".join(chr(random.randint(0, 255)) for _ in range(length))

        elif input_type == "ascii":
            return "".join(random.choice(string.printable) for _ in range(length))

        elif input_type == "binary":
            return bytes(random.randint(0, 255) for _ in range(length)).decode(errors="replace")

        elif input_type == "structured":
            templates = [
                lambda: str(random.randint(-1000000, 1000000)),
                lambda: str(random.random()),
                lambda: "".join(random.choices(string.ascii_letters, k=random.randint(1, 100))),
                lambda: " ".join(str(random.randint(0, 100)) for _ in range(random.randint(1, 10))),
            ]
            return random.choice(templates)()

        else:
            return ""

    def fuzz_with_args(
        self, original_path: Path, mutated_path: Path, arg_count: int = 5
    ) -> FuzzResult:
        """
        Fuzz with random command-line arguments.

        Args:
            original_path: Original binary
            mutated_path: Mutated binary
            arg_count: Maximum number of arguments

        Returns:
            FuzzResult
        """
        logger.info("Fuzzing with random arguments")

        validation_results = []
        passed = 0
        failed = 0
        crashes = 0
        timeouts = 0

        for i in range(self.num_tests):
            num_args = random.randint(0, arg_count)
            args = [
                "".join(
                    random.choices(string.ascii_letters + string.digits, k=random.randint(1, 20))
                )
                for _ in range(num_args)
            ]

            self.validator.test_cases = []

            self.validator.add_test_case(args=args, description=f"Args fuzz test {i + 1}")

            result = self.validator.validate(original_path, mutated_path)
            validation_results.append(result)

            if result.passed:
                passed += 1
            else:
                failed += 1

            if result.mutated_exitcode < 0:
                crashes += 1

        return FuzzResult(
            total_tests=self.num_tests,
            passed=passed,
            failed=failed,
            crashes=crashes,
            timeouts=timeouts,
            validation_results=validation_results,
        )
