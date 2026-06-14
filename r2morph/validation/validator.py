"""Binary validation to ensure mutations preserve semantics."""

import logging
from pathlib import Path
from typing import Any

from r2morph.validation.validator_execution import normalize_output, run_binary
from r2morph.validation.validator_results import build_validation_result, calculate_similarity
from r2morph.validation.validator_runtime import (
    RuntimeComparisonConfig,
    ValidationResult,
    ValidationTestCase,
)

logger = logging.getLogger(__name__)


class BinaryValidator:
    """
    Validates that mutated binaries preserve semantic behavior.

    Compares execution of original vs mutated binary with various inputs.
    """

    def __init__(
        self,
        timeout: int = 10,
        comparison: RuntimeComparisonConfig | None = None,
    ):
        """
        Initialize validator.

        Args:
            timeout: Maximum execution time per test (seconds)
        """
        self.timeout = timeout
        self.comparison = comparison or RuntimeComparisonConfig()
        self.test_cases: list[ValidationTestCase] = []

    def add_test_case(
        self,
        args: list[str] | None = None,
        stdin: str = "",
        env: dict[str, str] | None = None,
        expected_exitcode: int = 0,
        description: str = "",
    ) -> None:
        """
        Add a test case for validation.

        Args:
            args: Command line arguments
            stdin: Standard input to provide
            env: Environment variables
            expected_exitcode: Expected exit code
            description: Test description
        """
        self.test_cases.append(
            ValidationTestCase(
                args=args or [],
                stdin=stdin,
                env=env or {},
                expected_exitcode=expected_exitcode,
                description=description or f"Test {len(self.test_cases) + 1}",
            )
        )

    def load_test_cases(self, test_cases: list[dict[str, Any]]) -> None:
        """Load a configurable runtime corpus."""
        self.test_cases = []
        for case in test_cases:
            self.test_cases.append(
                ValidationTestCase(
                    args=list(case.get("args", [])),
                    stdin=case.get("stdin", ""),
                    env=dict(case.get("env", {})),
                    expected_exitcode=case.get("expected_exitcode", 0),
                    description=case.get("description", f"Test {len(self.test_cases) + 1}"),
                    working_dir=case.get("working_dir"),
                    monitored_files=list(case.get("monitored_files", [])),
                )
            )

    def validate(self, original_path: Path, mutated_path: Path) -> ValidationResult:
        """
        Validate that mutated binary behaves like original.

        Args:
            original_path: Path to original binary
            mutated_path: Path to mutated binary

        Returns:
            ValidationResult with comparison details
        """
        logger.info(f"Validating {mutated_path.name} against {original_path.name}")

        errors = []
        all_outputs_match = True

        if not self.test_cases:
            self.add_test_case(description="Default execution")

        original_outputs = []
        mutated_outputs = []
        file_differences: dict[str, dict[str, str]] = {}
        runtime_details: list[dict[str, Any]] = []

        for i, test_case in enumerate(self.test_cases):
            logger.debug(f"Running test case {i + 1}: {test_case.description}")

            orig_result = run_binary(original_path, test_case, self.timeout)

            mut_result = run_binary(mutated_path, test_case, self.timeout)

            orig_stdout = normalize_output(orig_result["stdout"], self.comparison.normalize_whitespace)
            mut_stdout = normalize_output(mut_result["stdout"], self.comparison.normalize_whitespace)
            orig_stderr = normalize_output(orig_result["stderr"], self.comparison.normalize_whitespace)
            mut_stderr = normalize_output(mut_result["stderr"], self.comparison.normalize_whitespace)

            original_outputs.append(orig_result)
            mutated_outputs.append(mut_result)
            runtime_details.append(
                {
                    "description": test_case.description,
                    "args": list(test_case.args),
                    "working_dir": test_case.working_dir,
                    "original_exitcode": orig_result["exitcode"],
                    "mutated_exitcode": mut_result["exitcode"],
                    "stdout_match": orig_stdout == mut_stdout,
                    "stderr_match": orig_stderr == mut_stderr,
                    "files_compared": sorted(set(self.comparison.monitored_files) | set(test_case.monitored_files)),
                }
            )

            if self.comparison.compare_exitcode and orig_result["exitcode"] != mut_result["exitcode"]:
                errors.append(
                    f"Test {i + 1}: Exit code mismatch " f"({orig_result['exitcode']} vs {mut_result['exitcode']})"
                )
                all_outputs_match = False

            if self.comparison.compare_stdout and orig_stdout != mut_stdout:
                errors.append(f"Test {i + 1}: stdout mismatch")
                all_outputs_match = False

            if self.comparison.compare_stderr and orig_stderr != mut_stderr:
                errors.append(f"Test {i + 1}: stderr mismatch")
                all_outputs_match = False

            if self.comparison.compare_files:
                expected_files = set(self.comparison.monitored_files) | set(test_case.monitored_files)
                for rel_path in expected_files:
                    orig_file = orig_result["files"].get(rel_path, "")
                    mut_file = mut_result["files"].get(rel_path, "")
                    if orig_file != mut_file:
                        file_differences[rel_path] = {
                            "original": orig_file,
                            "mutated": mut_file,
                        }
                        errors.append(f"Test {i + 1}: file mismatch for {rel_path}")
                        all_outputs_match = False

        result = build_validation_result(
            all_outputs_match=all_outputs_match,
            errors=errors,
            original_outputs=original_outputs,
            mutated_outputs=mutated_outputs,
            comparison=self.comparison,
            file_differences=file_differences,
            runtime_details=runtime_details,
            test_cases=self.test_cases,
        )

        logger.info(f"Validation result: {result}")
        return result

    def _calculate_similarity(self, original_outputs: list[dict], mutated_outputs: list[dict]) -> float:
        """
        Calculate similarity percentage between outputs.

        Args:
            original_outputs: Original binary outputs
            mutated_outputs: Mutated binary outputs

        Returns:
            Similarity percentage (0-100)
        """
        return calculate_similarity(original_outputs, mutated_outputs, self.comparison)

    def validate_with_inputs(self, original_path: Path, mutated_path: Path, test_inputs: list[str]) -> ValidationResult:
        """
        Validate with multiple input strings.

        Args:
            original_path: Original binary
            mutated_path: Mutated binary
            test_inputs: List of input strings to test

        Returns:
            ValidationResult
        """
        self.test_cases = []

        for i, input_str in enumerate(test_inputs):
            self.add_test_case(stdin=input_str, description=f"Input test {i + 1}")

        return self.validate(original_path, mutated_path)
