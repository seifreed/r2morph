"""
Binary validation to ensure mutations preserve semantics.
"""

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of binary validation."""

    passed: bool
    original_output: str
    mutated_output: str
    original_exitcode: int
    mutated_exitcode: int
    errors: list[str]
    similarity_score: float

    def __str__(self) -> str:
        status = "✅ PASSED" if self.passed else "❌ FAILED"
        return (
            f"{status}\n"
            f"Exit codes: {self.original_exitcode} vs {self.mutated_exitcode}\n"
            f"Output similarity: {self.similarity_score:.1f}%\n"
            f"Errors: {len(self.errors)}"
        )


class BinaryValidator:
    """
    Validates that mutated binaries preserve semantic behavior.

    Compares execution of original vs mutated binary with various inputs.
    """

    def __init__(self, timeout: int = 10):
        """
        Initialize validator.

        Args:
            timeout: Maximum execution time per test (seconds)
        """
        self.timeout = timeout
        self.test_cases: list[dict[str, Any]] = []

    def add_test_case(
        self,
        args: list[str] = None,
        stdin: str = "",
        env: dict[str, str] = None,
        expected_exitcode: int = 0,
        description: str = "",
    ):
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
            {
                "args": args or [],
                "stdin": stdin,
                "env": env or {},
                "expected_exitcode": expected_exitcode,
                "description": description or f"Test {len(self.test_cases) + 1}",
            }
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

        for i, test_case in enumerate(self.test_cases):
            logger.debug(f"Running test case {i + 1}: {test_case['description']}")

            orig_result = self._run_binary(
                original_path, test_case["args"], test_case["stdin"], test_case["env"]
            )

            mut_result = self._run_binary(
                mutated_path, test_case["args"], test_case["stdin"], test_case["env"]
            )

            original_outputs.append(orig_result)
            mutated_outputs.append(mut_result)

            if orig_result["exitcode"] != mut_result["exitcode"]:
                errors.append(
                    f"Test {i + 1}: Exit code mismatch "
                    f"({orig_result['exitcode']} vs {mut_result['exitcode']})"
                )
                all_outputs_match = False

            if orig_result["stdout"] != mut_result["stdout"]:
                errors.append(f"Test {i + 1}: stdout mismatch")
                all_outputs_match = False

            if orig_result["stderr"] != mut_result["stderr"]:
                errors.append(f"Test {i + 1}: stderr mismatch")
                all_outputs_match = False

        similarity = self._calculate_similarity(original_outputs, mutated_outputs)

        orig_combined = "\n".join(o["stdout"] for o in original_outputs)
        mut_combined = "\n".join(o["stdout"] for o in mutated_outputs)
        orig_exitcode = original_outputs[0]["exitcode"] if original_outputs else 0
        mut_exitcode = mutated_outputs[0]["exitcode"] if mutated_outputs else 0

        result = ValidationResult(
            passed=all_outputs_match and len(errors) == 0,
            original_output=orig_combined,
            mutated_output=mut_combined,
            original_exitcode=orig_exitcode,
            mutated_exitcode=mut_exitcode,
            errors=errors,
            similarity_score=similarity,
        )

        logger.info(f"Validation result: {result}")
        return result

    def _run_binary(
        self, binary_path: Path, args: list[str], stdin: str, env: dict[str, str]
    ) -> dict[str, Any]:
        """
        Run a binary and capture output.

        Args:
            binary_path: Path to binary
            args: Command line arguments
            stdin: Input to provide on stdin
            env: Environment variables

        Returns:
            Dict with stdout, stderr, exitcode
        """
        try:
            binary_path.chmod(0o755)

            cmd = [str(binary_path)] + args

            result = subprocess.run(
                cmd,
                input=stdin.encode() if stdin else None,
                capture_output=True,
                timeout=self.timeout,
                env={**subprocess.os.environ, **env},
            )

            return {
                "stdout": result.stdout.decode(errors="replace"),
                "stderr": result.stderr.decode(errors="replace"),
                "exitcode": result.returncode,
            }

        except subprocess.TimeoutExpired:
            logger.warning(f"Binary {binary_path.name} timed out")
            return {"stdout": "", "stderr": "TIMEOUT", "exitcode": -1}
        except Exception as e:
            logger.error(f"Error running binary: {e}")
            return {"stdout": "", "stderr": str(e), "exitcode": -2}

    def _calculate_similarity(
        self, original_outputs: list[dict], mutated_outputs: list[Dict]
    ) -> float:
        """
        Calculate similarity percentage between outputs.

        Args:
            original_outputs: Original binary outputs
            mutated_outputs: Mutated binary outputs

        Returns:
            Similarity percentage (0-100)
        """
        if len(original_outputs) != len(mutated_outputs):
            return 0.0

        matches = 0
        total = len(original_outputs) * 3

        for orig, mut in zip(original_outputs, mutated_outputs, strict=False):
            if orig["exitcode"] == mut["exitcode"]:
                matches += 1
            if orig["stdout"] == mut["stdout"]:
                matches += 1
            if orig["stderr"] == mut["stderr"]:
                matches += 1

        return (matches / total * 100) if total > 0 else 0.0

    def validate_with_inputs(
        self, original_path: Path, mutated_path: Path, test_inputs: list[str]
    ) -> ValidationResult:
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
