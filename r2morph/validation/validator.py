"""
Binary validation to ensure mutations preserve semantics.
"""

import logging
import subprocess
import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import tempfile
import shutil

logger = logging.getLogger(__name__)


@dataclass
class RuntimeComparisonConfig:
    """Controls what runtime signals are compared."""

    compare_exitcode: bool = True
    compare_stdout: bool = True
    compare_stderr: bool = True
    compare_files: bool = False
    normalize_whitespace: bool = False
    monitored_files: list[str] = field(default_factory=list)


@dataclass
class ValidationTestCase:
    """Runtime test case for original vs mutated binaries."""

    args: list[str] = field(default_factory=list)
    stdin: str = ""
    env: dict[str, str] = field(default_factory=dict)
    expected_exitcode: int = 0
    description: str = ""
    working_dir: str | None = None
    monitored_files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        return {
            "args": list(self.args),
            "stdin": self.stdin,
            "env": dict(self.env),
            "expected_exitcode": self.expected_exitcode,
            "description": self.description,
            "working_dir": self.working_dir,
            "monitored_files": list(self.monitored_files),
        }


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
    compared_signals: dict[str, bool] = field(default_factory=dict)
    file_differences: dict[str, dict[str, str]] = field(default_factory=dict)
    output_hashes: dict[str, str] = field(default_factory=dict)
    runtime_details: list[dict[str, Any]] = field(default_factory=list)
    test_cases: list[dict[str, Any]] = field(default_factory=list)

    def __str__(self) -> str:
        status = "✅ PASSED" if self.passed else "❌ FAILED"
        return (
            f"{status}\n"
            f"Exit codes: {self.original_exitcode} vs {self.mutated_exitcode}\n"
            f"Output similarity: {self.similarity_score:.1f}%\n"
            f"Errors: {len(self.errors)}"
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the validation result to a dict."""
        return {
            "passed": self.passed,
            "original_output": self.original_output,
            "mutated_output": self.mutated_output,
            "original_exitcode": self.original_exitcode,
            "mutated_exitcode": self.mutated_exitcode,
            "errors": list(self.errors),
            "similarity_score": self.similarity_score,
            "compared_signals": dict(self.compared_signals),
            "file_differences": dict(self.file_differences),
            "output_hashes": dict(self.output_hashes),
            "runtime_details": list(self.runtime_details),
            "test_cases": list(self.test_cases),
        }


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

            orig_result = self._run_binary(original_path, test_case)

            mut_result = self._run_binary(mutated_path, test_case)

            orig_stdout = self._normalize_output(orig_result["stdout"])
            mut_stdout = self._normalize_output(mut_result["stdout"])
            orig_stderr = self._normalize_output(orig_result["stderr"])
            mut_stderr = self._normalize_output(mut_result["stderr"])

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
            compared_signals={
                "exitcode": self.comparison.compare_exitcode,
                "stdout": self.comparison.compare_stdout,
                "stderr": self.comparison.compare_stderr,
                "files": self.comparison.compare_files,
                "normalize_whitespace": self.comparison.normalize_whitespace,
            },
            file_differences=file_differences,
            output_hashes={
                "original_stdout_sha256": self._hash_text(orig_combined),
                "mutated_stdout_sha256": self._hash_text(mut_combined),
                "original_stderr_sha256": self._hash_text("\n".join(o["stderr"] for o in original_outputs)),
                "mutated_stderr_sha256": self._hash_text("\n".join(o["stderr"] for o in mutated_outputs)),
                "normalized_original_stdout_sha256": self._hash_text(
                    "\n".join(self._normalize_output(o["stdout"]) for o in original_outputs)
                ),
                "normalized_mutated_stdout_sha256": self._hash_text(
                    "\n".join(self._normalize_output(o["stdout"]) for o in mutated_outputs)
                ),
            },
            runtime_details=runtime_details,
            test_cases=[case.to_dict() for case in self.test_cases],
        )

        logger.info(f"Validation result: {result}")
        return result

    def _normalize_output(self, text: str) -> str:
        """Normalize output text for optional whitespace-insensitive comparison."""
        if not self.comparison.normalize_whitespace:
            return text
        return "\n".join(line.rstrip() for line in text.splitlines()).strip()

    def _hash_text(self, text: str) -> str:
        """Return a stable hash for machine-readable runtime reporting."""
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _run_binary(self, binary_path: Path, test_case: ValidationTestCase) -> dict[str, Any]:
        """
        Run a binary and capture output.

        Args:
            binary_path: Path to binary
            test_case: Test case configuration

        Returns:
            Dict with stdout, stderr, exitcode
        """
        run_dir = None
        cleanup_dir = False

        try:
            try:
                binary_path.chmod(0o755)
            except (OSError, PermissionError):
                pass

            if test_case.working_dir:
                run_dir = Path(test_case.working_dir)
            else:
                run_dir = Path(tempfile.mkdtemp(prefix="r2morph_runtime_"))
                cleanup_dir = True

            run_dir.mkdir(parents=True, exist_ok=True)

            local_binary = run_dir / binary_path.name
            shutil.copy2(binary_path, local_binary)
            cmd = [str(local_binary)] + test_case.args

            result = subprocess.run(
                cmd,
                input=test_case.stdin.encode() if test_case.stdin else None,
                capture_output=True,
                timeout=self.timeout,
                env={**os.environ, **test_case.env},
                cwd=run_dir,
            )

            files = {}
            for rel_path in set(self.comparison.monitored_files) | set(test_case.monitored_files):
                candidate = run_dir / rel_path
                files[rel_path] = candidate.read_bytes().hex() if candidate.exists() else ""

            return {
                "stdout": result.stdout.decode(errors="replace"),
                "stderr": result.stderr.decode(errors="replace"),
                "exitcode": result.returncode,
                "files": files,
            }

        except subprocess.TimeoutExpired:
            logger.warning(f"Binary {binary_path.name} timed out")
            return {"stdout": "", "stderr": "TIMEOUT", "exitcode": -1, "files": {}}
        except Exception as e:
            logger.error(f"Error running binary: {e}")
            return {"stdout": "", "stderr": str(e), "exitcode": -2, "files": {}}
        finally:
            if cleanup_dir and run_dir is not None:
                try:
                    shutil.rmtree(run_dir, ignore_errors=True)
                except Exception as e:
                    logger.debug(f"Error cleaning up temp directory {run_dir}: {e}")

    def _calculate_similarity(self, original_outputs: list[dict], mutated_outputs: list[dict]) -> float:
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

        total_enabled_checks = 0
        total_matches = 0

        enabled_dimensions = []
        if self.comparison.compare_exitcode:
            enabled_dimensions.append("exitcode")
        if self.comparison.compare_stdout:
            enabled_dimensions.append("stdout")
        if self.comparison.compare_stderr:
            enabled_dimensions.append("stderr")
        if self.comparison.compare_files:
            enabled_dimensions.append("files")

        if not enabled_dimensions:
            return 100.0

        for orig, mut in zip(original_outputs, mutated_outputs, strict=False):
            total_enabled_checks += len(enabled_dimensions)

            if self.comparison.compare_exitcode and orig["exitcode"] == mut["exitcode"]:
                total_matches += 1
            if self.comparison.compare_stdout and orig["stdout"] == mut["stdout"]:
                total_matches += 1
            if self.comparison.compare_stderr and orig["stderr"] == mut["stderr"]:
                total_matches += 1
            if self.comparison.compare_files and orig.get("files", {}) == mut.get("files", {}):
                total_matches += 1

        return (total_matches / total_enabled_checks * 100) if total_enabled_checks > 0 else 0.0

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
