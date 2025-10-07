"""
Regression testing for mutation passes.
"""

import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from r2morph.validation.validator import BinaryValidator, ValidationResult

logger = logging.getLogger(__name__)


@dataclass
class RegressionTest:
    """A single regression test."""

    name: str
    binary_path: str
    mutations: list[str]
    test_cases: list[dict[str, Any]]
    expected_mutations: Optional[int] = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class RegressionResult:
    """Result of a regression test."""

    test_name: str
    passed: bool
    mutations_applied: int
    expected_mutations: int | None
    validation_result: ValidationResult
    timestamp: str
    errors: list[str]

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "test_name": self.test_name,
            "passed": self.passed,
            "mutations_applied": self.mutations_applied,
            "expected_mutations": self.expected_mutations,
            "validation_passed": self.validation_result.passed,
            "similarity_score": self.validation_result.similarity_score,
            "timestamp": self.timestamp,
            "errors": self.errors,
        }


class RegressionTester:
    """
    Manages regression tests for mutation passes.

    Maintains a suite of tests and validates that mutations
    continue to work correctly across versions.
    """

    def __init__(self, test_dir: Path | None = None):
        """
        Initialize regression tester.

        Args:
            test_dir: Directory containing test definitions
        """
        self.test_dir = test_dir or Path.cwd() / "tests" / "regression"
        self.tests: list[RegressionTest] = []
        self.results: list[RegressionResult] = []

    def load_tests(self, test_file: Path | None = None):
        """
        Load regression tests from JSON file.

        Args:
            test_file: Path to test definition file
        """
        if test_file is None:
            test_file = self.test_dir / "regression_tests.json"

        if not test_file.exists():
            logger.warning(f"No regression test file found at {test_file}")
            return

        logger.info(f"Loading regression tests from {test_file}")

        with open(test_file) as f:
            data = json.load(f)

        for test_data in data.get("tests", []):
            test = RegressionTest(**test_data)
            self.tests.append(test)

        logger.info(f"Loaded {len(self.tests)} regression tests")

    def add_test(
        self,
        name: str,
        binary_path: str,
        mutations: list[str],
        test_cases: list[dict[str, Any]],
        expected_mutations: Optional[int] = None,
    ):
        """
        Add a regression test.

        Args:
            name: Test name
            binary_path: Path to binary to test
            mutations: List of mutation names to apply
            test_cases: Test cases for validation
            expected_mutations: Expected number of mutations
        """
        test = RegressionTest(
            name=name,
            binary_path=binary_path,
            mutations=mutations,
            test_cases=test_cases,
            expected_mutations=expected_mutations,
        )
        self.tests.append(test)

    def run_test(self, test: RegressionTest) -> RegressionResult:
        """
        Run a single regression test.

        Args:
            test: Regression test to run

        Returns:
            RegressionResult
        """
        logger.info(f"Running regression test: {test.name}")

        errors = []

        try:
            from r2morph import MorphEngine

            mutation_instances = []
            for mutation_name in test.mutations:
                try:
                    mutation_instances.append(self._get_mutation_pass(mutation_name))
                except Exception as e:
                    errors.append(f"Failed to load mutation {mutation_name}: {e}")

            original_path = Path(test.binary_path)
            output_path = original_path.parent / f"{original_path.stem}_regression_test"

            with MorphEngine() as engine:
                engine.load_binary(original_path).analyze()

                for mutation in mutation_instances:
                    engine.add_mutation(mutation)

                result = engine.run()
                engine.save(output_path)

            mutations_applied = result.get("total_mutations", 0)

            if test.expected_mutations is not None:
                if mutations_applied != test.expected_mutations:
                    errors.append(
                        f"Expected {test.expected_mutations} mutations, but got {mutations_applied}"
                    )

            validator = BinaryValidator()
            for tc in test.test_cases:
                validator.add_test_case(**tc)

            validation_result = validator.validate(original_path, output_path)

            if output_path.exists():
                output_path.unlink()

            passed = (
                validation_result.passed
                and len(errors) == 0
                and (
                    test.expected_mutations is None or mutations_applied == test.expected_mutations
                )
            )

            return RegressionResult(
                test_name=test.name,
                passed=passed,
                mutations_applied=mutations_applied,
                expected_mutations=test.expected_mutations,
                validation_result=validation_result,
                timestamp=datetime.now().isoformat(),
                errors=errors,
            )

        except Exception as e:
            logger.error(f"Error running regression test {test.name}: {e}")

            from r2morph.validation.validator import ValidationResult

            failed_validation = ValidationResult(
                passed=False,
                original_output="",
                mutated_output="",
                original_exitcode=0,
                mutated_exitcode=-1,
                errors=[str(e)],
                similarity_score=0.0,
            )

            return RegressionResult(
                test_name=test.name,
                passed=False,
                mutations_applied=0,
                expected_mutations=test.expected_mutations,
                validation_result=failed_validation,
                timestamp=datetime.now().isoformat(),
                errors=[str(e)],
            )

    def run_all(self) -> list[RegressionResult]:
        """
        Run all regression tests.

        Returns:
            List of RegressionResults
        """
        logger.info(f"Running {len(self.tests)} regression tests")

        self.results = []
        for test in self.tests:
            result = self.run_test(test)
            self.results.append(result)

        passed = sum(1 for r in self.results if r.passed)
        failed = len(self.results) - passed

        logger.info(f"Regression tests complete: {passed} passed, {failed} failed")

        return self.results

    def save_results(self, output_file: Path | None = None):
        """
        Save regression results to JSON.

        Args:
            output_file: Output file path
        """
        if output_file is None:
            output_file = self.test_dir / "regression_results.json"

        output_file.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "timestamp": datetime.now().isoformat(),
            "total_tests": len(self.results),
            "passed": sum(1 for r in self.results if r.passed),
            "failed": sum(1 for r in self.results if not r.passed),
            "results": [r.to_dict() for r in self.results],
        }

        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Saved regression results to {output_file}")

    def _get_mutation_pass(self, name: str):
        """
        Get a mutation pass instance by name.

        Args:
            name: Mutation pass name

        Returns:
            MutationPass instance
        """
        from r2morph.mutations import (
            BlockReorderingPass,
            InstructionExpansionPass,
            InstructionSubstitutionPass,
            NopInsertionPass,
            RegisterSubstitutionPass,
        )

        mapping = {
            "nop": NopInsertionPass,
            "substitute": InstructionSubstitutionPass,
            "register": RegisterSubstitutionPass,
            "expand": InstructionExpansionPass,
            "reorder": BlockReorderingPass,
        }

        mutation_class = mapping.get(name.lower())
        if mutation_class is None:
            raise ValueError(f"Unknown mutation pass: {name}")

        return mutation_class()
