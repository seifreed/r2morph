"""
Comprehensive regression testing framework for r2morph.

This module provides automated regression testing capabilities to ensure
that new changes don't break existing functionality.
"""

import json
import logging
import time
import hashlib
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from enum import Enum
from typing import Any

from r2morph.validation.validator import BinaryValidator, ValidationResult

logger = logging.getLogger(__name__)


class RegressionTestType(Enum):
    """Types of regression tests."""
    DETECTION_ACCURACY = "detection_accuracy"
    PERFORMANCE_BASELINE = "performance_baseline"
    API_COMPATIBILITY = "api_compatibility"
    OUTPUT_CONSISTENCY = "output_consistency"
    MUTATION_VALIDATION = "mutation_validation"


@dataclass
class BaselineResult:
    """Baseline result for regression testing."""
    test_id: str
    test_type: RegressionTestType
    input_hash: str
    expected_output: dict[str, Any]
    performance_baseline: dict[str, float]
    timestamp: str
    version: str


@dataclass
class RegressionTest:
    """A single regression test."""

    name: str
    binary_path: str
    mutations: list[str]
    test_cases: list[dict[str, Any]]
    expected_mutations: int | None = None

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
            "validation_result": self.validation_result.to_dict(),
            "timestamp": self.timestamp,
            "errors": self.errors,
        }


@dataclass
class NewRegressionResult:
    """Enhanced result of a regression test."""
    test_id: str
    baseline: BaselineResult
    actual_output: dict[str, Any]
    performance_actual: dict[str, float]
    passed: bool
    issues: list[str]
    timestamp: str


class RegressionTestFramework:
    """
    Comprehensive framework for automated regression testing of r2morph functionality.
    """
    
    def __init__(self, baseline_dir: str = "regression_baselines"):
        """
        Initialize the regression testing framework.
        
        Args:
            baseline_dir: Directory to store baseline results
        """
        self.baseline_dir = Path(baseline_dir)
        self.baseline_dir.mkdir(exist_ok=True)
        
        self.baselines: dict[str, BaselineResult] = {}
        self.test_results: list[NewRegressionResult] = []
        
        # Load existing baselines
        self._load_baselines()
    
    def _load_baselines(self):
        """Load existing baseline results."""
        baseline_files = list(self.baseline_dir.glob("*.json"))
        
        for baseline_file in baseline_files:
            try:
                with open(baseline_file, 'r') as f:
                    data = json.load(f)
                    test_type = data.get("test_type")
                    if isinstance(test_type, str):
                        if test_type.startswith("RegressionTestType."):
                            test_type = test_type.split(".", 1)[1]
                        try:
                            data["test_type"] = RegressionTestType(test_type)
                        except ValueError:
                            data["test_type"] = RegressionTestType.DETECTION_ACCURACY
                    baseline = BaselineResult(**data)
                    self.baselines[baseline.test_id] = baseline
                    logger.debug(f"Loaded baseline: {baseline.test_id}")
            except Exception as e:
                logger.warning(f"Failed to load baseline {baseline_file}: {e}")
    
    def _save_baseline(self, baseline: BaselineResult):
        """Save a baseline result."""
        baseline_file = self.baseline_dir / f"{baseline.test_id}.json"
        
        try:
            with open(baseline_file, 'w') as f:
                payload = asdict(baseline)
                if isinstance(payload.get("test_type"), RegressionTestType):
                    payload["test_type"] = payload["test_type"].value
                json.dump(payload, f, indent=2, default=str)
            
            self.baselines[baseline.test_id] = baseline
            logger.info(f"Saved baseline: {baseline.test_id}")
        
        except Exception as e:
            logger.error(f"Failed to save baseline {baseline.test_id}: {e}")
            raise
    
    def _compute_input_hash(self, input_data: Any) -> str:
        """Compute hash of input data for consistency checking."""
        if isinstance(input_data, (str, Path)):
            # File input
            try:
                with open(input_data, 'rb') as f:
                    return hashlib.sha256(f.read()).hexdigest()
            except Exception:
                return hashlib.sha256(str(input_data).encode()).hexdigest()
        else:
            # Other input types
            return hashlib.sha256(str(input_data).encode()).hexdigest()
    
    def create_detection_baseline(self, test_id: str, binary_path: str) -> BaselineResult:
        """
        Create a baseline for detection accuracy testing.
        
        Args:
            test_id: Unique test identifier
            binary_path: Path to test binary
        
        Returns:
            BaselineResult object
        """
        from r2morph import Binary
        from r2morph.detection import ObfuscationDetector
        
        start_time = time.time()
        
        try:
            with Binary(binary_path) as bin_obj:
                bin_obj.analyze()
                
                detector = ObfuscationDetector()
                result = detector.analyze_binary(bin_obj)
                
                # Extract relevant output for comparison
                expected_output = {
                    'packer_detected': result.packer_detected.value if result.packer_detected else None,
                    'vm_detected': result.vm_detected,
                    'anti_analysis_detected': result.anti_analysis_detected,
                    'control_flow_flattened': result.control_flow_flattened,
                    'mba_detected': result.mba_detected,
                    'confidence_score': round(result.confidence_score, 3),  # Round for stability
                    'techniques_count': len(result.obfuscation_techniques),
                    'obfuscation_techniques': sorted(result.obfuscation_techniques[:20])  # Limited list
                }
                
                # Extended detection results
                custom_vm = detector.detect_custom_virtualizer(bin_obj)
                layers = detector.detect_code_packing_layers(bin_obj)
                metamorphic = detector.detect_metamorphic_engine(bin_obj)
                
                expected_output.update({
                    'custom_vm_detected': custom_vm['detected'],
                    'custom_vm_type': custom_vm.get('vm_type'),
                    'packing_layers': layers['layers_detected'],
                    'metamorphic_detected': metamorphic['detected'],
                    'polymorphic_ratio': round(metamorphic.get('polymorphic_ratio', 0.0), 3)
                })
        
        except Exception as e:
            logger.error(f"Failed to create detection baseline for {test_id}: {e}")
            raise
        
        execution_time = time.time() - start_time
        
        # Performance baseline
        performance_baseline = {
            'execution_time': round(execution_time, 3),
            'max_allowed_time': round(execution_time * 2.0, 3)  # Allow 2x slowdown
        }
        
        baseline = BaselineResult(
            test_id=test_id,
            test_type=RegressionTestType.DETECTION_ACCURACY,
            input_hash=self._compute_input_hash(binary_path),
            expected_output=expected_output,
            performance_baseline=performance_baseline,
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
            version="2.0.0-phase2"
        )
        
        self._save_baseline(baseline)
        return baseline
    
    def create_api_compatibility_baseline(self, test_id: str) -> BaselineResult:
        """
        Create a baseline for API compatibility testing.
        
        Args:
            test_id: Unique test identifier
        
        Returns:
            BaselineResult object
        """
        api_checks = {}
        
        # Test core imports
        try:
            from r2morph import Binary
            api_checks['binary_import'] = True
        except ImportError:
            api_checks['binary_import'] = False
        
        try:
            from r2morph.detection import ObfuscationDetector
            api_checks['detection_import'] = True
        except ImportError:
            api_checks['detection_import'] = False
        
        try:
            from r2morph.devirtualization import CFOSimplifier, IterativeSimplifier
            api_checks['devirtualization_import'] = True
        except ImportError:
            api_checks['devirtualization_import'] = False
        
        # Test class instantiation
        try:
            detector = ObfuscationDetector()
            api_checks['detector_instantiation'] = True
            
            # Test method existence
            api_checks['analyze_binary_method'] = hasattr(detector, 'analyze_binary')
            api_checks['detect_custom_virtualizer_method'] = hasattr(detector, 'detect_custom_virtualizer')
            api_checks['get_comprehensive_report_method'] = hasattr(detector, 'get_comprehensive_report')
            
        except Exception:
            api_checks['detector_instantiation'] = False
            api_checks['analyze_binary_method'] = False
        
        # Test enum imports
        try:
            from r2morph.detection import PackerType
            api_checks['packer_type_enum'] = True
            api_checks['packer_type_count'] = len(list(PackerType))
        except ImportError:
            api_checks['packer_type_enum'] = False
            api_checks['packer_type_count'] = 0
        
        baseline = BaselineResult(
            test_id=test_id,
            test_type=RegressionTestType.API_COMPATIBILITY,
            input_hash="api_compatibility",  # Static hash for API tests
            expected_output=api_checks,
            performance_baseline={},  # No performance baselines for API tests
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
            version="2.0.0-phase2"
        )
        
        self._save_baseline(baseline)
        return baseline
    
    def run_regression_test(self, test_id: str, binary_path: str | None = None) -> NewRegressionResult:
        """
        Run a regression test against an existing baseline.
        
        Args:
            test_id: Test identifier
            binary_path: Path to test binary (required for non-API tests)
        
        Returns:
            NewRegressionResult object
        """
        if test_id not in self.baselines:
            raise ValueError(f"No baseline found for test ID: {test_id}")
        
        baseline = self.baselines[test_id]
        issues = []
        
        # Verify input consistency (for file-based tests)
        if binary_path and baseline.test_type != RegressionTestType.API_COMPATIBILITY:
            current_hash = self._compute_input_hash(binary_path)
            if current_hash != baseline.input_hash:
                issues.append(f"Input file hash mismatch: expected {baseline.input_hash}, got {current_hash}")
        
        # Run the appropriate test
        if baseline.test_type == RegressionTestType.DETECTION_ACCURACY:
            actual_output, performance_actual = self._run_detection_test(binary_path)
        elif baseline.test_type == RegressionTestType.API_COMPATIBILITY:
            actual_output, performance_actual = self._run_api_test()
        else:
            raise ValueError(f"Unsupported test type: {baseline.test_type}")
        
        # Compare results
        issues.extend(self._compare_outputs(baseline.expected_output, actual_output, baseline.test_type))
        issues.extend(self._compare_performance(baseline.performance_baseline, performance_actual))
        
        # Determine pass/fail
        passed = len(issues) == 0
        
        result = NewRegressionResult(
            test_id=test_id,
            baseline=baseline,
            actual_output=actual_output,
            performance_actual=performance_actual,
            passed=passed,
            issues=issues,
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
        )
        
        self.test_results.append(result)
        return result
    
    def _run_detection_test(self, binary_path: str) -> tuple[dict[str, Any], dict[str, float]]:
        """Run detection accuracy test."""
        from r2morph import Binary
        from r2morph.detection import ObfuscationDetector
        
        start_time = time.time()
        
        with Binary(binary_path) as bin_obj:
            bin_obj.analyze()
            
            detector = ObfuscationDetector()
            result = detector.analyze_binary(bin_obj)
            
            # Extract output for comparison
            actual_output = {
                'packer_detected': result.packer_detected.value if result.packer_detected else None,
                'vm_detected': result.vm_detected,
                'anti_analysis_detected': result.anti_analysis_detected,
                'control_flow_flattened': result.control_flow_flattened,
                'mba_detected': result.mba_detected,
                'confidence_score': round(result.confidence_score, 3),
                'techniques_count': len(result.obfuscation_techniques),
                'obfuscation_techniques': sorted(result.obfuscation_techniques[:20])
            }
            
            # Extended detection
            custom_vm = detector.detect_custom_virtualizer(bin_obj)
            layers = detector.detect_code_packing_layers(bin_obj)
            metamorphic = detector.detect_metamorphic_engine(bin_obj)
            
            actual_output.update({
                'custom_vm_detected': custom_vm['detected'],
                'custom_vm_type': custom_vm.get('vm_type'),
                'packing_layers': layers['layers_detected'],
                'metamorphic_detected': metamorphic['detected'],
                'polymorphic_ratio': round(metamorphic.get('polymorphic_ratio', 0.0), 3)
            })
        
        execution_time = time.time() - start_time
        performance_actual = {'execution_time': round(execution_time, 3)}
        
        return actual_output, performance_actual
    
    def _run_api_test(self) -> tuple[dict[str, Any], dict[str, float]]:
        """Run API compatibility test."""
        api_checks = {}
        
        # Test core imports
        try:
            from r2morph import Binary
            api_checks['binary_import'] = True
        except ImportError:
            api_checks['binary_import'] = False
        
        try:
            from r2morph.detection import ObfuscationDetector
            api_checks['detection_import'] = True
        except ImportError:
            api_checks['detection_import'] = False
        
        try:
            from r2morph.devirtualization import CFOSimplifier, IterativeSimplifier
            api_checks['devirtualization_import'] = True
        except ImportError:
            api_checks['devirtualization_import'] = False
        
        # Test class instantiation
        try:
            detector = ObfuscationDetector()
            api_checks['detector_instantiation'] = True
            
            # Test method existence
            api_checks['analyze_binary_method'] = hasattr(detector, 'analyze_binary')
            api_checks['detect_custom_virtualizer_method'] = hasattr(detector, 'detect_custom_virtualizer')
            api_checks['get_comprehensive_report_method'] = hasattr(detector, 'get_comprehensive_report')
            
        except Exception:
            api_checks['detector_instantiation'] = False
            api_checks['analyze_binary_method'] = False
        
        # Test enum imports
        try:
            from r2morph.detection import PackerType
            api_checks['packer_type_enum'] = True
            api_checks['packer_type_count'] = len(list(PackerType))
        except ImportError:
            api_checks['packer_type_enum'] = False
            api_checks['packer_type_count'] = 0
        
        return api_checks, {}  # No performance metrics for API tests
    
    def _compare_outputs(self, expected: dict[str, Any], actual: dict[str, Any], test_type: RegressionTestType) -> list[str]:
        """Compare expected vs actual outputs."""
        issues = []
        
        # Check for missing keys
        missing_keys = set(expected.keys()) - set(actual.keys())
        if missing_keys:
            issues.append(f"Missing output keys: {missing_keys}")
        
        # Check for extra keys
        extra_keys = set(actual.keys()) - set(expected.keys())
        if extra_keys:
            issues.append(f"Extra output keys: {extra_keys}")
        
        # Compare values
        for key in expected.keys():
            if key not in actual:
                continue
            
            expected_val = expected[key]
            actual_val = actual[key]
            
            if self._values_differ(expected_val, actual_val, key):
                issues.append(f"Value mismatch for '{key}': expected {expected_val}, got {actual_val}")
        
        return issues
    
    def _values_differ(self, expected: Any, actual: Any, key: str) -> bool:
        """Check if two values differ significantly."""
        # Handle floating point comparisons with tolerance
        if isinstance(expected, float) and isinstance(actual, float):
            tolerance = 0.1 if 'score' in key else 0.001
            return abs(expected - actual) > tolerance
        
        # Handle list comparisons (order doesn't matter for some fields)
        if isinstance(expected, list) and isinstance(actual, list):
            if 'techniques' in key:
                # Order doesn't matter for technique lists
                return set(expected) != set(actual)
            else:
                return expected != actual
        
        # Direct comparison for other types
        return expected != actual
    
    def _compare_performance(self, baseline: dict[str, float], actual: dict[str, float]) -> list[str]:
        """Compare performance metrics against baseline."""
        issues = []
        
        for metric, baseline_value in baseline.items():
            if metric.endswith('_max'):
                # This is a maximum threshold
                base_metric = metric[:-4]  # Remove '_max' suffix
                if base_metric in actual:
                    if actual[base_metric] > baseline_value:
                        issues.append(f"Performance regression: {base_metric} = {actual[base_metric]:.3f}s "
                                    f"exceeds maximum {baseline_value:.3f}s")
        
        return issues
    
    def generate_regression_report(self) -> str:
        """Generate a human-readable regression test report."""
        if not self.test_results:
            return "No regression test results available."
        
        report = []
        report.append("=" * 80)
        report.append("R2MORPH REGRESSION TEST REPORT")
        report.append("=" * 80)
        report.append("")
        
        # Summary
        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results if r.passed)
        failed_tests = total_tests - passed_tests
        
        report.append("SUMMARY")
        report.append("-" * 40)
        report.append(f"Total Tests:       {total_tests}")
        report.append(f"Passed:            {passed_tests}")
        report.append(f"Failed:            {failed_tests}")
        report.append(f"Success Rate:      {passed_tests/total_tests:.1%}" if total_tests > 0 else "Success Rate:      N/A")
        report.append("")
        
        # Test Results
        report.append("TEST RESULTS")
        report.append("-" * 40)
        
        for result in self.test_results:
            status = "PASS" if result.passed else "FAIL"
            report.append(f"[{status}] {result.test_id} ({result.baseline.test_type.value})")
            
            if not result.passed:
                for issue in result.issues:
                    report.append(f"      Issue: {issue}")
            
            report.append("")
        
        return "\n".join(report)


# Legacy regression testing classes for backward compatibility


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
        expected_mutations: int | None = None,
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
