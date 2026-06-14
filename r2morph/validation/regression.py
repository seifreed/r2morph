"""
Comprehensive regression testing framework for r2morph.

This module provides automated regression testing capabilities to ensure
that new changes don't break existing functionality.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from r2morph.validation import regression_comparison, regression_models

BaselineResult = regression_models.BaselineResult
NewRegressionResult = regression_models.NewRegressionResult
RegressionResult = regression_models.RegressionResult
RegressionTest = regression_models.RegressionTest
RegressionTestType = regression_models.RegressionTestType

logger = logging.getLogger(__name__)


class RegressionTestFramework:
    """
    Comprehensive framework for automated regression testing of r2morph functionality.
    """

    def __init__(self, baseline_dir: str = "regression_baselines") -> None:
        """
        Initialize the regression testing framework.

        Args:
            baseline_dir: Directory to store baseline results
        """
        self.baseline_dir = Path(baseline_dir)
        self.baseline_dir.mkdir(exist_ok=True)

        self.baselines: dict[str, BaselineResult] = {}
        self.test_results: list[NewRegressionResult] = []

        self._load_baselines()

    def _load_baselines(self) -> None:
        """Load existing baseline results."""
        baseline_files = list(self.baseline_dir.glob("*.json"))

        for baseline_file in baseline_files:
            try:
                with open(baseline_file) as f:
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

    def _save_baseline(self, baseline: BaselineResult) -> None:
        """Save a baseline result."""
        baseline_file = self.baseline_dir / f"{baseline.test_id}.json"

        try:
            with open(baseline_file, "w") as f:
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
            try:
                with open(input_data, "rb") as f:
                    return hashlib.sha256(f.read()).hexdigest()
            except Exception:
                return hashlib.sha256(str(input_data).encode()).hexdigest()
        else:
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

                expected_output = {
                    "packer_detected": result.packer_detected.value if result.packer_detected else None,
                    "vm_detected": result.vm_detected,
                    "anti_analysis_detected": result.anti_analysis_detected,
                    "control_flow_flattened": result.control_flow_flattened,
                    "mba_detected": result.mba_detected,
                    "confidence_score": round(result.confidence_score, 3),  # Round for stability
                    "techniques_count": len(result.obfuscation_techniques),
                    "obfuscation_techniques": sorted(
                        result.obfuscation_techniques[:20], key=lambda t: t.value
                    ),  # Limited list
                }

                custom_vm = detector.detect_custom_virtualizer(bin_obj)
                layers = detector.detect_code_packing_layers(bin_obj)
                metamorphic = detector.detect_metamorphic_engine(bin_obj)

                expected_output.update(
                    {
                        "custom_vm_detected": custom_vm["detected"],
                        "custom_vm_type": custom_vm.get("vm_type", ""),
                        "packing_layers": layers["layers_detected"],
                        "metamorphic_detected": metamorphic["detected"],
                        "polymorphic_ratio": round(metamorphic.get("polymorphic_ratio", 0.0), 3),
                    }
                )

        except Exception as e:
            logger.error(f"Failed to create detection baseline for {test_id}: {e}")
            raise

        execution_time = time.time() - start_time

        performance_baseline = {
            "execution_time": round(execution_time, 3),
            "max_allowed_time": round(execution_time * 2.0, 3),  # Allow 2x slowdown
        }

        baseline = BaselineResult(
            test_id=test_id,
            test_type=RegressionTestType.DETECTION_ACCURACY,
            input_hash=self._compute_input_hash(binary_path),
            expected_output=expected_output,
            performance_baseline=performance_baseline,
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            version="2.0.0-phase2",
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
        import importlib.util

        api_checks: dict[str, Any] = {}

        api_checks["binary_import"] = importlib.util.find_spec("r2morph") is not None
        api_checks["detection_import"] = importlib.util.find_spec("r2morph.detection") is not None
        api_checks["devirtualization_import"] = importlib.util.find_spec("r2morph.devirtualization") is not None

        try:
            from r2morph.detection import ObfuscationDetector

            detector = ObfuscationDetector()
            api_checks["detector_instantiation"] = True

            api_checks["analyze_binary_method"] = hasattr(detector, "analyze_binary")
            api_checks["detect_custom_virtualizer_method"] = hasattr(detector, "detect_custom_virtualizer")
            api_checks["get_comprehensive_report_method"] = hasattr(detector, "get_comprehensive_report")

        except Exception:
            api_checks["detector_instantiation"] = False
            api_checks["analyze_binary_method"] = False

        try:
            from r2morph.detection import PackerType

            api_checks["packer_type_enum"] = True
            api_checks["packer_type_count"] = len(list(PackerType))
        except ImportError:
            api_checks["packer_type_enum"] = False
            api_checks["packer_type_count"] = 0

        baseline = BaselineResult(
            test_id=test_id,
            test_type=RegressionTestType.API_COMPATIBILITY,
            input_hash="api_compatibility",  # Static hash for API tests
            expected_output=api_checks,
            performance_baseline={},  # No performance baselines for API tests
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            version="2.0.0-phase2",
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

        if binary_path and baseline.test_type != RegressionTestType.API_COMPATIBILITY:
            current_hash = self._compute_input_hash(binary_path)
            if current_hash != baseline.input_hash:
                issues.append(f"Input file hash mismatch: expected {baseline.input_hash}, got {current_hash}")

        if baseline.test_type == RegressionTestType.DETECTION_ACCURACY:
            if binary_path is None:
                raise ValueError("binary_path is required for detection accuracy tests")
            actual_output, performance_actual = self._run_detection_test(binary_path)
        elif baseline.test_type == RegressionTestType.API_COMPATIBILITY:
            actual_output, performance_actual = self._run_api_test()
        else:
            raise ValueError(f"Unsupported test type: {baseline.test_type}")

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
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
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

            actual_output = {
                "packer_detected": result.packer_detected.value if result.packer_detected else None,
                "vm_detected": result.vm_detected,
                "anti_analysis_detected": result.anti_analysis_detected,
                "control_flow_flattened": result.control_flow_flattened,
                "mba_detected": result.mba_detected,
                "confidence_score": round(result.confidence_score, 3),
                "techniques_count": len(result.obfuscation_techniques),
                "obfuscation_techniques": sorted(result.obfuscation_techniques[:20], key=lambda t: t.value),
            }

            custom_vm = detector.detect_custom_virtualizer(bin_obj)
            layers = detector.detect_code_packing_layers(bin_obj)
            metamorphic = detector.detect_metamorphic_engine(bin_obj)

            actual_output.update(
                {
                    "custom_vm_detected": custom_vm["detected"],
                    "custom_vm_type": custom_vm.get("vm_type", ""),
                    "packing_layers": layers["layers_detected"],
                    "metamorphic_detected": metamorphic["detected"],
                    "polymorphic_ratio": round(metamorphic.get("polymorphic_ratio", 0.0), 3),
                }
            )

        execution_time = time.time() - start_time
        performance_actual = {"execution_time": round(execution_time, 3)}

        return actual_output, performance_actual

    def _run_api_test(self) -> tuple[dict[str, Any], dict[str, float]]:
        """Run API compatibility test."""
        import importlib.util

        api_checks: dict[str, Any] = {}

        api_checks["binary_import"] = importlib.util.find_spec("r2morph") is not None
        api_checks["detection_import"] = importlib.util.find_spec("r2morph.detection") is not None
        api_checks["devirtualization_import"] = importlib.util.find_spec("r2morph.devirtualization") is not None

        try:
            from r2morph.detection import ObfuscationDetector

            detector = ObfuscationDetector()
            api_checks["detector_instantiation"] = True

            api_checks["analyze_binary_method"] = hasattr(detector, "analyze_binary")
            api_checks["detect_custom_virtualizer_method"] = hasattr(detector, "detect_custom_virtualizer")
            api_checks["get_comprehensive_report_method"] = hasattr(detector, "get_comprehensive_report")

        except Exception:
            api_checks["detector_instantiation"] = False
            api_checks["analyze_binary_method"] = False

        try:
            from r2morph.detection import PackerType

            api_checks["packer_type_enum"] = True
            api_checks["packer_type_count"] = len(list(PackerType))
        except ImportError:
            api_checks["packer_type_enum"] = False
            api_checks["packer_type_count"] = 0

        return api_checks, {}  # No performance metrics for API tests

    def _compare_outputs(
        self, expected: dict[str, Any], actual: dict[str, Any], test_type: RegressionTestType
    ) -> list[str]:
        """Compare expected vs actual outputs."""
        return regression_comparison.compare_outputs(expected, actual)

    def _values_differ(self, expected: Any, actual: Any, key: str) -> bool:
        """Check if two values differ significantly."""
        return regression_comparison.values_differ(expected, actual, key)

    def _compare_performance(self, baseline: dict[str, float], actual: dict[str, float]) -> list[str]:
        """Compare performance metrics against baseline."""
        return regression_comparison.compare_performance(baseline, actual)

    def generate_regression_report(self) -> str:
        """Generate a human-readable regression test report."""
        if not self.test_results:
            return "No regression test results available."

        report = []
        report.append("=" * 80)
        report.append("R2MORPH REGRESSION TEST REPORT")
        report.append("=" * 80)
        report.append("")

        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results if r.passed)
        failed_tests = total_tests - passed_tests

        report.append("SUMMARY")
        report.append("-" * 40)
        report.append(f"Total Tests:       {total_tests}")
        report.append(f"Passed:            {passed_tests}")
        report.append(f"Failed:            {failed_tests}")
        report.append(
            f"Success Rate:      {passed_tests/total_tests:.1%}" if total_tests > 0 else "Success Rate:      N/A"
        )
        report.append("")

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

class RegressionTester:
    """Compatibility wrapper that instantiates the legacy tester on demand."""

    def __new__(cls, *args: Any, **kwargs: Any) -> Any:
        from r2morph.validation.regression_legacy import RegressionTester as LegacyRegressionTester

        return LegacyRegressionTester(*args, **kwargs)
