"""
Comprehensive validation suite demonstration for r2morph Phase 2.

This example shows how to use the complete validation framework including:
- Performance benchmarking
- Accuracy validation
- Regression testing
- Real-world validation scenarios
"""

import argparse
import importlib
import logging
import sys
import time
from pathlib import Path

_EXPECTED_ACCURACY_RESULTS_AVERAGE_ACCURACY_0_8 = 0.8
_EXPECTED_CONFIDENCE_0_3 = 0.3
_EXPECTED_OVERALL_SCORE_0_6 = 0.6
_EXPECTED_OVERALL_SCORE_0_6_2 = 0.6
_EXPECTED_OVERALL_SCORE_0_8 = 0.8
_EXPECTED_OVERALL_SCORE_0_8_2 = 0.8
_EXPECTED_PERFORMANCE_RESULTS_SUCCESS_RATE_0_8 = 0.8
_EXPECTED_REALWORLD_RESULTS_SUCCESS_RATE_0_7 = 0.7
_EXPECTED_REGRESSION_RESULTS_SUCCESS_RATE_0_9 = 0.9
_EXPECTED_SCENARIO_TIME_60 = 60


# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def setup_test_environment():
    """Set up the test environment with sample files."""
    dataset_dir = Path("fixtures/dataset")
    dataset_dir.mkdir(exist_ok=True)

    # Check if test files exist
    test_files = [dataset_dir / "simple", dataset_dir / "loop", dataset_dir / "conditional"]

    existing_files = [f for f in test_files if f.exists()]

    if not existing_files:
        logger.warning("No test files found in fixtures/dataset/ directory")
        logger.info("Please ensure test binaries are available for comprehensive validation")
        return []

    return existing_files


def run_performance_benchmarks():
    """Run comprehensive performance benchmarks."""
    print("\n" + "=" * 80)
    print("PERFORMANCE BENCHMARKING")
    print("=" * 80)

    try:
        benchmark_category = importlib.import_module("r2morph.validation").BenchmarkCategory
        validation_framework = importlib.import_module("r2morph.validation").ValidationFramework

        # Initialize validation framework
        framework = validation_framework("dataset")

        print(f"Loaded {len(framework.test_samples)} test samples")

        # Run performance-focused benchmarks
        benchmark_categories = [
            benchmark_category.DETECTION,
            benchmark_category.DEVIRTUALIZATION,
            benchmark_category.FULL_PIPELINE,
        ]

        print("Running performance benchmarks...")
        start_time = time.time()

        results = framework.run_validation_suite(benchmark_categories)

        execution_time = time.time() - start_time

        # Display summary
        print("\nBenchmark Results Summary:")
        print(f"  Total Tests: {results['total_tests']}")
        print(f"  Success Rate: {results['success_rate']:.1%}")
        print(f"  Average Execution Time: {results['avg_execution_time']:.2f}s")
        print(f"  Average Memory Usage: {results['avg_memory_usage']:.1f}MB")
        print(f"  Total Benchmark Time: {execution_time:.2f}s")

        # Category breakdown
        if results["categories"]:
            print("\nCategory Performance:")
            for category, stats in results["categories"].items():
                print(f"  {category.upper()}:")
                print(f"    Success Rate: {stats['success_rate']:.1%}")
                print(f"    Average Time: {stats['avg_time']:.2f}s")

        # Export results
        framework.export_results("performance_benchmark_results.json", "json")
        print("\nDetailed results exported to performance_benchmark_results.json")

        return results

    except ImportError as e:
        print(f"Error: Missing dependencies for benchmarking: {e}")
        return None
    except Exception as e:
        print(f"Benchmarking failed: {e}")
        traceback = importlib.import_module("traceback")

        traceback.print_exc()
        return None


def run_accuracy_validation():
    """Run accuracy validation against known samples."""
    print("\n" + "=" * 80)
    print("ACCURACY VALIDATION")
    print("=" * 80)

    try:
        validation_framework = importlib.import_module("r2morph.validation").ValidationFramework

        framework = validation_framework("dataset")

        # Focus on detection accuracy
        print("Running detection accuracy validation...")

        accuracy_results = []

        for sample in framework.test_samples:
            if not sample.file_exists:
                print(f"  Skipping {sample.description} (file not found)")
                continue

            print(f"  Testing: {sample.description}")

            try:
                result = framework.benchmark_detection(sample)

                if result.accuracy:
                    accuracy_results.append(result.accuracy)
                    print(f"    Accuracy: {result.accuracy.accuracy:.1%}")
                    print(f"    Precision: {result.accuracy.precision:.1%}")
                    print(f"    Recall: {result.accuracy.recall:.1%}")
                    print(f"    F1-Score: {result.accuracy.f1_score:.3f}")
                else:
                    print("    No accuracy metrics available")

                print(f"    Performance: {result.performance.execution_time:.2f}s")

            except Exception as e:
                print(f"    Error: {e}")

        if accuracy_results:
            # Calculate overall accuracy metrics
            avg_accuracy = sum(r.accuracy for r in accuracy_results) / len(accuracy_results)
            avg_precision = sum(r.precision for r in accuracy_results) / len(accuracy_results)
            avg_recall = sum(r.recall for r in accuracy_results) / len(accuracy_results)
            avg_f1 = sum(r.f1_score for r in accuracy_results) / len(accuracy_results)

            print("\nOverall Accuracy Metrics:")
            print(f"  Average Accuracy: {avg_accuracy:.1%}")
            print(f"  Average Precision: {avg_precision:.1%}")
            print(f"  Average Recall: {avg_recall:.1%}")
            print(f"  Average F1-Score: {avg_f1:.3f}")
            print(f"  Samples Tested: {len(accuracy_results)}")

            return {
                "average_accuracy": avg_accuracy,
                "average_precision": avg_precision,
                "average_recall": avg_recall,
                "average_f1": avg_f1,
                "samples_tested": len(accuracy_results),
            }
        else:
            print("No accuracy results available")
            return None

    except Exception as e:
        print(f"Accuracy validation failed: {e}")
        traceback = importlib.import_module("traceback")

        traceback.print_exc()
        return None


def run_regression_tests():
    """Run regression tests to ensure backward compatibility."""
    print("\n" + "=" * 80 + "\nREGRESSION TESTING\n" + "=" * 80)

    try:
        regression_test_framework = importlib.import_module("r2morph.validation").RegressionTestFramework

        # Initialize regression framework
        framework = regression_test_framework("regression_baselines")

        print("Setting up regression test baselines...")

        # Create API compatibility baseline
        framework.create_api_compatibility_baseline("api_v2_compatibility")
        print("  ✓ API compatibility baseline created")

        # Create baselines for available test files
        test_files = setup_test_environment()

        baseline_count = 0
        for i, test_file in enumerate(test_files[:3]):  # Limit to 3 files for demo
            test_id = f"test_file_{i+1}"
            try:
                framework.create_detection_baseline(f"{test_id}_detection", str(test_file))
                baseline_count += 1
                print(f"  ✓ Detection baseline created for {test_file.name}")
            except Exception as e:
                print(f"  ✗ Failed to create baseline for {test_file.name}: {e}")

        print(f"\nCreated {baseline_count + 1} regression baselines")

        # Run regression tests
        print("\nRunning regression tests...")

        # Test API compatibility
        try:
            api_result = framework.run_regression_test("api_v2_compatibility")
            api_status = "PASS" if api_result.passed else "FAIL"
            print(f"  API Compatibility: {api_status}")

            if not api_result.passed:
                for issue in api_result.issues:
                    print(f"    Issue: {issue}")

        except Exception as e:
            print(f"  API Compatibility: ERROR - {e}")

        # Test detection baselines
        for i in range(baseline_count):
            test_id = f"test_file_{i+1}_detection"
            test_file = test_files[i]

            try:
                result = framework.run_regression_test(test_id, str(test_file))
                status = "PASS" if result.passed else "FAIL"
                print(f"  Detection Test {i+1}: {status}")

                if not result.passed:
                    for issue in result.issues[:3]:  # Show first 3 issues
                        print(f"    Issue: {issue}")

            except Exception as e:
                print(f"  Detection Test {i+1}: ERROR - {e}")

        # Generate regression report
        report = framework.generate_regression_report()

        # Save report
        with open("regression_test_report.txt", "w") as f:
            f.write(report)

        print("\nRegression test report saved to regression_test_report.txt")

        # Summary
        total_tests = len(framework.test_results)
        passed_tests = sum(1 for r in framework.test_results if r.passed)

        print(
            "\nRegression Testing Summary:\n"
            f"  Total Tests: {total_tests}\n"
            f"  Passed: {passed_tests}\n"
            f"  Failed: {total_tests - passed_tests}\n"
            f"  Success Rate: {passed_tests/total_tests:.1%}"
            if total_tests > 0
            else "  Success Rate: N/A"
        )

        return {
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "success_rate": passed_tests / total_tests if total_tests > 0 else 0.0,
        }

    except Exception as e:
        print(f"Regression testing failed: {e}")
        traceback = importlib.import_module("traceback")

        traceback.print_exc()
        return None


def _run_devirtualization(binary_object, detection_result, cfo_class, iterative_class, strategy):
    if not (detection_result.vm_detected or detection_result.control_flow_flattened):
        print("  2. Skipping devirtualization (not needed)")
        return False, 0.0
    print("  2. Running devirtualization...")
    try:
        simplifier = cfo_class(binary_object)
        reduction = 0.0
        for function in binary_object.get_functions()[:2]:
            result = simplifier.simplify_control_flow(function.get("offset", 0))
            if result.success:
                reduction += result.original_complexity - result.simplified_complexity
        if reduction <= 0:
            print("     No complexity reduction achieved")
            return False, reduction
        result = iterative_class(binary_object).simplify(strategy=strategy.FAST, max_iterations=2, timeout=15)
        if not result.success:
            print("     Iterative simplification failed")
            return False, reduction
        print(f"     Devirtualization successful: {reduction:.1f} complexity reduced")
        return True, reduction
    except Exception as error:
        print(f"     Devirtualization error: {error}")
        return False, 0.0


def _validate_real_world_file(test_file, *components):
    binary_class, detector_class, cfo_class, iterative_class, strategy = components
    print(f"\nValidating real-world scenario: {test_file.name}")
    started = time.time()
    try:
        with binary_class(str(test_file)) as binary_object:
            binary_object.analyze()
            print("  1. Running detection analysis...")
            detection_result = detector_class().analyze_binary(binary_object)
            technique_count = len(detection_result.obfuscation_techniques)
            confidence = detection_result.confidence_score
            print(f"     Detected {technique_count} techniques (confidence: {confidence:.2f})")
            devirt_success, reduction = _run_devirtualization(
                binary_object, detection_result, cfo_class, iterative_class, strategy
            )
            print("  3. Validating results...")
            elapsed = time.time() - started
            issues = []
            if confidence < _EXPECTED_CONFIDENCE_0_3:
                issues.append("Low confidence score")
            if elapsed > _EXPECTED_SCENARIO_TIME_60:
                issues.append("Execution time too long")
            if detection_result.vm_detected and not devirt_success and reduction == 0:
                issues.append("VM detected but no devirtualization performed")
            passed = confidence >= _EXPECTED_CONFIDENCE_0_3 and elapsed <= _EXPECTED_SCENARIO_TIME_60
            status = "PASS" if passed else "FAIL"
            print(f"     Validation: {status} ({elapsed:.2f}s)")
            for issue in issues:
                print(f"     Issue: {issue}")
            return {
                "file": test_file.name,
                "passed": passed,
                "execution_time": elapsed,
                "techniques_detected": technique_count,
                "confidence": confidence,
                "devirt_success": devirt_success,
                "complexity_reduction": reduction,
                "issues": issues,
            }
    except Exception as error:
        print(f"  Error during validation: {error}")
        return {"file": test_file.name, "passed": False, "execution_time": time.time() - started, "error": str(error)}


def run_real_world_validation():
    """Run validation against real-world scenarios."""
    print("\n" + "=" * 80 + "\nREAL-WORLD VALIDATION\n" + "=" * 80)
    try:
        binary_class = importlib.import_module("r2morph").Binary
        detection_module = importlib.import_module("r2morph.detection")
        devirt_module = importlib.import_module("r2morph.devirtualization")
        test_files = setup_test_environment()
        if not test_files:
            print("No test files available for real-world validation")
            return None
        results = [
            _validate_real_world_file(
                test_file,
                binary_class,
                detection_module.ObfuscationDetector,
                devirt_module.CFOSimplifier,
                devirt_module.IterativeSimplifier,
                devirt_module.SimplificationStrategy,
            )
            for test_file in test_files[:2]
        ]
        total = len(results)
        passed = sum(result.get("passed", False) for result in results)
        average_time = sum(result.get("execution_time", 0) for result in results) / total if total else 0
        print(
            "\nReal-World Validation Summary:\n"
            f"  Total Scenarios: {total}\n"
            f"  Passed: {passed}\n"
            f"  Failed: {total - passed}\n"
            f"  Success Rate: {passed / total:.1%}\n"
            f"  Average Execution Time: {average_time:.2f}s"
            if total
            else "  Success Rate: N/A"
        )
        return {
            "total_scenarios": total,
            "passed_scenarios": passed,
            "success_rate": passed / total if total else 0.0,
            "results": results,
        }
    except Exception as error:
        print(f"Real-world validation failed: {error}")
        importlib.import_module("traceback").print_exc()
        return None


def _append_summary(report, title, result, fields, fallback):
    report.extend([title, "-" * 30])
    if result:
        for key, label, format_spec in fields:
            report.append(f"{label}: {format(result[key], format_spec)}")
    else:
        report.append(fallback)
    report.append("")


def _append_assessment(report, results):
    report.extend(["OVERALL ASSESSMENT", "-" * 30])
    successful = 0
    for result, key, threshold, label in results:
        if result and result[key] > threshold:
            successful += 1
            report.append(f"✓ {label}: GOOD")
        else:
            report.append(f"✗ {label}: NEEDS IMPROVEMENT")
    return successful / len(results)


def generate_comprehensive_report(performance_results, accuracy_results, regression_results, realworld_results):
    """Generate a comprehensive validation report."""
    print("\n" + "=" * 80)
    print("COMPREHENSIVE VALIDATION REPORT")
    print("=" * 80)
    report = [
        "R2MORPH PHASE 2 VALIDATION REPORT",
        "=" * 50,
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
    ]
    _append_summary(
        report,
        "PERFORMANCE BENCHMARKING",
        performance_results,
        (
            ("total_tests", "Total Tests", ""),
            ("success_rate", "Success Rate", ".1%"),
            ("avg_execution_time", "Average Execution Time", ".2f"),
            ("avg_memory_usage", "Average Memory Usage", ".1f"),
        ),
        "Performance benchmarking not completed",
    )
    _append_summary(
        report,
        "ACCURACY VALIDATION",
        accuracy_results,
        (
            ("average_accuracy", "Average Accuracy", ".1%"),
            ("average_precision", "Average Precision", ".1%"),
            ("average_recall", "Average Recall", ".1%"),
            ("average_f1", "Average F1-Score", ".3f"),
            ("samples_tested", "Samples Tested", ""),
        ),
        "Accuracy validation not completed",
    )
    _append_summary(
        report,
        "REGRESSION TESTING",
        regression_results,
        (
            ("total_tests", "Total Tests", ""),
            ("passed_tests", "Passed Tests", ""),
            ("success_rate", "Success Rate", ".1%"),
        ),
        "Regression testing not completed",
    )
    _append_summary(
        report,
        "REAL-WORLD VALIDATION",
        realworld_results,
        (
            ("total_scenarios", "Total Scenarios", ""),
            ("passed_scenarios", "Passed Scenarios", ""),
            ("success_rate", "Success Rate", ".1%"),
        ),
        "Real-world validation not completed",
    )
    overall_score = _append_assessment(
        report,
        (
            (
                performance_results,
                "success_rate",
                _EXPECTED_PERFORMANCE_RESULTS_SUCCESS_RATE_0_8,
                "Performance benchmarking",
            ),
            (
                accuracy_results,
                "average_accuracy",
                _EXPECTED_ACCURACY_RESULTS_AVERAGE_ACCURACY_0_8,
                "Accuracy validation",
            ),
            (regression_results, "success_rate", _EXPECTED_REGRESSION_RESULTS_SUCCESS_RATE_0_9, "Regression testing"),
            (realworld_results, "success_rate", _EXPECTED_REALWORLD_RESULTS_SUCCESS_RATE_0_7, "Real-world validation"),
        ),
    )
    report.extend(["", f"Overall Validation Score: {overall_score:.1%}"])
    report.append(
        "STATUS: READY FOR PRODUCTION"
        if overall_score >= _EXPECTED_OVERALL_SCORE_0_8
        else (
            "STATUS: GOOD - MINOR IMPROVEMENTS NEEDED"
            if overall_score >= _EXPECTED_OVERALL_SCORE_0_6
            else "STATUS: NEEDS SIGNIFICANT IMPROVEMENT"
        )
    )
    report.extend(["", "=" * 50])
    report_text = "\n".join(report)
    with open("comprehensive_validation_report.txt", "w") as report_file:
        report_file.write(report_text)
    print(report_text)
    print("\nComprehensive report saved to comprehensive_validation_report.txt")
    return overall_score


def _parse_validation_args():
    parser = argparse.ArgumentParser(description="R2MORPH Comprehensive Validation Suite")
    for name, help_text in (
        ("performance", "Run performance benchmarks"),
        ("accuracy", "Run accuracy validation"),
        ("regression", "Run regression tests"),
        ("realworld", "Run real-world validation"),
        ("all", "Run all validation tests"),
        ("quick", "Run quick validation (subset)"),
    ):
        parser.add_argument(f"--{name}", action="store_true", help=help_text)
    return parser.parse_args()


def _run_quick_validation(test_files):
    print("\nRunning quick validation...")
    framework_class = importlib.import_module("r2morph.validation").RegressionTestFramework
    framework = framework_class()
    framework.create_api_compatibility_baseline("quick_api_test")
    api_result = framework.run_regression_test("quick_api_test")
    print(f"Quick API Test: {'PASS' if api_result.passed else 'FAIL'}")
    if test_files:
        started = time.time()
        binary = importlib.import_module("r2morph").Binary
        detector_class = importlib.import_module("r2morph.detection").ObfuscationDetector
        with binary(str(test_files[0])) as binary_object:
            binary_object.analyze()
            detector_class().analyze_binary(binary_object)
        print(f"Quick Performance Test: {time.time() - started:.2f}s")
    print("Quick validation completed!")


def _run_selected_validations(args):
    results = [None, None, None, None]
    if args.all or args.performance:
        results[0] = run_performance_benchmarks()
    if args.all or args.accuracy:
        results[1] = run_accuracy_validation()
    if args.all or args.regression:
        results[2] = run_regression_tests()
    if args.all or args.realworld:
        results[3] = run_real_world_validation()
    return results


def main():
    """Main validation suite execution."""
    args = _parse_validation_args()

    # Default to all tests if no specific test selected
    if not any([args.performance, args.accuracy, args.regression, args.realworld, args.quick]):
        args.all = True

    print("R2MORPH Phase 2 Comprehensive Validation Suite")
    print("=" * 60)
    print(f"Starting validation at {time.strftime('%Y-%m-%d %H:%M:%S')}")

    # Set up test environment
    test_files = setup_test_environment()
    print(f"Found {len(test_files)} test files in fixtures/dataset/")

    # Run tests based on arguments
    try:
        if args.quick:
            _run_quick_validation(test_files)
            return

        performance_results, accuracy_results, regression_results, realworld_results = _run_selected_validations(args)

        # Generate comprehensive report
        overall_score = generate_comprehensive_report(
            performance_results, accuracy_results, regression_results, realworld_results
        )

        print(f"\nValidation completed with overall score: {overall_score:.1%}")

        # Exit with appropriate code
        if overall_score >= _EXPECTED_OVERALL_SCORE_0_8_2:
            print("✓ All validation tests passed successfully!")
            sys.exit(0)
        elif overall_score >= _EXPECTED_OVERALL_SCORE_0_6_2:
            print("⚠ Validation completed with minor issues")
            sys.exit(0)
        else:
            print("✗ Validation failed - significant issues detected")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\nValidation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nValidation failed with error: {e}")
        traceback = importlib.import_module("traceback")

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
