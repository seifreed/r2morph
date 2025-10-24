"""
Comprehensive validation suite demonstration for r2morph Phase 2.

This example shows how to use the complete validation framework including:
- Performance benchmarking
- Accuracy validation  
- Regression testing
- Real-world validation scenarios
"""

import argparse
import sys
import time
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def setup_test_environment():
    """Set up the test environment with sample files."""
    dataset_dir = Path("dataset")
    dataset_dir.mkdir(exist_ok=True)
    
    # Check if test files exist
    test_files = [
        dataset_dir / "simple",
        dataset_dir / "loop", 
        dataset_dir / "conditional"
    ]
    
    existing_files = [f for f in test_files if f.exists()]
    
    if not existing_files:
        logger.warning("No test files found in dataset/ directory")
        logger.info("Please ensure test binaries are available for comprehensive validation")
        return []
    
    return existing_files


def run_performance_benchmarks():
    """Run comprehensive performance benchmarks."""
    print("\n" + "="*80)
    print("PERFORMANCE BENCHMARKING")
    print("="*80)
    
    try:
        from r2morph.validation import ValidationFramework, BenchmarkCategory
        
        # Initialize validation framework
        framework = ValidationFramework("dataset")
        
        print(f"Loaded {len(framework.test_samples)} test samples")
        
        # Run performance-focused benchmarks
        benchmark_categories = [
            BenchmarkCategory.DETECTION,
            BenchmarkCategory.DEVIRTUALIZATION,
            BenchmarkCategory.FULL_PIPELINE
        ]
        
        print("Running performance benchmarks...")
        start_time = time.time()
        
        results = framework.run_validation_suite(benchmark_categories)
        
        execution_time = time.time() - start_time
        
        # Display summary
        print(f"\nBenchmark Results Summary:")
        print(f"  Total Tests: {results['total_tests']}")
        print(f"  Success Rate: {results['success_rate']:.1%}")
        print(f"  Average Execution Time: {results['avg_execution_time']:.2f}s")
        print(f"  Average Memory Usage: {results['avg_memory_usage']:.1f}MB")
        print(f"  Total Benchmark Time: {execution_time:.2f}s")
        
        # Category breakdown
        if results['categories']:
            print(f"\nCategory Performance:")
            for category, stats in results['categories'].items():
                print(f"  {category.upper()}:")
                print(f"    Success Rate: {stats['success_rate']:.1%}")
                print(f"    Average Time: {stats['avg_time']:.2f}s")
        
        # Export results
        framework.export_results("performance_benchmark_results.json", "json")
        print(f"\nDetailed results exported to performance_benchmark_results.json")
        
        return results
        
    except ImportError as e:
        print(f"Error: Missing dependencies for benchmarking: {e}")
        return None
    except Exception as e:
        print(f"Benchmarking failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def run_accuracy_validation():
    """Run accuracy validation against known samples."""
    print("\n" + "="*80)
    print("ACCURACY VALIDATION")
    print("="*80)
    
    try:
        from r2morph.validation import ValidationFramework
        
        framework = ValidationFramework("dataset")
        
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
                    print(f"    No accuracy metrics available")
                
                print(f"    Performance: {result.performance.execution_time:.2f}s")
                
            except Exception as e:
                print(f"    Error: {e}")
        
        if accuracy_results:
            # Calculate overall accuracy metrics
            avg_accuracy = sum(r.accuracy for r in accuracy_results) / len(accuracy_results)
            avg_precision = sum(r.precision for r in accuracy_results) / len(accuracy_results)
            avg_recall = sum(r.recall for r in accuracy_results) / len(accuracy_results)
            avg_f1 = sum(r.f1_score for r in accuracy_results) / len(accuracy_results)
            
            print(f"\nOverall Accuracy Metrics:")
            print(f"  Average Accuracy: {avg_accuracy:.1%}")
            print(f"  Average Precision: {avg_precision:.1%}")
            print(f"  Average Recall: {avg_recall:.1%}")
            print(f"  Average F1-Score: {avg_f1:.3f}")
            print(f"  Samples Tested: {len(accuracy_results)}")
            
            return {
                'average_accuracy': avg_accuracy,
                'average_precision': avg_precision,
                'average_recall': avg_recall,
                'average_f1': avg_f1,
                'samples_tested': len(accuracy_results)
            }
        else:
            print("No accuracy results available")
            return None
        
    except Exception as e:
        print(f"Accuracy validation failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def run_regression_tests():
    """Run regression tests to ensure backward compatibility."""
    print("\n" + "="*80)
    print("REGRESSION TESTING")
    print("="*80)
    
    try:
        from r2morph.validation import RegressionTestFramework
        
        # Initialize regression framework
        framework = RegressionTestFramework("regression_baselines")
        
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
        
        print(f"\nRegression test report saved to regression_test_report.txt")
        
        # Summary
        total_tests = len(framework.test_results)
        passed_tests = sum(1 for r in framework.test_results if r.passed)
        
        print(f"\nRegression Testing Summary:")
        print(f"  Total Tests: {total_tests}")
        print(f"  Passed: {passed_tests}")
        print(f"  Failed: {total_tests - passed_tests}")
        print(f"  Success Rate: {passed_tests/total_tests:.1%}" if total_tests > 0 else "  Success Rate: N/A")
        
        return {
            'total_tests': total_tests,
            'passed_tests': passed_tests,
            'success_rate': passed_tests/total_tests if total_tests > 0 else 0.0
        }
        
    except Exception as e:
        print(f"Regression testing failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def run_real_world_validation():
    """Run validation against real-world scenarios."""
    print("\n" + "="*80)
    print("REAL-WORLD VALIDATION")
    print("="*80)
    
    try:
        from r2morph import Binary
        from r2morph.detection import ObfuscationDetector
        from r2morph.devirtualization import CFOSimplifier, IterativeSimplifier, SimplificationStrategy
        
        test_files = setup_test_environment()
        
        if not test_files:
            print("No test files available for real-world validation")
            return None
        
        validation_results = []
        
        for test_file in test_files[:2]:  # Test first 2 files
            print(f"\nValidating real-world scenario: {test_file.name}")
            
            scenario_start = time.time()
            
            try:
                with Binary(str(test_file)) as bin_obj:
                    bin_obj.analyze()
                    
                    # Step 1: Detection
                    print(f"  1. Running detection analysis...")
                    detector = ObfuscationDetector()
                    detection_result = detector.analyze_binary(bin_obj)
                    
                    detected_techniques = len(detection_result.obfuscation_techniques)
                    confidence = detection_result.confidence_score
                    
                    print(f"     Detected {detected_techniques} techniques (confidence: {confidence:.2f})")
                    
                    # Step 2: Devirtualization (if applicable)
                    devirt_success = False
                    complexity_reduction = 0.0
                    
                    if detection_result.vm_detected or detection_result.control_flow_flattened:
                        print(f"  2. Running devirtualization...")
                        
                        try:
                            # CFO Simplification
                            cfo_simplifier = CFOSimplifier(bin_obj)
                            functions = bin_obj.get_functions()[:2]  # Test 2 functions
                            
                            for func in functions:
                                func_addr = func.get('offset', 0)
                                result = cfo_simplifier.simplify_control_flow(func_addr)
                                if result.success:
                                    complexity_reduction += result.original_complexity - result.simplified_complexity
                            
                            # Iterative Simplification
                            if complexity_reduction > 0:
                                iterative_simplifier = IterativeSimplifier(bin_obj)
                                iter_result = iterative_simplifier.simplify(
                                    strategy=SimplificationStrategy.FAST,
                                    max_iterations=2,
                                    timeout=15
                                )
                                
                                if iter_result.success:
                                    devirt_success = True
                                    print(f"     Devirtualization successful: {complexity_reduction:.1f} complexity reduced")
                                else:
                                    print(f"     Iterative simplification failed")
                            else:
                                print(f"     No complexity reduction achieved")
                        
                        except Exception as e:
                            print(f"     Devirtualization error: {e}")
                    else:
                        print(f"  2. Skipping devirtualization (not needed)")
                    
                    # Step 3: Validation
                    print(f"  3. Validating results...")
                    
                    scenario_time = time.time() - scenario_start
                    
                    # Simple validation criteria
                    validation_passed = True
                    issues = []
                    
                    if confidence < 0.3:
                        issues.append("Low confidence score")
                        validation_passed = False
                    
                    if scenario_time > 60:  # 1 minute timeout
                        issues.append("Execution time too long")
                        validation_passed = False
                    
                    if detection_result.vm_detected and not devirt_success and complexity_reduction == 0:
                        issues.append("VM detected but no devirtualization performed")
                        # This is a warning, not a failure
                    
                    status = "PASS" if validation_passed else "FAIL"
                    print(f"     Validation: {status} ({scenario_time:.2f}s)")
                    
                    if issues:
                        for issue in issues:
                            print(f"     Issue: {issue}")
                    
                    validation_results.append({
                        'file': test_file.name,
                        'passed': validation_passed,
                        'execution_time': scenario_time,
                        'techniques_detected': detected_techniques,
                        'confidence': confidence,
                        'devirt_success': devirt_success,
                        'complexity_reduction': complexity_reduction,
                        'issues': issues
                    })
            
            except Exception as e:
                print(f"  Error during validation: {e}")
                validation_results.append({
                    'file': test_file.name,
                    'passed': False,
                    'execution_time': time.time() - scenario_start,
                    'error': str(e)
                })
        
        # Summary
        print(f"\nReal-World Validation Summary:")
        total_scenarios = len(validation_results)
        passed_scenarios = sum(1 for r in validation_results if r.get('passed', False))
        
        print(f"  Total Scenarios: {total_scenarios}")
        print(f"  Passed: {passed_scenarios}")
        print(f"  Failed: {total_scenarios - passed_scenarios}")
        print(f"  Success Rate: {passed_scenarios/total_scenarios:.1%}" if total_scenarios > 0 else "  Success Rate: N/A")
        
        if validation_results:
            avg_time = sum(r.get('execution_time', 0) for r in validation_results) / len(validation_results)
            print(f"  Average Execution Time: {avg_time:.2f}s")
        
        return {
            'total_scenarios': total_scenarios,
            'passed_scenarios': passed_scenarios,
            'success_rate': passed_scenarios/total_scenarios if total_scenarios > 0 else 0.0,
            'results': validation_results
        }
        
    except Exception as e:
        print(f"Real-world validation failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def generate_comprehensive_report(performance_results, accuracy_results, regression_results, realworld_results):
    """Generate a comprehensive validation report."""
    print("\n" + "="*80)
    print("COMPREHENSIVE VALIDATION REPORT")
    print("="*80)
    
    report = []
    report.append("R2MORPH PHASE 2 VALIDATION REPORT")
    report.append("="*50)
    report.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("")
    
    # Performance Summary
    report.append("PERFORMANCE BENCHMARKING")
    report.append("-"*30)
    if performance_results:
        report.append(f"Total Tests: {performance_results['total_tests']}")
        report.append(f"Success Rate: {performance_results['success_rate']:.1%}")
        report.append(f"Average Execution Time: {performance_results['avg_execution_time']:.2f}s")
        report.append(f"Average Memory Usage: {performance_results['avg_memory_usage']:.1f}MB")
    else:
        report.append("Performance benchmarking not completed")
    report.append("")
    
    # Accuracy Summary
    report.append("ACCURACY VALIDATION")
    report.append("-"*30)
    if accuracy_results:
        report.append(f"Average Accuracy: {accuracy_results['average_accuracy']:.1%}")
        report.append(f"Average Precision: {accuracy_results['average_precision']:.1%}")
        report.append(f"Average Recall: {accuracy_results['average_recall']:.1%}")
        report.append(f"Average F1-Score: {accuracy_results['average_f1']:.3f}")
        report.append(f"Samples Tested: {accuracy_results['samples_tested']}")
    else:
        report.append("Accuracy validation not completed")
    report.append("")
    
    # Regression Summary
    report.append("REGRESSION TESTING")
    report.append("-"*30)
    if regression_results:
        report.append(f"Total Tests: {regression_results['total_tests']}")
        report.append(f"Passed Tests: {regression_results['passed_tests']}")
        report.append(f"Success Rate: {regression_results['success_rate']:.1%}")
    else:
        report.append("Regression testing not completed")
    report.append("")
    
    # Real-World Summary
    report.append("REAL-WORLD VALIDATION")
    report.append("-"*30)
    if realworld_results:
        report.append(f"Total Scenarios: {realworld_results['total_scenarios']}")
        report.append(f"Passed Scenarios: {realworld_results['passed_scenarios']}")
        report.append(f"Success Rate: {realworld_results['success_rate']:.1%}")
    else:
        report.append("Real-world validation not completed")
    report.append("")
    
    # Overall Assessment
    report.append("OVERALL ASSESSMENT")
    report.append("-"*30)
    
    total_categories = 4
    successful_categories = 0
    
    if performance_results and performance_results['success_rate'] > 0.8:
        successful_categories += 1
        report.append("✓ Performance benchmarking: GOOD")
    else:
        report.append("✗ Performance benchmarking: NEEDS IMPROVEMENT")
    
    if accuracy_results and accuracy_results['average_accuracy'] > 0.8:
        successful_categories += 1
        report.append("✓ Accuracy validation: GOOD")
    else:
        report.append("✗ Accuracy validation: NEEDS IMPROVEMENT")
    
    if regression_results and regression_results['success_rate'] > 0.9:
        successful_categories += 1
        report.append("✓ Regression testing: GOOD")
    else:
        report.append("✗ Regression testing: NEEDS IMPROVEMENT")
    
    if realworld_results and realworld_results['success_rate'] > 0.7:
        successful_categories += 1
        report.append("✓ Real-world validation: GOOD")
    else:
        report.append("✗ Real-world validation: NEEDS IMPROVEMENT")
    
    overall_score = successful_categories / total_categories
    report.append("")
    report.append(f"Overall Validation Score: {overall_score:.1%}")
    
    if overall_score >= 0.8:
        report.append("STATUS: READY FOR PRODUCTION")
    elif overall_score >= 0.6:
        report.append("STATUS: GOOD - MINOR IMPROVEMENTS NEEDED")
    else:
        report.append("STATUS: NEEDS SIGNIFICANT IMPROVEMENT")
    
    report.append("")
    report.append("="*50)
    
    # Save and display report
    report_text = "\n".join(report)
    
    with open("comprehensive_validation_report.txt", "w") as f:
        f.write(report_text)
    
    print(report_text)
    print(f"\nComprehensive report saved to comprehensive_validation_report.txt")
    
    return overall_score


def main():
    """Main validation suite execution."""
    parser = argparse.ArgumentParser(description="R2MORPH Comprehensive Validation Suite")
    parser.add_argument("--performance", action="store_true", help="Run performance benchmarks")
    parser.add_argument("--accuracy", action="store_true", help="Run accuracy validation")
    parser.add_argument("--regression", action="store_true", help="Run regression tests")
    parser.add_argument("--realworld", action="store_true", help="Run real-world validation")
    parser.add_argument("--all", action="store_true", help="Run all validation tests")
    parser.add_argument("--quick", action="store_true", help="Run quick validation (subset)")
    
    args = parser.parse_args()
    
    # Default to all tests if no specific test selected
    if not any([args.performance, args.accuracy, args.regression, args.realworld, args.quick]):
        args.all = True
    
    print("R2MORPH Phase 2 Comprehensive Validation Suite")
    print("="*60)
    print(f"Starting validation at {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Initialize results
    performance_results = None
    accuracy_results = None
    regression_results = None
    realworld_results = None
    
    # Set up test environment
    test_files = setup_test_environment()
    print(f"Found {len(test_files)} test files in dataset/")
    
    # Run tests based on arguments
    try:
        if args.all or args.performance:
            performance_results = run_performance_benchmarks()
        
        if args.all or args.accuracy:
            accuracy_results = run_accuracy_validation()
        
        if args.all or args.regression:
            regression_results = run_regression_tests()
        
        if args.all or args.realworld:
            realworld_results = run_real_world_validation()
        
        if args.quick:
            # Quick validation - just API compatibility and one performance test
            print("\nRunning quick validation...")
            from r2morph.validation import RegressionTestFramework
            
            framework = RegressionTestFramework()
            framework.create_api_compatibility_baseline("quick_api_test")
            api_result = framework.run_regression_test("quick_api_test")
            
            print(f"Quick API Test: {'PASS' if api_result.passed else 'FAIL'}")
            
            if test_files:
                performance_start = time.time()
                from r2morph import Binary
                from r2morph.detection import ObfuscationDetector
                
                with Binary(str(test_files[0])) as bin_obj:
                    bin_obj.analyze()
                    detector = ObfuscationDetector()
                    detector.analyze_binary(bin_obj)
                
                performance_time = time.time() - performance_start
                print(f"Quick Performance Test: {performance_time:.2f}s")
            
            print("Quick validation completed!")
            return
        
        # Generate comprehensive report
        overall_score = generate_comprehensive_report(
            performance_results, accuracy_results, regression_results, realworld_results
        )
        
        print(f"\nValidation completed with overall score: {overall_score:.1%}")
        
        # Exit with appropriate code
        if overall_score >= 0.8:
            print("✓ All validation tests passed successfully!")
            sys.exit(0)
        elif overall_score >= 0.6:
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
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()