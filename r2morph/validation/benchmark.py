"""
Real-world validation and benchmarking framework for r2morph.

This module provides comprehensive testing capabilities including:
- Performance benchmarking
- Accuracy metrics against known samples
- Regression testing
- Real-world validation scenarios
"""

import time
import json
import statistics
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
from enum import Enum
import hashlib
import logging

# Type checking for optional dependencies
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

logger = logging.getLogger(__name__)


class BenchmarkCategory(Enum):
    """Categories for benchmark testing."""
    DETECTION = "detection"
    DEVIRTUALIZATION = "devirtualization"
    DEOBFUSCATION = "deobfuscation"
    BYPASS = "bypass"
    FULL_PIPELINE = "full_pipeline"


class TestSeverity(Enum):
    """Test severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class PerformanceMetrics:
    """Performance metrics for analysis operations."""
    execution_time: float
    memory_usage_mb: float
    cpu_usage_percent: float
    peak_memory_mb: float
    success: bool
    error_message: Optional[str] = None


@dataclass
class AccuracyMetrics:
    """Accuracy metrics for analysis results."""
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    accuracy: float


@dataclass
class TestSample:
    """Represents a test sample with known characteristics."""
    file_path: str
    sample_hash: str
    expected_packer: Optional[str]
    expected_vm_protection: bool
    expected_anti_analysis: bool
    expected_cfo: bool
    expected_mba: bool
    severity: TestSeverity
    description: str
    source: str  # Where the sample came from
    
    @property
    def file_exists(self) -> bool:
        """Check if the test file exists."""
        return Path(self.file_path).exists()
    
    def verify_hash(self) -> bool:
        """Verify the sample's hash."""
        if not self.file_exists:
            return False
        
        try:
            with open(self.file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
                return file_hash == self.sample_hash
        except Exception:
            return False


@dataclass
class BenchmarkResult:
    """Result of a benchmark test."""
    sample: TestSample
    category: BenchmarkCategory
    performance: PerformanceMetrics
    accuracy: Optional[AccuracyMetrics]
    analysis_result: Dict[str, Any]
    timestamp: str
    r2morph_version: str


class ValidationFramework:
    """
    Comprehensive validation framework for r2morph analysis capabilities.
    """
    
    def __init__(self, test_data_dir: Optional[str] = None):
        """
        Initialize the validation framework.
        
        Args:
            test_data_dir: Directory containing test samples
        """
        self.test_data_dir = Path(test_data_dir) if test_data_dir else Path("dataset")
        self.test_samples: List[TestSample] = []
        self.benchmark_results: List[BenchmarkResult] = []
        
        # Load test samples
        self._load_test_samples()
    
    def _load_test_samples(self):
        """Load predefined test samples."""
        # Add known test samples for benchmarking purposes
        test_samples_data = [
            {
                "file_path": str(self.test_data_dir / "vmprotect_sample.exe"),
                "sample_hash": "abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234",
                "expected_packer": "VMProtect",
                "expected_vm_protection": True,
                "expected_anti_analysis": True,
                "expected_cfo": True,
                "expected_mba": True,
                "severity": TestSeverity.CRITICAL,
                "description": "VMProtect 3.x protected binary with full virtualization",
                "source": "research_collection"
            },
            {
                "file_path": str(self.test_data_dir / "themida_sample.exe"),
                "sample_hash": "efgh5678901234efgh5678901234efgh5678901234efgh5678901234efgh5678",
                "expected_packer": "Themida",
                "expected_vm_protection": True,
                "expected_anti_analysis": True,
                "expected_cfo": True,
                "expected_mba": False,
                "severity": TestSeverity.CRITICAL,
                "description": "Themida protected binary with anti-debugging",
                "source": "malware_zoo"
            },
            {
                "file_path": str(self.test_data_dir / "upx_sample.exe"),
                "sample_hash": "ijkl9012345678ijkl9012345678ijkl9012345678ijkl9012345678ijkl9012",
                "expected_packer": "UPX",
                "expected_vm_protection": False,
                "expected_anti_analysis": False,
                "expected_cfo": False,
                "expected_mba": False,
                "severity": TestSeverity.LOW,
                "description": "Simple UPX compressed binary",
                "source": "test_samples"
            },
            {
                "file_path": str(self.test_data_dir / "custom_vm_sample.exe"),
                "sample_hash": "mnop3456789012mnop3456789012mnop3456789012mnop3456789012mnop3456",
                "expected_packer": "Custom",
                "expected_vm_protection": True,
                "expected_anti_analysis": True,
                "expected_cfo": True,
                "expected_mba": True,
                "severity": TestSeverity.HIGH,
                "description": "Custom virtualization engine with MBA obfuscation",
                "source": "academic_research"
            },
            {
                "file_path": str(self.test_data_dir / "clean_sample.exe"),
                "sample_hash": "qrst7890123456qrst7890123456qrst7890123456qrst7890123456qrst7890",
                "expected_packer": None,
                "expected_vm_protection": False,
                "expected_anti_analysis": False,
                "expected_cfo": False,
                "expected_mba": False,
                "severity": TestSeverity.LOW,
                "description": "Clean unobfuscated binary",
                "source": "control_group"
            }
        ]
        
        self.test_samples = [TestSample(**data) for data in test_samples_data]
    
    def add_test_sample(self, sample: TestSample):
        """Add a new test sample."""
        self.test_samples.append(sample)
    
    def _measure_performance(self, func, *args, **kwargs) -> PerformanceMetrics:
        """
        Measure performance metrics for a function execution.
        
        Args:
            func: Function to measure
            *args: Function arguments
            **kwargs: Function keyword arguments
        
        Returns:
            PerformanceMetrics object
        """
        # Initialize metrics
        start_memory = 0
        peak_memory = 0
        cpu_percent = 0
        
        if HAS_PSUTIL:
            process = psutil.Process()
            start_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        start_time = time.time()
        success = True
        error_message = None
        
        try:
            # Execute function
            result = func(*args, **kwargs)
            
            if HAS_PSUTIL:
                peak_memory = process.memory_info().rss / 1024 / 1024  # MB
                cpu_percent = process.cpu_percent()
        
        except Exception as e:
            success = False
            error_message = str(e)
            result = None
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        if HAS_PSUTIL:
            end_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_usage = end_memory - start_memory
        else:
            memory_usage = 0
            peak_memory = 0
            cpu_percent = 0
        
        return PerformanceMetrics(
            execution_time=execution_time,
            memory_usage_mb=memory_usage,
            cpu_usage_percent=cpu_percent,
            peak_memory_mb=peak_memory,
            success=success,
            error_message=error_message
        ), result
    
    def _calculate_accuracy_metrics(self, expected: Dict[str, Any], actual: Dict[str, Any]) -> AccuracyMetrics:
        """
        Calculate accuracy metrics by comparing expected vs actual results.
        
        Args:
            expected: Expected analysis results
            actual: Actual analysis results
        
        Returns:
            AccuracyMetrics object
        """
        # Define comparison fields
        fields = [
            'packer_detected',
            'vm_protection',
            'anti_analysis',
            'cfo_detected',
            'mba_detected'
        ]
        
        tp = fp = tn = fn = 0
        
        for field in fields:
            exp_val = expected.get(field, False)
            act_val = actual.get(field, False)
            
            if exp_val and act_val:
                tp += 1
            elif not exp_val and act_val:
                fp += 1
            elif not exp_val and not act_val:
                tn += 1
            else:  # exp_val and not act_val
                fn += 1
        
        # Calculate metrics
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0
        
        return AccuracyMetrics(
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            f1_score=f1_score,
            accuracy=accuracy
        )
    
    def benchmark_detection(self, sample: TestSample) -> BenchmarkResult:
        """
        Benchmark obfuscation detection on a sample.
        
        Args:
            sample: Test sample to analyze
        
        Returns:
            BenchmarkResult
        """
        from r2morph import Binary
        from r2morph.detection import ObfuscationDetector
        
        def run_detection():
            with Binary(sample.file_path) as bin_obj:
                bin_obj.analyze()
                detector = ObfuscationDetector()
                result = detector.analyze_binary(bin_obj)
                
                return {
                    'packer_detected': result.packer_detected.value if result.packer_detected else None,
                    'vm_protection': result.vm_detected,
                    'anti_analysis': result.anti_analysis_detected,
                    'cfo_detected': result.control_flow_flattened,
                    'mba_detected': result.mba_detected,
                    'confidence_score': result.confidence_score,
                    'techniques_count': len(result.obfuscation_techniques)
                }
        
        # Measure performance
        performance, analysis_result = self._measure_performance(run_detection)
        
        # Calculate accuracy if analysis succeeded
        accuracy = None
        if performance.success and analysis_result:
            expected = {
                'packer_detected': sample.expected_packer,
                'vm_protection': sample.expected_vm_protection,
                'anti_analysis': sample.expected_anti_analysis,
                'cfo_detected': sample.expected_cfo,
                'mba_detected': sample.expected_mba
            }
            accuracy = self._calculate_accuracy_metrics(expected, analysis_result)
        
        return BenchmarkResult(
            sample=sample,
            category=BenchmarkCategory.DETECTION,
            performance=performance,
            accuracy=accuracy,
            analysis_result=analysis_result or {},
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
            r2morph_version="2.0.0-phase2"
        )
    
    def benchmark_devirtualization(self, sample: TestSample) -> BenchmarkResult:
        """
        Benchmark devirtualization capabilities on a sample.
        
        Args:
            sample: Test sample to analyze
        
        Returns:
            BenchmarkResult
        """
        from r2morph import Binary
        from r2morph.devirtualization import CFOSimplifier, IterativeSimplifier, SimplificationStrategy
        
        def run_devirtualization():
            with Binary(sample.file_path) as bin_obj:
                bin_obj.analyze()
                
                # CFO Simplification
                cfo_simplifier = CFOSimplifier(bin_obj)
                functions = bin_obj.get_functions()[:3]  # Test on first 3 functions
                
                cfo_results = []
                for func in functions:
                    func_addr = func.get('offset', 0)
                    result = cfo_simplifier.simplify_control_flow(func_addr)
                    if result.success:
                        cfo_results.append({
                            'function': func_addr,
                            'complexity_reduction': result.original_complexity - result.simplified_complexity,
                            'patterns_detected': len(result.patterns_detected)
                        })
                
                # Iterative Simplification
                iterative_simplifier = IterativeSimplifier(bin_obj)
                iter_result = iterative_simplifier.simplify(
                    strategy=SimplificationStrategy.BALANCED,
                    max_iterations=3,  # Reduced for benchmarking
                    timeout=30
                )
                
                return {
                    'cfo_functions_simplified': len(cfo_results),
                    'cfo_total_complexity_reduction': sum(r['complexity_reduction'] for r in cfo_results),
                    'iterative_success': iter_result.success,
                    'iterative_iterations': iter_result.metrics.iteration if iter_result.success else 0,
                    'iterative_complexity_reduction': iter_result.metrics.complexity_reduction if iter_result.success else 0.0
                }
        
        # Measure performance
        performance, analysis_result = self._measure_performance(run_devirtualization)
        
        return BenchmarkResult(
            sample=sample,
            category=BenchmarkCategory.DEVIRTUALIZATION,
            performance=performance,
            accuracy=None,  # Devirtualization accuracy is more complex to measure
            analysis_result=analysis_result or {},
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
            r2morph_version="2.0.0-phase2"
        )
    
    def benchmark_full_pipeline(self, sample: TestSample) -> BenchmarkResult:
        """
        Benchmark the full analysis pipeline on a sample.
        
        Args:
            sample: Test sample to analyze
        
        Returns:
            BenchmarkResult
        """
        from r2morph import Binary
        from r2morph.detection import ObfuscationDetector, AntiAnalysisBypass
        from r2morph.devirtualization import CFOSimplifier, IterativeSimplifier, SimplificationStrategy
        
        def run_full_pipeline():
            with Binary(sample.file_path) as bin_obj:
                bin_obj.analyze()
                
                # Step 1: Detection
                detector = ObfuscationDetector()
                detection_result = detector.analyze_binary(bin_obj)
                
                # Step 2: Anti-Analysis Bypass
                bypass_framework = AntiAnalysisBypass()
                detected_techniques = bypass_framework.detect_anti_analysis_techniques(bin_obj)
                bypass_applied = len(detected_techniques) > 0
                
                # Step 3: Devirtualization (if needed)
                devirt_performed = False
                complexity_reduction = 0.0
                
                if detection_result.vm_detected or detection_result.control_flow_flattened:
                    # CFO Simplification
                    cfo_simplifier = CFOSimplifier(bin_obj)
                    functions = bin_obj.get_functions()[:2]  # Limited for performance
                    
                    for func in functions:
                        func_addr = func.get('offset', 0)
                        result = cfo_simplifier.simplify_control_flow(func_addr)
                        if result.success:
                            complexity_reduction += result.original_complexity - result.simplified_complexity
                    
                    # Iterative Simplification
                    iterative_simplifier = IterativeSimplifier(bin_obj)
                    iter_result = iterative_simplifier.simplify(
                        strategy=SimplificationStrategy.FAST,
                        max_iterations=2,
                        timeout=20
                    )
                    
                    if iter_result.success:
                        complexity_reduction += iter_result.metrics.complexity_reduction
                        devirt_performed = True
                
                return {
                    'detection_confidence': detection_result.confidence_score,
                    'packer_detected': detection_result.packer_detected.value if detection_result.packer_detected else None,
                    'vm_detected': detection_result.vm_detected,
                    'anti_analysis_bypass_applied': bypass_applied,
                    'devirtualization_performed': devirt_performed,
                    'total_complexity_reduction': complexity_reduction,
                    'obfuscation_techniques_count': len(detection_result.obfuscation_techniques),
                    'pipeline_completed': True
                }
        
        # Measure performance
        performance, analysis_result = self._measure_performance(run_full_pipeline)
        
        # Calculate accuracy
        accuracy = None
        if performance.success and analysis_result:
            expected = {
                'packer_detected': sample.expected_packer,
                'vm_protection': sample.expected_vm_protection,
                'anti_analysis': sample.expected_anti_analysis,
                'cfo_detected': sample.expected_cfo,
                'mba_detected': sample.expected_mba
            }
            
            actual = {
                'packer_detected': analysis_result.get('packer_detected'),
                'vm_protection': analysis_result.get('vm_detected', False),
                'anti_analysis': analysis_result.get('anti_analysis_bypass_applied', False),
                'cfo_detected': analysis_result.get('devirtualization_performed', False),
                'mba_detected': False  # Would need MBA-specific detection
            }
            
            accuracy = self._calculate_accuracy_metrics(expected, actual)
        
        return BenchmarkResult(
            sample=sample,
            category=BenchmarkCategory.FULL_PIPELINE,
            performance=performance,
            accuracy=accuracy,
            analysis_result=analysis_result or {},
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
            r2morph_version="2.0.0-phase2"
        )
    
    def run_validation_suite(self, categories: Optional[List[BenchmarkCategory]] = None) -> Dict[str, Any]:
        """
        Run the complete validation suite.
        
        Args:
            categories: List of benchmark categories to run (all if None)
        
        Returns:
            Validation results summary
        """
        if categories is None:
            categories = [
                BenchmarkCategory.DETECTION,
                BenchmarkCategory.DEVIRTUALIZATION,
                BenchmarkCategory.FULL_PIPELINE
            ]
        
        logger.info(f"Starting validation suite with {len(self.test_samples)} samples")
        logger.info(f"Categories: {[cat.value for cat in categories]}")
        
        results = []
        
        for sample in self.test_samples:
            if not sample.file_exists:
                logger.warning(f"Sample file not found: {sample.file_path}")
                continue
            
            if not sample.verify_hash():
                logger.warning(f"Sample hash verification failed: {sample.file_path}")
                continue
            
            logger.info(f"Testing sample: {sample.description}")
            
            # Run benchmarks for each category
            for category in categories:
                try:
                    if category == BenchmarkCategory.DETECTION:
                        result = self.benchmark_detection(sample)
                    elif category == BenchmarkCategory.DEVIRTUALIZATION:
                        result = self.benchmark_devirtualization(sample)
                    elif category == BenchmarkCategory.FULL_PIPELINE:
                        result = self.benchmark_full_pipeline(sample)
                    else:
                        continue
                    
                    results.append(result)
                    self.benchmark_results.append(result)
                    
                    logger.info(f"  {category.value}: {'PASS' if result.performance.success else 'FAIL'} "
                              f"({result.performance.execution_time:.2f}s)")
                
                except Exception as e:
                    logger.error(f"Benchmark failed for {sample.file_path} ({category.value}): {e}")
        
        # Generate summary
        summary = self._generate_validation_summary(results)
        
        logger.info("Validation suite completed")
        logger.info(f"Total tests: {summary['total_tests']}")
        logger.info(f"Success rate: {summary['success_rate']:.1%}")
        logger.info(f"Average execution time: {summary['avg_execution_time']:.2f}s")
        
        return summary
    
    def _generate_validation_summary(self, results: List[BenchmarkResult]) -> Dict[str, Any]:
        """Generate a summary of validation results."""
        if not results:
            return {
                'total_tests': 0,
                'success_rate': 0.0,
                'avg_execution_time': 0.0,
                'avg_memory_usage': 0.0,
                'avg_accuracy': 0.0,
                'categories': {},
                'severity_breakdown': {}
            }
        
        # Overall metrics
        total_tests = len(results)
        successful_tests = sum(1 for r in results if r.performance.success)
        success_rate = successful_tests / total_tests
        
        execution_times = [r.performance.execution_time for r in results if r.performance.success]
        avg_execution_time = statistics.mean(execution_times) if execution_times else 0.0
        
        memory_usages = [r.performance.memory_usage_mb for r in results if r.performance.success]
        avg_memory_usage = statistics.mean(memory_usages) if memory_usages else 0.0
        
        # Accuracy metrics (where available)
        accuracy_scores = [r.accuracy.accuracy for r in results if r.accuracy is not None]
        avg_accuracy = statistics.mean(accuracy_scores) if accuracy_scores else 0.0
        
        # Category breakdown
        categories = {}
        for category in BenchmarkCategory:
            cat_results = [r for r in results if r.category == category]
            if cat_results:
                cat_success = sum(1 for r in cat_results if r.performance.success)
                cat_times = [r.performance.execution_time for r in cat_results if r.performance.success]
                
                categories[category.value] = {
                    'total': len(cat_results),
                    'successful': cat_success,
                    'success_rate': cat_success / len(cat_results),
                    'avg_time': statistics.mean(cat_times) if cat_times else 0.0
                }
        
        # Severity breakdown
        severity_breakdown = {}
        for severity in TestSeverity:
            sev_results = [r for r in results if r.sample.severity == severity]
            if sev_results:
                sev_success = sum(1 for r in sev_results if r.performance.success)
                severity_breakdown[severity.value] = {
                    'total': len(sev_results),
                    'successful': sev_success,
                    'success_rate': sev_success / len(sev_results)
                }
        
        return {
            'total_tests': total_tests,
            'successful_tests': successful_tests,
            'success_rate': success_rate,
            'avg_execution_time': avg_execution_time,
            'avg_memory_usage': avg_memory_usage,
            'avg_accuracy': avg_accuracy,
            'categories': categories,
            'severity_breakdown': severity_breakdown,
            'execution_time_percentiles': {
                'p50': statistics.median(execution_times) if execution_times else 0.0,
                'p95': statistics.quantiles(execution_times, n=20)[18] if len(execution_times) >= 20 else (max(execution_times) if execution_times else 0.0),
                'p99': statistics.quantiles(execution_times, n=100)[98] if len(execution_times) >= 100 else (max(execution_times) if execution_times else 0.0)
            }
        }
    
    def export_results(self, output_path: str, format: str = 'json'):
        """
        Export benchmark results to file.
        
        Args:
            output_path: Output file path
            format: Export format ('json' or 'csv')
        """
        if format.lower() == 'json':
            self._export_json(output_path)
        elif format.lower() == 'csv':
            self._export_csv(output_path)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def _export_json(self, output_path: str):
        """Export results as JSON."""
        export_data = {
            'metadata': {
                'export_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'r2morph_version': '2.0.0-phase2',
                'total_results': len(self.benchmark_results)
            },
            'summary': self._generate_validation_summary(self.benchmark_results),
            'results': [asdict(result) for result in self.benchmark_results]
        }
        
        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
    
    def _export_csv(self, output_path: str):
        """Export results as CSV."""
        try:
            import csv
            
            with open(output_path, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Header
                writer.writerow([
                    'sample_path', 'sample_hash', 'category', 'success',
                    'execution_time', 'memory_usage_mb', 'accuracy',
                    'precision', 'recall', 'f1_score', 'timestamp'
                ])
                
                # Data
                for result in self.benchmark_results:
                    writer.writerow([
                        result.sample.file_path,
                        result.sample.sample_hash,
                        result.category.value,
                        result.performance.success,
                        result.performance.execution_time,
                        result.performance.memory_usage_mb,
                        result.accuracy.accuracy if result.accuracy else '',
                        result.accuracy.precision if result.accuracy else '',
                        result.accuracy.recall if result.accuracy else '',
                        result.accuracy.f1_score if result.accuracy else '',
                        result.timestamp
                    ])
        
        except ImportError:
            # Fallback to simple text format if csv module not available
            with open(output_path, 'w') as f:
                f.write("sample_path,category,success,execution_time,memory_usage_mb,timestamp\n")
                for result in self.benchmark_results:
                    f.write(f"{result.sample.file_path},{result.category.value},"
                           f"{result.performance.success},{result.performance.execution_time},"
                           f"{result.performance.memory_usage_mb},{result.timestamp}\n")
    
    def generate_report(self) -> str:
        """Generate a human-readable validation report."""
        if not self.benchmark_results:
            return "No benchmark results available."
        
        summary = self._generate_validation_summary(self.benchmark_results)
        
        report = []
        report.append("=" * 80)
        report.append("R2MORPH VALIDATION REPORT")
        report.append("=" * 80)
        report.append("")
        
        # Overall Summary
        report.append("OVERALL SUMMARY")
        report.append("-" * 40)
        report.append(f"Total Tests:          {summary['total_tests']}")
        report.append(f"Successful Tests:     {summary['successful_tests']}")
        report.append(f"Success Rate:         {summary['success_rate']:.1%}")
        report.append(f"Average Execution:    {summary['avg_execution_time']:.2f}s")
        report.append(f"Average Memory:       {summary['avg_memory_usage']:.1f}MB")
        report.append(f"Average Accuracy:     {summary['avg_accuracy']:.1%}")
        report.append("")
        
        # Performance Percentiles
        report.append("PERFORMANCE PERCENTILES")
        report.append("-" * 40)
        percentiles = summary['execution_time_percentiles']
        report.append(f"P50 (Median):         {percentiles['p50']:.2f}s")
        report.append(f"P95:                  {percentiles['p95']:.2f}s")
        report.append(f"P99:                  {percentiles['p99']:.2f}s")
        report.append("")
        
        # Category Breakdown
        if summary['categories']:
            report.append("CATEGORY BREAKDOWN")
            report.append("-" * 40)
            for category, stats in summary['categories'].items():
                report.append(f"{category.upper()}:")
                report.append(f"  Tests:       {stats['total']}")
                report.append(f"  Success:     {stats['successful']} ({stats['success_rate']:.1%})")
                report.append(f"  Avg Time:    {stats['avg_time']:.2f}s")
                report.append("")
        
        # Severity Breakdown
        if summary['severity_breakdown']:
            report.append("SEVERITY BREAKDOWN")
            report.append("-" * 40)
            for severity, stats in summary['severity_breakdown'].items():
                report.append(f"{severity.upper()}:")
                report.append(f"  Tests:       {stats['total']}")
                report.append(f"  Success:     {stats['successful']} ({stats['success_rate']:.1%})")
                report.append("")
        
        # Recommendations
        report.append("RECOMMENDATIONS")
        report.append("-" * 40)
        
        if summary['success_rate'] < 0.8:
            report.append("⚠️  Success rate below 80% - review failed tests")
        else:
            report.append("✅ Good success rate")
        
        if summary['avg_execution_time'] > 30:
            report.append("⚠️  Average execution time > 30s - consider optimization")
        else:
            report.append("✅ Good performance")
        
        if summary['avg_accuracy'] < 0.8:
            report.append("⚠️  Average accuracy below 80% - review detection algorithms")
        else:
            report.append("✅ Good accuracy")
        
        report.append("")
        report.append("=" * 80)
        
        return "\n".join(report)


def main():
    """Example usage of the validation framework."""
    # Initialize framework
    framework = ValidationFramework()
    
    # Run validation suite
    print("Starting r2morph validation suite...")
    
    try:
        results = framework.run_validation_suite([
            BenchmarkCategory.DETECTION,
            BenchmarkCategory.FULL_PIPELINE
        ])
        
        # Generate and display report
        report = framework.generate_report()
        print(report)
        
        # Export results
        framework.export_results("validation_results.json", "json")
        print("\nResults exported to validation_results.json")
        
    except Exception as e:
        print(f"Validation failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()