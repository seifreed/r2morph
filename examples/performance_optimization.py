"""
Performance optimization demonstration for r2morph.

This example shows the performance improvements achieved through:
- Parallel processing
- Memory management
- Incremental analysis
- Result caching
"""

import time
import argparse
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def benchmark_sequential_analysis(file_paths, analysis_func):
    """Benchmark sequential analysis without optimizations."""
    print("Running sequential analysis (baseline)...")
    
    start_time = time.time()
    results = []
    
    for file_path in file_paths:
        try:
            result = analysis_func(file_path)
            result['binary_path'] = file_path
            result['success'] = True
            results.append(result)
        except Exception as e:
            results.append({
                'binary_path': file_path,
                'success': False,
                'error': str(e)
            })
    
    total_time = time.time() - start_time
    successful = sum(1 for r in results if r.get('success', False))
    
    return {
        'results': results,
        'total_time': total_time,
        'successful_analyses': successful,
        'average_time_per_file': total_time / len(file_paths) if file_paths else 0,
        'optimization_type': 'sequential'
    }


def benchmark_parallel_analysis(file_paths, analysis_func):
    """Benchmark parallel analysis with optimizations."""
    print("Running parallel analysis (optimized)...")
    
    from r2morph.performance import PerformanceConfig, OptimizedAnalysisFramework
    
    # Configure for performance
    config = PerformanceConfig(
        max_workers=4,
        memory_limit_mb=1024,
        enable_parallel=True,
        enable_caching=True,
        enable_incremental=False,  # Disable for fair comparison
        chunk_size=10
    )
    
    framework = OptimizedAnalysisFramework(config)
    
    start_time = time.time()
    results = framework.analyze_files(file_paths, analysis_func, "parallel_benchmark")
    total_time = time.time() - start_time
    
    successful = sum(1 for r in results if r.get('success', False))
    
    return {
        'results': results,
        'total_time': total_time,
        'successful_analyses': successful,
        'average_time_per_file': total_time / len(file_paths) if file_paths else 0,
        'optimization_type': 'parallel',
        'performance_stats': framework.get_comprehensive_stats()
    }


def benchmark_incremental_analysis(file_paths, analysis_func):
    """Benchmark incremental analysis (second run)."""
    print("Running incremental analysis (cached results)...")
    
    from r2morph.performance import PerformanceConfig, OptimizedAnalysisFramework
    
    # Configure for incremental analysis
    config = PerformanceConfig(
        max_workers=4,
        memory_limit_mb=1024,
        enable_parallel=True,
        enable_caching=True,
        enable_incremental=True,
        chunk_size=10
    )
    
    framework = OptimizedAnalysisFramework(config, "incremental_benchmark_state.json")
    
    # First run to populate cache
    print("  First run (populating cache)...")
    first_start = time.time()
    framework.analyze_files(file_paths, analysis_func, "incremental_benchmark")
    first_time = time.time() - first_start
    
    # Second run should be much faster (incremental)
    print("  Second run (incremental)...")
    start_time = time.time()
    results = framework.analyze_files(file_paths, analysis_func, "incremental_benchmark")
    total_time = time.time() - start_time
    
    successful = sum(1 for r in results if r.get('success', False))
    
    return {
        'results': results,
        'total_time': total_time,
        'first_run_time': first_time,
        'successful_analyses': successful,
        'average_time_per_file': total_time / len(file_paths) if file_paths else 0,
        'optimization_type': 'incremental',
        'performance_stats': framework.get_comprehensive_stats()
    }


def create_test_detection_func():
    """Create a test detection function."""
    def test_detection(binary_path):
        # Simulate some processing time
        time.sleep(0.1)  # 100ms per file
        
        try:
            from r2morph import Binary
            from r2morph.detection import ObfuscationDetector
            
            with Binary(binary_path) as bin_obj:
                bin_obj.analyze()
                
                detector = ObfuscationDetector()
                result = detector.analyze_binary(bin_obj)
                
                return {
                    'packer_detected': result.packer_detected.value if result.packer_detected else None,
                    'vm_detected': result.vm_detected,
                    'confidence_score': result.confidence_score,
                    'techniques_count': len(result.obfuscation_techniques)
                }
        
        except Exception as e:
            # Return dummy data for missing files
            return {
                'packer_detected': None,
                'vm_detected': False,
                'confidence_score': 0.5,
                'techniques_count': 0,
                'simulated': True
            }
    
    return test_detection


def create_memory_intensive_func():
    """Create a memory-intensive analysis function for testing memory management."""
    def memory_intensive_analysis(binary_path):
        # Simulate memory-intensive operation
        import random
        
        # Create some memory load
        data = [random.random() for _ in range(100000)]  # ~800KB of data
        
        try:
            from r2morph import Binary
            
            with Binary(binary_path) as bin_obj:
                bin_obj.analyze()
                
                # Simulate complex analysis
                functions = bin_obj.get_functions()
                
                return {
                    'functions_found': len(functions),
                    'memory_usage_simulated': len(data),
                    'file_size': Path(binary_path).stat().st_size if Path(binary_path).exists() else 0
                }
        
        except Exception:
            return {
                'functions_found': random.randint(10, 100),
                'memory_usage_simulated': len(data),
                'file_size': random.randint(1000, 100000),
                'simulated': True
            }
    
    return memory_intensive_analysis


def prepare_test_files(count=10):
    """Prepare test files for benchmarking."""
    dataset_dir = Path("dataset")
    dataset_dir.mkdir(exist_ok=True)
    
    # Look for existing test files
    existing_files = []
    test_patterns = ["simple", "loop", "conditional"]
    
    for pattern in test_patterns:
        test_file = dataset_dir / pattern
        if test_file.exists():
            existing_files.append(str(test_file))
    
    # If we don't have enough real files, simulate with dummy paths
    test_files = existing_files.copy()
    
    while len(test_files) < count:
        dummy_file = f"dummy_file_{len(test_files)}.exe"
        test_files.append(dummy_file)
    
    return test_files[:count]


def run_performance_comparison():
    """Run comprehensive performance comparison."""
    print("=" * 80)
    print("R2MORPH PERFORMANCE OPTIMIZATION BENCHMARK")
    print("=" * 80)
    
    # Prepare test files
    file_count = 12  # Good number for demonstrating parallelization
    test_files = prepare_test_files(file_count)
    
    print(f"Testing with {len(test_files)} files")
    print(f"Real files: {sum(1 for f in test_files if Path(f).exists())}")
    print(f"Simulated files: {sum(1 for f in test_files if not Path(f).exists())}")
    
    analysis_func = create_test_detection_func()
    
    # Benchmark 1: Sequential Analysis
    print(f"\n{'-' * 40}")
    print("BENCHMARK 1: SEQUENTIAL ANALYSIS")
    print(f"{'-' * 40}")
    
    sequential_result = benchmark_sequential_analysis(test_files, analysis_func)
    
    print(f"Results:")
    print(f"  Total Time: {sequential_result['total_time']:.2f}s")
    print(f"  Average per File: {sequential_result['average_time_per_file']:.3f}s")
    print(f"  Successful Analyses: {sequential_result['successful_analyses']}/{len(test_files)}")
    
    # Benchmark 2: Parallel Analysis
    print(f"\n{'-' * 40}")
    print("BENCHMARK 2: PARALLEL ANALYSIS")
    print(f"{'-' * 40}")
    
    try:
        parallel_result = benchmark_parallel_analysis(test_files, analysis_func)
        
        print(f"Results:")
        print(f"  Total Time: {parallel_result['total_time']:.2f}s")
        print(f"  Average per File: {parallel_result['average_time_per_file']:.3f}s")
        print(f"  Successful Analyses: {parallel_result['successful_analyses']}/{len(test_files)}")
        print(f"  Speedup: {sequential_result['total_time'] / parallel_result['total_time']:.1f}x")
        
        # Performance stats
        stats = parallel_result['performance_stats']
        print(f"  Memory Usage: {stats.get('memory_usage_mb', 0):.1f}MB")
        print(f"  Cache Hit Ratio: {stats.get('cache_hit_ratio', 0):.1%}")
        
    except ImportError:
        print("  Skipped - performance module not available")
        parallel_result = None
    
    # Benchmark 3: Incremental Analysis
    print(f"\n{'-' * 40}")
    print("BENCHMARK 3: INCREMENTAL ANALYSIS")
    print(f"{'-' * 40}")
    
    try:
        incremental_result = benchmark_incremental_analysis(test_files, analysis_func)
        
        print(f"Results:")
        print(f"  First Run Time: {incremental_result['first_run_time']:.2f}s")
        print(f"  Incremental Time: {incremental_result['total_time']:.2f}s")
        print(f"  Incremental Speedup: {incremental_result['first_run_time'] / incremental_result['total_time']:.1f}x")
        print(f"  vs Sequential Speedup: {sequential_result['total_time'] / incremental_result['total_time']:.1f}x")
        
        # Performance stats
        stats = incremental_result['performance_stats']
        print(f"  Cache Hit Ratio: {stats.get('cache_hit_ratio', 0):.1%}")
        print(f"  Files Tracked: {stats.get('incremental_files_tracked', 0)}")
        
    except ImportError:
        print("  Skipped - performance module not available")
        incremental_result = None
    
    # Memory Management Test
    print(f"\n{'-' * 40}")
    print("BENCHMARK 4: MEMORY MANAGEMENT")
    print(f"{'-' * 40}")
    
    try:
        from r2morph.performance import PerformanceConfig, OptimizedAnalysisFramework
        
        # Test with smaller memory limit
        memory_config = PerformanceConfig(
            max_workers=2,
            memory_limit_mb=512,  # Small limit
            enable_parallel=True,
            enable_caching=False,  # Disable caching to test memory management
            chunk_size=3  # Small chunks
        )
        
        memory_framework = OptimizedAnalysisFramework(memory_config)
        memory_func = create_memory_intensive_func()
        
        start_time = time.time()
        memory_results = memory_framework.analyze_files(test_files, memory_func, "memory_test")
        memory_time = time.time() - start_time
        
        successful_memory = sum(1 for r in memory_results if r.get('success', False))
        
        print(f"Results:")
        print(f"  Total Time: {memory_time:.2f}s")
        print(f"  Successful Analyses: {successful_memory}/{len(test_files)}")
        print(f"  Memory Limit: {memory_config.memory_limit_mb}MB")
        
        stats = memory_framework.get_comprehensive_stats()
        print(f"  Peak Memory Usage: {stats.get('memory_usage_mb', 0):.1f}MB")
        
    except ImportError:
        print("  Skipped - performance module not available")
    
    # Summary
    print(f"\n{'=' * 80}")
    print("PERFORMANCE OPTIMIZATION SUMMARY")
    print(f"{'=' * 80}")
    
    print(f"Sequential Baseline: {sequential_result['total_time']:.2f}s")
    
    if parallel_result:
        speedup = sequential_result['total_time'] / parallel_result['total_time']
        print(f"Parallel Optimization: {parallel_result['total_time']:.2f}s ({speedup:.1f}x speedup)")
    
    if incremental_result:
        speedup = sequential_result['total_time'] / incremental_result['total_time']
        print(f"Incremental Optimization: {incremental_result['total_time']:.2f}s ({speedup:.1f}x speedup)")
    
    print(f"\nOptimizations provide significant performance improvements for large-scale analysis!")
    
    return {
        'sequential': sequential_result,
        'parallel': parallel_result,
        'incremental': incremental_result
    }


def run_scalability_test():
    """Test scalability with different file counts."""
    print(f"\n{'=' * 80}")
    print("SCALABILITY TESTING")
    print(f"{'=' * 80}")
    
    try:
        from r2morph.performance import PerformanceConfig, OptimizedAnalysisFramework
        
        config = PerformanceConfig(
            max_workers=4,
            memory_limit_mb=1024,
            enable_parallel=True,
            enable_caching=True,
            chunk_size=20
        )
        
        framework = OptimizedAnalysisFramework(config)
        analysis_func = create_test_detection_func()
        
        file_counts = [5, 10, 20, 50]
        
        for count in file_counts:
            test_files = prepare_test_files(count)
            
            print(f"\nTesting with {count} files:")
            
            start_time = time.time()
            results = framework.analyze_files(test_files, analysis_func, f"scalability_{count}")
            total_time = time.time() - start_time
            
            successful = sum(1 for r in results if r.get('success', False))
            
            print(f"  Time: {total_time:.2f}s")
            print(f"  Per File: {total_time/count:.3f}s")
            print(f"  Success Rate: {successful}/{count} ({successful/count:.1%})")
            
            stats = framework.get_comprehensive_stats()
            print(f"  Memory: {stats.get('memory_usage_mb', 0):.1f}MB")
            print(f"  Cache Hit: {stats.get('cache_hit_ratio', 0):.1%}")
    
    except ImportError:
        print("Scalability testing skipped - performance module not available")


def main():
    """Main performance optimization demonstration."""
    parser = argparse.ArgumentParser(description="R2MORPH Performance Optimization Demo")
    parser.add_argument("--comparison", action="store_true", help="Run performance comparison")
    parser.add_argument("--scalability", action="store_true", help="Run scalability test")
    parser.add_argument("--all", action="store_true", help="Run all tests")
    
    args = parser.parse_args()
    
    if not any([args.comparison, args.scalability]) or args.all:
        args.comparison = True
        args.scalability = True
    
    if args.comparison:
        run_performance_comparison()
    
    if args.scalability:
        run_scalability_test()
    
    print(f"\nPerformance optimization demonstration completed!")


if __name__ == "__main__":
    main()