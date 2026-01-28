"""
Performance optimization module for r2morph.

This module provides parallel processing, memory management, and incremental
analysis capabilities for large-scale deployment scenarios.
"""

import os
import time
import threading
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from typing import Any, Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
import logging
import gc
import sys

# Type checking for optional dependencies
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import memory_profiler
    HAS_MEMORY_PROFILER = True
except ImportError:
    HAS_MEMORY_PROFILER = False

logger = logging.getLogger(__name__)


@dataclass
class PerformanceConfig:
    """Configuration for performance optimization."""
    max_workers: int | None = None
    memory_limit_mb: int = 2048
    enable_parallel: bool = True
    enable_caching: bool = True
    enable_incremental: bool = True
    chunk_size: int = 100
    timeout_seconds: int = 300
    use_multiprocessing: bool = False  # ThreadPool by default for I/O bound tasks


@dataclass
class ResourceMonitor:
    """Resource monitoring for performance optimization."""
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    active_threads: int = 0
    cache_hit_ratio: float = 0.0
    
    def update(self):
        """Update resource metrics."""
        if HAS_PSUTIL:
            process = psutil.Process()
            self.memory_usage_mb = process.memory_info().rss / 1024 / 1024
            self.cpu_usage_percent = process.cpu_percent()
        
        self.active_threads = threading.active_count()


class MemoryManager:
    """Memory management utilities for large-scale analysis."""
    
    def __init__(self, config: PerformanceConfig):
        self.config = config
        self.monitor = ResourceMonitor()
        self._gc_threshold = config.memory_limit_mb * 0.8  # GC at 80% of limit
        
    def check_memory_usage(self) -> bool:
        """Check if memory usage is within limits."""
        if self.config.memory_limit_mb <= 0:
            return False
        self.monitor.update()
        
        if self.monitor.memory_usage_mb > self.config.memory_limit_mb:
            logger.warning(f"Memory usage ({self.monitor.memory_usage_mb:.1f}MB) "
                          f"exceeds limit ({self.config.memory_limit_mb}MB)")
            return False
        
        return True
    
    def trigger_gc_if_needed(self):
        """Trigger garbage collection if memory usage is high."""
        self.monitor.update()
        
        if self.monitor.memory_usage_mb > self._gc_threshold:
            logger.debug(f"Triggering GC: memory usage at {self.monitor.memory_usage_mb:.1f}MB")
            gc.collect()
    
    def get_optimal_chunk_size(self, total_items: int) -> int:
        """Calculate optimal chunk size based on available memory."""
        if not HAS_PSUTIL:
            return self.config.chunk_size
        
        available_memory_mb = psutil.virtual_memory().available / 1024 / 1024
        
        # Estimate memory per item (rough heuristic)
        estimated_memory_per_item = 10  # MB per binary analysis
        
        max_items_in_memory = int(available_memory_mb * 0.5 / estimated_memory_per_item)
        optimal_chunk_size = min(max_items_in_memory, self.config.chunk_size)
        
        return max(1, optimal_chunk_size)


class ResultCache:
    """Simple result caching for expensive operations."""
    
    def __init__(self, max_size: int = 1000):
        self.cache: dict[str, Any] = {}
        self.access_times: dict[str, float] = {}
        self.max_size = max_size
        self.hits = 0
        self.misses = 0
    
    def get(self, key: str) -> Any | None:
        """Get cached result."""
        if key in self.cache:
            self.access_times[key] = time.monotonic_ns()
            self.hits += 1
            return self.cache[key]
        
        self.misses += 1
        return None
    
    def set(self, key: str, value: Any):
        """Cache a result."""
        if len(self.cache) >= self.max_size:
            self._evict_lru()
        
        self.cache[key] = value
        self.access_times[key] = time.monotonic_ns()
    
    def _evict_lru(self):
        """Evict least recently used item."""
        if not self.access_times:
            return
        
        lru_key = min(self.access_times.keys(), key=lambda k: self.access_times[k])
        del self.cache[lru_key]
        del self.access_times[lru_key]
    
    def get_hit_ratio(self) -> float:
        """Get cache hit ratio."""
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0
    
    def clear(self):
        """Clear cache."""
        self.cache.clear()
        self.access_times.clear()
        self.hits = 0
        self.misses = 0


class ParallelAnalysisEngine:
    """Parallel analysis engine for processing multiple binaries."""
    
    def __init__(self, config: PerformanceConfig):
        self.config = config
        self.memory_manager = MemoryManager(config)
        self.cache = ResultCache() if config.enable_caching else None
        
        # Determine optimal worker count
        if config.max_workers is None:
            self.max_workers = min(8, (os.cpu_count() or 1) + 4)
        else:
            self.max_workers = config.max_workers
        
        logger.info(f"Initialized parallel engine with {self.max_workers} workers")
    
    def _get_cache_key(self, binary_path: str, analysis_type: str) -> str:
        """Generate cache key for analysis result."""
        try:
            # Use file size and modification time for cache key
            stat = Path(binary_path).stat()
            return f"{analysis_type}:{binary_path}:{stat.st_size}:{stat.st_mtime}"
        except Exception:
            return f"{analysis_type}:{binary_path}"
    
    def _analyze_single_binary(self, binary_path: str, analysis_func: Callable, 
                              analysis_type: str = "default") -> dict[str, Any]:
        """Analyze a single binary with caching and error handling."""
        cache_key = self._get_cache_key(binary_path, analysis_type)
        
        # Check cache first
        if self.cache:
            cached_result = self.cache.get(cache_key)
            if cached_result is not None:
                logger.debug(f"Cache hit for {binary_path}")
                return cached_result
        
        # Check memory before analysis
        if not self.memory_manager.check_memory_usage():
            self.memory_manager.trigger_gc_if_needed()
            
            # If still over limit, return error
            if not self.memory_manager.check_memory_usage():
                return {
                    'binary_path': binary_path,
                    'success': False,
                    'error': 'Memory limit exceeded',
                    'analysis_type': analysis_type
                }
        
        # Perform analysis
        start_time = time.time()
        
        try:
            result = analysis_func(binary_path)
            
            # Add metadata
            result.update({
                'binary_path': binary_path,
                'success': True,
                'analysis_time': time.time() - start_time,
                'analysis_type': analysis_type
            })
            
            # Cache result
            if self.cache:
                self.cache.set(cache_key, result)
            
            return result
        
        except Exception as e:
            logger.error(f"Analysis failed for {binary_path}: {e}")
            return {
                'binary_path': binary_path,
                'success': False,
                'error': str(e),
                'analysis_time': time.time() - start_time,
                'analysis_type': analysis_type
            }
        
        finally:
            # Trigger GC periodically
            self.memory_manager.trigger_gc_if_needed()
    
    def analyze_batch(self, binary_paths: list[str], analysis_func: Callable,
                     analysis_type: str = "default") -> list[dict[str, Any]]:
        """Analyze a batch of binaries in parallel."""
        if not self.config.enable_parallel:
            # Sequential processing
            results = []
            for binary_path in binary_paths:
                result = self._analyze_single_binary(binary_path, analysis_func, analysis_type)
                results.append(result)
            return results
        
        # Parallel processing
        results = []
        
        # Choose executor type
        if self.config.use_multiprocessing:
            executor_class = ProcessPoolExecutor
        else:
            executor_class = ThreadPoolExecutor
        
        with executor_class(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_path = {
                executor.submit(self._analyze_single_binary, binary_path, analysis_func, analysis_type): binary_path
                for binary_path in binary_paths
            }
            
            # Collect results with timeout
            for future in as_completed(future_to_path, timeout=self.config.timeout_seconds):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    binary_path = future_to_path[future]
                    logger.error(f"Future failed for {binary_path}: {e}")
                    results.append({
                        'binary_path': binary_path,
                        'success': False,
                        'error': str(e),
                        'analysis_type': analysis_type
                    })
        
        return results
    
    def analyze_chunked(self, binary_paths: list[str], analysis_func: Callable,
                       analysis_type: str = "default") -> Iterator[list[dict[str, Any]]]:
        """Analyze binaries in chunks to manage memory usage."""
        chunk_size = self.memory_manager.get_optimal_chunk_size(len(binary_paths))
        
        logger.info(f"Processing {len(binary_paths)} binaries in chunks of {chunk_size}")
        
        for i in range(0, len(binary_paths), chunk_size):
            chunk = binary_paths[i:i + chunk_size]
            
            logger.debug(f"Processing chunk {i//chunk_size + 1}/{(len(binary_paths) + chunk_size - 1)//chunk_size}")
            
            # Process chunk
            chunk_results = self.analyze_batch(chunk, analysis_func, analysis_type)
            
            yield chunk_results
            
            # Clean up between chunks
            self.memory_manager.trigger_gc_if_needed()
    
    def get_performance_stats(self) -> dict[str, Any]:
        """Get performance statistics."""
        self.memory_manager.monitor.update()
        
        stats = {
            'memory_usage_mb': self.memory_manager.monitor.memory_usage_mb,
            'cpu_usage_percent': self.memory_manager.monitor.cpu_usage_percent,
            'active_threads': self.memory_manager.monitor.active_threads,
            'max_workers': self.max_workers,
            'memory_limit_mb': self.config.memory_limit_mb
        }
        
        if self.cache:
            stats['cache_hit_ratio'] = self.cache.get_hit_ratio()
            stats['cache_size'] = len(self.cache.cache)
        
        return stats


class IncrementalAnalyzer:
    """Incremental analysis engine for processing only changed files."""
    
    def __init__(self, state_file: str = "incremental_state.json"):
        self.state_file = Path(state_file)
        self.file_states: dict[str, dict[str, Any]] = {}
        self._load_state()
    
    def _load_state(self):
        """Load incremental analysis state."""
        if self.state_file.exists():
            try:
                import json
                with open(self.state_file, 'r') as f:
                    self.file_states = json.load(f)
                logger.debug(f"Loaded state for {len(self.file_states)} files")
            except Exception as e:
                logger.warning(f"Failed to load incremental state: {e}")
                self.file_states = {}
    
    def _save_state(self):
        """Save incremental analysis state."""
        try:
            import json
            with open(self.state_file, 'w') as f:
                json.dump(self.file_states, f, indent=2)
            logger.debug(f"Saved state for {len(self.file_states)} files")
        except Exception as e:
            logger.error(f"Failed to save incremental state: {e}")
    
    def _get_file_signature(self, file_path: str) -> dict[str, Any]:
        """Get file signature for change detection."""
        try:
            stat = Path(file_path).stat()
            return {
                'size': stat.st_size,
                'mtime': stat.st_mtime,
                'exists': True
            }
        except Exception:
            return {'exists': False}
    
    def has_file_changed(self, file_path: str) -> bool:
        """Check if file has changed since last analysis."""
        current_sig = self._get_file_signature(file_path)
        
        if not current_sig['exists']:
            return False
        
        if file_path not in self.file_states:
            return True  # New file
        
        previous_sig = self.file_states[file_path].get('signature', {})
        
        return (current_sig['size'] != previous_sig.get('size') or
                current_sig['mtime'] != previous_sig.get('mtime'))
    
    def get_changed_files(self, file_paths: list[str]) -> list[str]:
        """Get list of files that have changed."""
        changed_files = []
        
        for file_path in file_paths:
            if self.has_file_changed(file_path):
                changed_files.append(file_path)
        
        return changed_files
    
    def update_file_state(self, file_path: str, analysis_result: dict[str, Any]):
        """Update file state after analysis."""
        signature = self._get_file_signature(file_path)
        
        self.file_states[file_path] = {
            'signature': signature,
            'last_analysis': time.time(),
            'analysis_result': analysis_result
        }
    
    def get_cached_result(self, file_path: str) -> dict[str, Any] | None:
        """Get cached analysis result if file hasn't changed."""
        if not self.has_file_changed(file_path):
            return self.file_states.get(file_path, {}).get('analysis_result')
        return None
    
    def cleanup_missing_files(self, current_files: list[str]):
        """Remove state for files that no longer exist."""
        current_files_set = set(current_files)
        files_to_remove = []
        
        for file_path in self.file_states:
            if file_path not in current_files_set:
                files_to_remove.append(file_path)
        
        for file_path in files_to_remove:
            del self.file_states[file_path]
        
        if files_to_remove:
            logger.info(f"Cleaned up state for {len(files_to_remove)} missing files")
    
    def save(self):
        """Save incremental state to disk."""
        self._save_state()


class OptimizedAnalysisFramework:
    """High-level framework combining all performance optimizations."""
    
    def __init__(self, config: PerformanceConfig, incremental_state_file: str | None = None):
        self.config = config
        self.parallel_engine = ParallelAnalysisEngine(config)
        
        if config.enable_incremental:
            self.incremental_analyzer = IncrementalAnalyzer(
                incremental_state_file or "analysis_state.json"
            )
        else:
            self.incremental_analyzer = None
    
    def analyze_files(self, file_paths: list[str], analysis_func: Callable,
                     analysis_type: str = "optimized") -> list[dict[str, Any]]:
        """
        Analyze files with full optimization (parallel, incremental, caching).
        
        Args:
            file_paths: List of file paths to analyze
            analysis_func: Analysis function to apply
            analysis_type: Type of analysis for caching
        
        Returns:
            List of analysis results
        """
        start_time = time.time()
        
        # Filter files if incremental analysis is enabled
        if self.incremental_analyzer:
            changed_files = self.incremental_analyzer.get_changed_files(file_paths)
            
            logger.info(f"Incremental analysis: {len(changed_files)}/{len(file_paths)} files changed")
            
            # Get cached results for unchanged files
            results = []
            for file_path in file_paths:
                if file_path not in changed_files:
                    cached_result = self.incremental_analyzer.get_cached_result(file_path)
                    if cached_result:
                        results.append(cached_result)
            
            # Only analyze changed files
            files_to_analyze = changed_files
        else:
            files_to_analyze = file_paths
            results = []
        
        if files_to_analyze:
            logger.info(f"Analyzing {len(files_to_analyze)} files")
            
            # Process in chunks if memory management is needed
            if len(files_to_analyze) > self.config.chunk_size:
                for chunk_results in self.parallel_engine.analyze_chunked(
                    files_to_analyze, analysis_func, analysis_type
                ):
                    results.extend(chunk_results)
                    
                    # Update incremental state for each chunk
                    if self.incremental_analyzer:
                        for result in chunk_results:
                            if result.get('success'):
                                self.incremental_analyzer.update_file_state(
                                    result['binary_path'], result
                                )
            else:
                # Process all files at once
                new_results = self.parallel_engine.analyze_batch(
                    files_to_analyze, analysis_func, analysis_type
                )
                results.extend(new_results)
                
                # Update incremental state
                if self.incremental_analyzer:
                    for result in new_results:
                        if result.get('success'):
                            self.incremental_analyzer.update_file_state(
                                result['binary_path'], result
                            )
        
        # Clean up and save state
        if self.incremental_analyzer:
            self.incremental_analyzer.cleanup_missing_files(file_paths)
            self.incremental_analyzer.save()
        
        total_time = time.time() - start_time
        
        logger.info(f"Analysis completed in {total_time:.2f}s")
        logger.info(f"Processed {len(results)} files total")
        
        return results
    
    def get_comprehensive_stats(self) -> dict[str, Any]:
        """Get comprehensive performance statistics."""
        stats = self.parallel_engine.get_performance_stats()
        
        if self.incremental_analyzer:
            stats['incremental_files_tracked'] = len(self.incremental_analyzer.file_states)
        
        return stats


# Analysis function wrappers for common operations
def create_detection_analysis_func():
    """Create detection analysis function for parallel processing."""
    def analyze_detection(binary_path: str) -> dict[str, Any]:
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
                    'anti_analysis_detected': result.anti_analysis_detected,
                    'control_flow_flattened': result.control_flow_flattened,
                    'mba_detected': result.mba_detected,
                    'confidence_score': result.confidence_score,
                    'techniques_count': len(result.obfuscation_techniques)
                }
        
        except Exception as e:
            return {'error': str(e)}
    
    return analyze_detection


def create_devirtualization_analysis_func():
    """Create devirtualization analysis function for parallel processing."""
    def analyze_devirtualization(binary_path: str) -> dict[str, Any]:
        try:
            from r2morph import Binary
            from r2morph.devirtualization import CFOSimplifier
            
            with Binary(binary_path) as bin_obj:
                bin_obj.analyze()
                
                cfo_simplifier = CFOSimplifier(bin_obj)
                functions = bin_obj.get_functions()[:3]  # Limit for performance
                
                total_complexity_reduction = 0
                simplified_functions = 0
                
                for func in functions:
                    func_addr = func.get('offset', 0)
                    result = cfo_simplifier.simplify_control_flow(func_addr)
                    if result.success:
                        total_complexity_reduction += result.original_complexity - result.simplified_complexity
                        simplified_functions += 1
                
                return {
                    'functions_analyzed': len(functions),
                    'functions_simplified': simplified_functions,
                    'total_complexity_reduction': total_complexity_reduction,
                    'average_complexity_reduction': total_complexity_reduction / len(functions) if functions else 0
                }
        
        except Exception as e:
            return {'error': str(e)}
    
    return analyze_devirtualization


def main():
    """Example usage of the optimization framework."""
    # Configuration
    config = PerformanceConfig(
        max_workers=4,
        memory_limit_mb=1024,
        enable_parallel=True,
        enable_caching=True,
        enable_incremental=True,
        chunk_size=50
    )
    
    # Initialize framework
    framework = OptimizedAnalysisFramework(config)
    
    # Example file list (you would provide real file paths)
    test_files = [
        "dataset/simple",
        "dataset/loop",
        "dataset/conditional"
    ]
    
    # Filter to existing files
    existing_files = [f for f in test_files if Path(f).exists()]
    
    if not existing_files:
        print("No test files found - create some test binaries in dataset/")
        return
    
    print(f"Optimized Analysis Framework Demo")
    print(f"Configuration: {config}")
    print(f"Files to analyze: {len(existing_files)}")
    
    # Run detection analysis
    print("\nRunning optimized detection analysis...")
    detection_func = create_detection_analysis_func()
    
    start_time = time.time()
    detection_results = framework.analyze_files(existing_files, detection_func, "detection")
    detection_time = time.time() - start_time
    
    successful_detections = sum(1 for r in detection_results if r.get('success', False))
    print(f"Detection analysis completed: {successful_detections}/{len(detection_results)} successful")
    print(f"Total time: {detection_time:.2f}s")
    
    # Run devirtualization analysis
    print("\nRunning optimized devirtualization analysis...")
    devirt_func = create_devirtualization_analysis_func()
    
    start_time = time.time()
    devirt_results = framework.analyze_files(existing_files, devirt_func, "devirtualization")
    devirt_time = time.time() - start_time
    
    successful_devirts = sum(1 for r in devirt_results if r.get('success', False))
    print(f"Devirtualization analysis completed: {successful_devirts}/{len(devirt_results)} successful")
    print(f"Total time: {devirt_time:.2f}s")
    
    # Show performance statistics
    stats = framework.get_comprehensive_stats()
    print(f"\nPerformance Statistics:")
    for key, value in stats.items():
        if isinstance(value, float):
            print(f"  {key}: {value:.2f}")
        else:
            print(f"  {key}: {value}")
    
    print(f"\nOptimization demo completed!")


if __name__ == "__main__":
    main()
