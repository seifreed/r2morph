"""
Memory leak detection for mutation passes.

Detects memory leaks and resource leaks during mutation operations
using memory profiling and garbage collection tracking.
"""

import gc
import logging
import tracemalloc
from pathlib import Path
from typing import Any

from r2morph.validation.leak_detection_models import (
    LeakDetectionResult,
    MemoryLeak,
    MemorySnapshot,
)
from r2morph.validation.leak_detection_models import (
    ResourceLeak as _ResourceLeak,
)
from r2morph.validation.leak_detection_models import (
    ResourceLeakTestResult as _ResourceLeakTestResult,
)
from r2morph.validation.object_tracker import ObjectTracker as _ObjectTracker
from r2morph.validation.resource_leak_detection import (
    ResourceLeakDetector as _ResourceLeakDetector,
)

logger = logging.getLogger(__name__)

ObjectTracker = _ObjectTracker
ResourceLeak = _ResourceLeak
ResourceLeakTestResult = _ResourceLeakTestResult
ResourceLeakDetector = _ResourceLeakDetector


class MemoryLeakDetector:
    """
    Detect memory leaks in mutation passes.

    Uses tracemalloc and garbage collection analysis to detect
    memory leaks and unbounded object growth.
    """

    def __init__(
        self,
        threshold_mb: float = 10.0,
        object_growth_threshold: int = 1000,
        enable_tracing: bool = True,
    ) -> None:
        """
        Initialize memory leak detector.

        Args:
            threshold_mb: Memory growth threshold in MB for leak detection
            object_growth_threshold: Object count growth threshold
            enable_tracing: Enable traceback tracing
        """
        self.threshold_mb = threshold_mb
        self.object_growth_threshold = object_growth_threshold
        self.enable_tracing = enable_tracing
        self.object_tracker = ObjectTracker()

    def _get_gc_stats(self) -> tuple[int, int, int]:
        """Get garbage collection statistics."""
        counts = gc.get_count()
        return counts[0], counts[1], counts[2]

    def _take_snapshot(self) -> MemorySnapshot:
        """Take a memory snapshot."""
        if tracemalloc.is_tracing():
            current, peak = tracemalloc.get_traced_memory()
            tracer_running = True
        else:
            current, peak = 0, 0
            tracer_running = False

        gc_gen0, gc_gen1, gc_gen2 = self._get_gc_stats()

        import time

        return MemorySnapshot(
            timestamp=time.time(),
            current_memory_bytes=current,
            peak_memory_bytes=peak,
            object_count=len(gc.get_objects()),
            gc_gen0=gc_gen0,
            gc_gen1=gc_gen1,
            gc_gen2=gc_gen2,
            tracer_running=tracer_running,
        )

    def start_monitoring(self) -> MemorySnapshot:
        """
        Start memory monitoring.

        Returns:
            Initial memory snapshot
        """
        gc.collect()

        if self.enable_tracing and not tracemalloc.is_tracing():
            tracemalloc.start()

        self.object_tracker.start_tracking()

        return self._take_snapshot()

    def stop_monitoring(self) -> MemorySnapshot:
        """
        Stop memory monitoring.

        Returns:
            Final memory snapshot
        """
        snapshot = self._take_snapshot()

        self.object_tracker.stop_tracking()

        if tracemalloc.is_tracing():
            tracemalloc.stop()

        return snapshot

    def detect_leaks(
        self,
        snapshots: list[MemorySnapshot],
        func_name: str = "unknown",
    ) -> LeakDetectionResult:
        """
        Analyze memory snapshots to detect leaks.

        Args:
            snapshots: List of memory snapshots
            func_name: Name of the function being tested

        Returns:
            LeakDetectionResult with analysis
        """
        if len(snapshots) < 2:
            return LeakDetectionResult(
                passed=True,
                leaks_detected=0,
                memory_leaks=[],
                snapshots=snapshots,
                peak_memory_growth_mb=0.0,
                total_object_growth=0,
            )

        leaks = []

        initial = snapshots[0]
        final = snapshots[-1]

        memory_growth_mb = (final.current_memory_bytes - initial.current_memory_bytes) / (1024 * 1024)
        object_growth = final.object_count - initial.object_count

        if memory_growth_mb > self.threshold_mb:
            leaks.append(
                MemoryLeak(
                    leak_type="memory_growth",
                    description=f"Memory grew by {memory_growth_mb:.2f}MB during {func_name}",
                    initial_memory_mb=initial.current_memory_bytes / (1024 * 1024),
                    final_memory_mb=final.current_memory_bytes / (1024 * 1024),
                    memory_growth_mb=memory_growth_mb,
                    initial_objects=initial.object_count,
                    final_objects=final.object_count,
                    object_growth=object_growth,
                    potential_cause="Possible memory leak in mutation pass",
                )
            )

        if object_growth > self.object_growth_threshold:
            leaks.append(
                MemoryLeak(
                    leak_type="object_leak",
                    description=f"Object count grew by {object_growth} during {func_name}",
                    initial_memory_mb=initial.current_memory_bytes / (1024 * 1024),
                    final_memory_mb=final.current_memory_bytes / (1024 * 1024),
                    memory_growth_mb=memory_growth_mb,
                    initial_objects=initial.object_count,
                    final_objects=final.object_count,
                    object_growth=object_growth,
                    potential_cause="Objects not being garbage collected",
                )
            )

        gc_growth = (final.gc_gen0 + final.gc_gen1 + final.gc_gen2) - (
            initial.gc_gen0 + initial.gc_gen1 + initial.gc_gen2
        )
        if gc_growth > 1000:
            leaks.append(
                MemoryLeak(
                    leak_type="gc_pressure",
                    description=f"GC pressure increased by {gc_growth} objects during {func_name}",
                    initial_memory_mb=initial.current_memory_bytes / (1024 * 1024),
                    final_memory_mb=final.current_memory_bytes / (1024 * 1024),
                    memory_growth_mb=memory_growth_mb,
                    initial_objects=initial.object_count,
                    final_objects=final.object_count,
                    object_growth=object_growth,
                    potential_cause="High object allocation rate",
                )
            )

        peak_growth = max((s.peak_memory_bytes - snapshots[0].peak_memory_bytes) / (1024 * 1024) for s in snapshots)

        return LeakDetectionResult(
            passed=len(leaks) == 0,
            leaks_detected=len(leaks),
            memory_leaks=leaks,
            snapshots=snapshots,
            peak_memory_growth_mb=peak_growth,
            total_object_growth=object_growth,
        )

    def test_function(
        self,
        func: Any,
        *args: Any,
        **kwargs: Any,
    ) -> LeakDetectionResult:
        """
        Test a function for memory leaks.

        Args:
            func: Function to test
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            LeakDetectionResult
        """
        self.start_monitoring()

        initial_snapshot = self._take_snapshot()
        snapshots = [initial_snapshot]

        try:
            func(*args, **kwargs)

            gc.collect()

            final_snapshot = self._take_snapshot()
            snapshots.append(final_snapshot)

            return self.detect_leaks(snapshots, func.__name__)

        except Exception as e:
            logger.error(f"Error during leak testing: {e}")

            return LeakDetectionResult(
                passed=False,
                leaks_detected=1,
                memory_leaks=[
                    MemoryLeak(
                        leak_type="exception",
                        description=f"Exception during test: {e}",
                        initial_memory_mb=0,
                        final_memory_mb=0,
                        memory_growth_mb=0,
                        initial_objects=0,
                        final_objects=0,
                        object_growth=0,
                        potential_cause=str(e),
                    )
                ],
                snapshots=snapshots,
                peak_memory_growth_mb=0,
                total_object_growth=0,
            )

        finally:
            self.stop_monitoring()

    def test_mutation_pass(
        self,
        pass_class: type,
        binary_path: Path,
        config: dict[str, Any] | None = None,
    ) -> LeakDetectionResult:
        """
        Test a mutation pass for memory leaks.

        Args:
            pass_class: Mutation pass class to test
            binary_path: Path to test binary
            config: Optional configuration

        Returns:
            LeakDetectionResult
        """
        from r2morph import Binary

        def run_pass() -> None:
            with Binary(binary_path, flags=["-2"], writable=True) as binary:
                binary.analyze()

                mutation = pass_class(config=config)
                mutation.apply(binary)

        return self.test_function(run_pass)


def create_memory_detector(
    threshold_mb: float = 10.0,
    object_threshold: int = 1000,
) -> MemoryLeakDetector:
    """
    Create a configured memory leak detector.

    Args:
        threshold_mb: Memory growth threshold in MB
        object_threshold: Object growth threshold

    Returns:
        MemoryLeakDetector instance
    """
    return MemoryLeakDetector(
        threshold_mb=threshold_mb,
        object_growth_threshold=object_threshold,
    )
