"""
Memory leak detection for mutation passes.

Detects memory leaks and resource leaks during mutation operations
using memory profiling and garbage collection tracking.
"""

import gc
import logging
import tracemalloc
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from weakref import WeakSet

logger = logging.getLogger(__name__)


@dataclass
class MemorySnapshot:
    """Snapshot of memory usage at a point in time."""

    timestamp: float
    current_memory_bytes: int
    peak_memory_bytes: int
    object_count: int
    gc_gen0: int
    gc_gen1: int
    gc_gen2: int
    tracer_running: bool


@dataclass
class MemoryLeak:
    """Detected memory leak."""

    leak_type: str  # "memory_growth", "object_leak", "resource_leak"
    description: str
    initial_memory_mb: float
    final_memory_mb: float
    memory_growth_mb: float
    initial_objects: int
    final_objects: int
    object_growth: int
    potential_cause: str | None = None
    traceback: list[str] | None = None


@dataclass
class LeakDetectionResult:
    """Result of leak detection analysis."""

    passed: bool
    leaks_detected: int
    memory_leaks: list[MemoryLeak]
    snapshots: list[MemorySnapshot]
    peak_memory_growth_mb: float
    total_object_growth: int


class ObjectTracker:
    """
    Track object creation and deletion to detect leaks.
    """

    def __init__(self) -> None:
        self._tracked_objects: WeakSet = WeakSet()
        self._creation_counts: dict[str, int] = {}
        self._deletion_counts: dict[str, int] = {}
        self._enabled = False

    def start_tracking(self) -> None:
        """Start tracking objects."""
        self._tracked_objects = WeakSet()
        self._creation_counts = {}
        self._deletion_counts = {}
        self._enabled = True

    def stop_tracking(self) -> None:
        """Stop tracking objects."""
        self._enabled = False

    def track_object(self, obj: object) -> None:
        """Track an object."""
        if self._enabled:
            self._tracked_objects.add(obj)
            type_name = type(obj).__name__
            self._creation_counts[type_name] = self._creation_counts.get(type_name, 0) + 1

    def get_tracked_count(self) -> int:
        """Get count of tracked objects."""
        return len(self._tracked_objects)

    def get_object_counts(self) -> dict[str, tuple[int, int]]:
        """
        Get creation and deletion counts by type.

        Returns:
            Dict mapping type name to (created, deleted) counts
        """
        result = {}
        all_types = set(self._creation_counts.keys()) | set(self._deletion_counts.keys())
        for type_name in all_types:
            created = self._creation_counts.get(type_name, 0)
            deleted = self._deletion_counts.get(type_name, 0)
            result[type_name] = (created, deleted)
        return result


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
        *args,
        **kwargs,
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


@dataclass
class ResourceLeak:
    """Detected resource leak."""

    resource_type: str
    description: str
    initial_count: int
    final_count: int
    leaked_count: int


@dataclass
class ResourceLeakTestResult:
    """Result of resource leak testing."""

    passed: bool
    leaks_detected: int
    resource_leaks: list[ResourceLeak]


class ResourceLeakDetector:
    """
    Detect resource leaks (file handles, connections, etc).
    """

    def __init__(self) -> None:
        self._initial_resources: dict[str, int] = {}
        self._final_resources: dict[str, int] = {}

    def _get_resource_counts(self) -> dict[str, int]:
        """Get current resource counts."""
        import os

        resources = {}

        try:
            resources["file_descriptors"] = len(os.listdir("/proc/self/fd"))
        except Exception:
            try:
                import psutil

                resources["file_descriptors"] = psutil.Process().num_fds()
            except Exception:
                resources["file_descriptors"] = 0

        resources["open_files"] = sum(
            1
            for obj in gc.get_objects()
            if hasattr(obj, "closed") and hasattr(obj, "name") and not getattr(obj, "closed", True)
        )

        try:
            import psutil

            proc = psutil.Process()
            resources["open_connections"] = len(proc.connections())
        except Exception:
            resources["open_connections"] = 0

        resources["gc_tracked_objects"] = len(gc.get_objects())
        resources["gc_garbage"] = len(gc.garbage)

        return resources

    def start_monitoring(self) -> None:
        """Start resource monitoring."""
        gc.collect()
        self._initial_resources = self._get_resource_counts()

    def stop_monitoring(self) -> ResourceLeakTestResult:
        """
        Stop monitoring and check for leaks.

        Returns:
            ResourceLeakTestResult
        """
        gc.collect()
        self._final_resources = self._get_resource_counts()

        leaks = []

        for resource_type, initial_count in self._initial_resources.items():
            final_count = self._final_resources.get(resource_type, 0)

            if final_count > initial_count:
                leaked = final_count - initial_count
                leaks.append(
                    ResourceLeak(
                        resource_type=resource_type,
                        description=f"{resource_type} leaked: {leaked} instances",
                        initial_count=initial_count,
                        final_count=final_count,
                        leaked_count=leaked,
                    )
                )

        return ResourceLeakTestResult(
            passed=len(leaks) == 0,
            leaks_detected=len(leaks),
            resource_leaks=leaks,
        )

    def test_function(self, func: Any, *args, **kwargs) -> ResourceLeakTestResult:
        """
        Test a function for resource leaks.

        Args:
            func: Function to test
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            ResourceLeakTestResult
        """
        self.start_monitoring()

        try:
            func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error during resource leak test: {e}")

        return self.stop_monitoring()


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
