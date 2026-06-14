"""Resource leak detection helpers."""

from __future__ import annotations

import gc
import io
import logging
from typing import Any

from r2morph.validation.leak_detection_models import ResourceLeak, ResourceLeakTestResult

logger = logging.getLogger(__name__)


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

        # Filter by concrete type before touching attributes: probing
        # `hasattr(obj, "closed")` over every gc object invokes
        # __getattr__ on arbitrary objects, and on objects with
        # side-effecting __getattr__ (e.g. pytest's MarkGenerator,
        # `pytest.mark`) it would synthesize `pytest.mark.closed` and
        # emit a PytestUnknownMarkWarning -- fatal under `pytest -W
        # error`. io.IOBase.closed is a plain, side-effect-free property
        # and covers the real OS-backed file objects we care about.
        resources["open_files"] = sum(1 for obj in gc.get_objects() if isinstance(obj, io.IOBase) and not obj.closed)

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

    def test_function(self, func: Any, *args: Any, **kwargs: Any) -> ResourceLeakTestResult:
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
