"""Object tracking helpers for memory leak detection."""

from __future__ import annotations

from weakref import WeakSet


class ObjectTracker:
    """Track object creation and deletion to detect leaks."""

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
        """Get creation and deletion counts by type."""
        result = {}
        all_types = set(self._creation_counts.keys()) | set(self._deletion_counts.keys())
        for type_name in all_types:
            created = self._creation_counts.get(type_name, 0)
            deleted = self._deletion_counts.get(type_name, 0)
            result[type_name] = (created, deleted)
        return result
