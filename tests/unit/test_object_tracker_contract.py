from __future__ import annotations

from r2morph.validation import ObjectTracker as PublicObjectTracker
from r2morph.validation.leak_detection import ObjectTracker as LeakDetectionObjectTracker
from r2morph.validation.object_tracker import ObjectTracker as ModuleObjectTracker


def test_object_tracker_is_reexported_from_validation_package() -> None:
    assert PublicObjectTracker is ModuleObjectTracker


def test_object_tracker_is_compatible_through_leak_detection_module() -> None:
    assert LeakDetectionObjectTracker is ModuleObjectTracker
