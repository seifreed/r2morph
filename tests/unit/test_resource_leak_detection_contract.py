from __future__ import annotations

from r2morph.validation import (
    ResourceLeak as PublicResourceLeak,
)
from r2morph.validation import (
    ResourceLeakDetector as PublicResourceLeakDetector,
)
from r2morph.validation import (
    ResourceLeakTestResult as PublicResourceLeakTestResult,
)
from r2morph.validation.leak_detection_models import (
    ResourceLeak as ModelsResourceLeak,
)
from r2morph.validation.leak_detection_models import (
    ResourceLeakTestResult as ModelsResourceLeakTestResult,
)
from r2morph.validation.resource_leak_detection import ResourceLeakDetector


def test_resource_leak_models_are_reexported_from_validation_package() -> None:
    assert PublicResourceLeak is ModelsResourceLeak
    assert PublicResourceLeakTestResult is ModelsResourceLeakTestResult
    assert PublicResourceLeakDetector is ResourceLeakDetector
