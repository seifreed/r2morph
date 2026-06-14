from __future__ import annotations

from r2morph.validation import (
    LeakDetectionResult as PublicLeakDetectionResult,
)
from r2morph.validation import (
    MemoryLeak as PublicMemoryLeak,
)
from r2morph.validation import (
    MemorySnapshot as PublicMemorySnapshot,
)
from r2morph.validation import (
    ResourceLeak as PublicResourceLeak,
)
from r2morph.validation import (
    ResourceLeakTestResult as PublicResourceLeakTestResult,
)
from r2morph.validation.leak_detection_models import (
    LeakDetectionResult as ModelsLeakDetectionResult,
)
from r2morph.validation.leak_detection_models import (
    MemoryLeak as ModelsMemoryLeak,
)
from r2morph.validation.leak_detection_models import (
    MemorySnapshot as ModelsMemorySnapshot,
)
from r2morph.validation.leak_detection_models import (
    ResourceLeak as ModelsResourceLeak,
)
from r2morph.validation.leak_detection_models import (
    ResourceLeakTestResult as ModelsResourceLeakTestResult,
)


def test_leak_detection_models_are_reexported_from_validation_package() -> None:
    assert PublicMemorySnapshot is ModelsMemorySnapshot
    assert PublicMemoryLeak is ModelsMemoryLeak
    assert PublicLeakDetectionResult is ModelsLeakDetectionResult
    assert PublicResourceLeak is ModelsResourceLeak
    assert PublicResourceLeakTestResult is ModelsResourceLeakTestResult
