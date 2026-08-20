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
from tests.utils.assertions import expect


def test_leak_detection_models_are_reexported_from_validation_package() -> None:
    expect(not (PublicMemorySnapshot is not ModelsMemorySnapshot))
    expect(not (PublicMemoryLeak is not ModelsMemoryLeak))
    expect(not (PublicLeakDetectionResult is not ModelsLeakDetectionResult))
    expect(not (PublicResourceLeak is not ModelsResourceLeak))
    expect(not (PublicResourceLeakTestResult is not ModelsResourceLeakTestResult))
