"""Contract tests for entropy analyzer result models."""

from r2morph.detection import EntropyResult as PublicEntropyResult
from r2morph.detection.entropy_analyzer import EntropyAnalyzer
from r2morph.detection.entropy_analyzer_models import EntropyResult as ModelsEntropyResult


def test_entropy_result_is_reexported_from_detection_package():
    assert PublicEntropyResult is ModelsEntropyResult
    assert EntropyAnalyzer is not None
