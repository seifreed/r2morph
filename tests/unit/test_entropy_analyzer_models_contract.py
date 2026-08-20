"""Contract tests for entropy analyzer result models."""

from r2morph.detection import EntropyResult as PublicEntropyResult
from r2morph.detection.entropy_analyzer import EntropyAnalyzer
from r2morph.detection.entropy_analyzer_models import EntropyResult as ModelsEntropyResult
from tests.utils.assertions import expect


def test_entropy_result_is_reexported_from_detection_package():
    expect(not (PublicEntropyResult is not ModelsEntropyResult))
    expect(EntropyAnalyzer is not None)
