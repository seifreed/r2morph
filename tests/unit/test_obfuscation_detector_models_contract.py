"""Contract tests for obfuscation detector model exports."""

from r2morph.detection import ObfuscationAnalysisResult as PublicObfuscationAnalysisResult
from r2morph.detection import ObfuscationType as PublicObfuscationType
from r2morph.detection.obfuscation_detector import ObfuscationDetector
from r2morph.detection.obfuscation_detector_models import (
    ObfuscationAnalysisResult as ModelsObfuscationAnalysisResult,
)
from r2morph.detection.obfuscation_detector_models import ObfuscationType as ModelsObfuscationType


def test_obfuscation_models_are_reexported_from_detection_package():
    assert PublicObfuscationAnalysisResult is ModelsObfuscationAnalysisResult
    assert PublicObfuscationType is ModelsObfuscationType
    assert ObfuscationDetector is not None
