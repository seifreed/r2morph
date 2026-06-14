"""Contract tests for control flow detector result models."""

from r2morph.detection import ControlFlowAnalysisResult as PublicControlFlowAnalysisResult
from r2morph.detection.control_flow_detector import ControlFlowAnalyzer
from r2morph.detection.control_flow_detector_models import (
    ControlFlowAnalysisResult as ModelsControlFlowAnalysisResult,
)


def test_control_flow_result_is_reexported_from_detection_package():
    assert PublicControlFlowAnalysisResult is ModelsControlFlowAnalysisResult
    assert ControlFlowAnalyzer is not None
