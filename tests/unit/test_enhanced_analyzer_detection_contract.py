from pathlib import Path

from r2morph.analysis.enhanced_analyzer_detection import run_detection
from r2morph.analysis.enhanced_analyzer_lifecycle import load_binary
from r2morph.analysis.enhanced_analyzer_models import AnalysisResults


def test_enhanced_analyzer_detection_helpers_cover_basic_flow():
    binary = load_binary(Path("dataset/elf_x86_64"))
    results = AnalysisResults()
    try:
        detector, detection_result = run_detection(binary, results)
        assert detector is not None
        assert detection_result is not None
        assert results.detection_result is detection_result
        assert isinstance(results.custom_vm, dict)
        assert isinstance(results.layers, dict)
        assert isinstance(results.metamorphic, dict)
    finally:
        binary.__exit__(None, None, None)
