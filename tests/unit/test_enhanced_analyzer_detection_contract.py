from pathlib import Path

from r2morph.analysis.enhanced_analyzer_detection import run_detection
from r2morph.analysis.enhanced_analyzer_lifecycle import load_binary
from r2morph.analysis.enhanced_analyzer_models import AnalysisResults
from tests.utils.assertions import expect


def test_enhanced_analyzer_detection_helpers_cover_basic_flow():
    binary = load_binary(Path("fixtures/dataset/elf_x86_64"))
    results = AnalysisResults()
    try:
        detector, detection_result = run_detection(binary, results)
        expect(detector is not None)
        expect(detection_result is not None)
        expect(not (results.detection_result is not detection_result))
        expect(isinstance(results.custom_vm, dict))
        expect(isinstance(results.layers, dict))
        expect(isinstance(results.metamorphic, dict))
    finally:
        binary.__exit__(None, None, None)
