from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.detection.obfuscation_detector import ObfuscationAnalysisResult, ObfuscationDetector
from tests.utils.assertions import expect


def test_obfuscation_detector_analyze_binary_real():
    binary_path = Path("fixtures/dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    detector = ObfuscationDetector()
    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        result = detector.analyze_binary(bin_obj)

    expect(isinstance(result, ObfuscationAnalysisResult))
    expect(not (result.confidence_score < 0.0))
    expect(not (result.vm_handler_count < 0))
    expect(not (result.mba_expressions_found < 0))
    expect(not (result.opaque_predicates_found < 0))
    expect(isinstance(result.obfuscation_techniques, list))
    expect(isinstance(result.confidence_scores, dict))
    expect(isinstance(result.analysis_details, dict))


def test_obfuscation_detector_report_real():
    binary_path = Path("fixtures/dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    detector = ObfuscationDetector()
    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        report = detector.get_comprehensive_report(bin_obj)

    expect(not ("timestamp" not in report))
    expect(not ("binary_info" not in report))
    expect(not ("obfuscation_analysis" not in report))
    expect(not ("virtualization_analysis" not in report))
    expect(not ("layer_analysis" not in report))
    expect(not ("metamorphic_analysis" not in report))
    expect(not ("recommendations" not in report))
    expect(isinstance(report["recommendations"], list))
