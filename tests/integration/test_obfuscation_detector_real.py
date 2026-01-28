from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.detection.obfuscation_detector import ObfuscationDetector, ObfuscationAnalysisResult


def test_obfuscation_detector_analyze_binary_real():
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    detector = ObfuscationDetector()
    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        result = detector.analyze_binary(bin_obj)

    assert isinstance(result, ObfuscationAnalysisResult)
    assert result.confidence_score >= 0.0
    assert result.vm_handler_count >= 0
    assert result.mba_expressions_found >= 0
    assert result.opaque_predicates_found >= 0
    assert isinstance(result.obfuscation_techniques, list)
    assert isinstance(result.confidence_scores, dict)
    assert isinstance(result.analysis_details, dict)


def test_obfuscation_detector_report_real():
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    detector = ObfuscationDetector()
    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        report = detector.get_comprehensive_report(bin_obj)

    assert "timestamp" in report
    assert "binary_info" in report
    assert "obfuscation_analysis" in report
    assert "virtualization_analysis" in report
    assert "layer_analysis" in report
    assert "metamorphic_analysis" in report
    assert "recommendations" in report
    assert isinstance(report["recommendations"], list)
