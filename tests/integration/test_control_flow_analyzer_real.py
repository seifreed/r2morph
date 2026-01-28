from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.detection.control_flow_detector import ControlFlowAnalyzer, ControlFlowAnalysisResult


def test_control_flow_analyzer_basic_outputs_real():
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        analyzer = ControlFlowAnalyzer(bin_obj)
        result = analyzer.analyze()

    assert isinstance(result, ControlFlowAnalysisResult)
    assert 0.0 <= result.cff_confidence <= 1.0
    assert 0.0 <= result.vm_confidence <= 1.0
    assert 0.0 <= result.metamorphic_confidence <= 1.0
    assert 0.0 <= result.polymorphic_ratio <= 1.0
    assert result.opaque_predicates_count >= 0
    assert result.mba_expressions_count >= 0
    assert result.vm_handler_count >= 0


def test_control_flow_analyzer_custom_virtualizer_real():
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        analyzer = ControlFlowAnalyzer(bin_obj)
        result = analyzer.detect_custom_virtualizer()

    assert isinstance(result, dict)
    assert "detected" in result
    assert "confidence" in result
    assert 0.0 <= result["confidence"] <= 1.0
    assert "indicators" in result
    assert isinstance(result["indicators"], list)
