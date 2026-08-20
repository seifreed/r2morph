from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.detection.control_flow_detector import ControlFlowAnalysisResult, ControlFlowAnalyzer
from tests.utils.assertions import expect


def test_control_flow_analyzer_basic_outputs_real():
    binary_path = Path("fixtures/dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        analyzer = ControlFlowAnalyzer(bin_obj)
        result = analyzer.analyze()

    expect(isinstance(result, ControlFlowAnalysisResult))
    expect(0.0 <= result.cff_confidence <= 1.0)
    expect(0.0 <= result.vm_confidence <= 1.0)
    expect(0.0 <= result.metamorphic_confidence <= 1.0)
    expect(0.0 <= result.polymorphic_ratio <= 1.0)
    expect(not (result.opaque_predicates_count < 0))
    expect(not (result.mba_expressions_count < 0))
    expect(not (result.vm_handler_count < 0))


def test_control_flow_analyzer_custom_virtualizer_real():
    binary_path = Path("fixtures/dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        analyzer = ControlFlowAnalyzer(bin_obj)
        result = analyzer.detect_custom_virtualizer()

    expect(isinstance(result, dict))
    expect(not ("detected" not in result))
    expect(not ("confidence" not in result))
    expect(0.0 <= result["confidence"] <= 1.0)
    expect(not ("indicators" not in result))
    expect(isinstance(result["indicators"], list))
