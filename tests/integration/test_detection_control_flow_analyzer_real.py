from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.detection.control_flow_detector import ControlFlowAnalyzer


def test_control_flow_analyzer_real_binary():
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze()
        analyzer = ControlFlowAnalyzer(bin_obj)
        result = analyzer.analyze()

    assert isinstance(result.cff_confidence, float)
    assert isinstance(result.opaque_predicates_count, int)
    assert isinstance(result.mba_expressions_count, int)
    assert isinstance(result.vm_detected, bool)
