from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.detection.control_flow_detector import ControlFlowAnalyzer


def test_control_flow_detector_custom_vm_and_metamorphic():
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze()
        analyzer = ControlFlowAnalyzer(bin_obj)

        custom = analyzer.detect_custom_virtualizer()
        assert isinstance(custom, dict)
        assert "detected" in custom
        assert "confidence" in custom
        assert "indicators" in custom

        meta = analyzer._detect_metamorphic_engine()
        assert isinstance(meta, dict)
        assert "polymorphic_ratio" in meta
