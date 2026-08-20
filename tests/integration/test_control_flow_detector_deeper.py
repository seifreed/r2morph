from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.detection.control_flow_detector import ControlFlowAnalyzer
from tests.utils.assertions import expect


def test_control_flow_detector_custom_vm_and_metamorphic():
    binary_path = Path("fixtures/dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze()
        analyzer = ControlFlowAnalyzer(bin_obj)

        custom = analyzer.detect_custom_virtualizer()
        expect(isinstance(custom, dict))
        expect(not ("detected" not in custom))
        expect(not ("confidence" not in custom))
        expect(not ("indicators" not in custom))

        meta = analyzer._detect_metamorphic_engine()
        expect(isinstance(meta, dict))
        expect(not ("polymorphic_ratio" not in meta))
