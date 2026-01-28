from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.detection.control_flow_detector import ControlFlowAnalyzer


def test_control_flow_detector_internal_paths_real():
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        analyzer = ControlFlowAnalyzer(bin_obj)

        functions = bin_obj.get_functions()
        if not functions:
            pytest.skip("No functions found in binary")

        func_addr = functions[0].get("offset", 0) or functions[0].get("addr", 0)
        if not func_addr:
            pytest.skip("Invalid function address")

        # Exercise individual detection methods (return types only)
        cff_conf = analyzer._detect_control_flow_flattening()
        assert 0.0 <= cff_conf <= 1.0

        opaque_count = analyzer._detect_opaque_predicates()
        assert opaque_count >= 0

        mba_count = analyzer._detect_mba_patterns()
        assert mba_count >= 0

        vm_result = analyzer._detect_virtualization()
        assert isinstance(vm_result, dict)
        assert "confidence" in vm_result

        # Dispatcher pattern on actual blocks (if available)
        blocks = bin_obj.get_basic_blocks(func_addr)
        if blocks:
            dispatcher = analyzer._check_dispatcher_pattern(blocks)
            assert dispatcher is True or dispatcher is False
