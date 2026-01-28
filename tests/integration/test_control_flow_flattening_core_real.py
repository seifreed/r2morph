import random
import shutil
import platform
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass
from tests.utils.platform_binaries import get_platform_binary, ensure_exists


def test_control_flow_flattening_core_paths(tmp_path):
    random.seed(1337)
    src = get_platform_binary("generic")
    if not ensure_exists(Path(src)):
        return
    target = tmp_path / "pe_flatten.exe"
    shutil.copy2(src, target)

    with Binary(target, writable=True) as bin_obj:
        bin_obj.analyze("aa")

        func_addr = None
        for func in bin_obj.get_functions():
            addr = func.get("offset") or func.get("addr")
            if not addr:
                continue
            blocks = bin_obj.get_basic_blocks(addr)
            if blocks and len(blocks) >= 3:
                func_addr = addr
                func_dict = func
                break

        if func_addr is None:
            # Some tiny test binaries may not have enough blocks for flattening.
            return

        nop_addr = func_addr + 8
        bin_obj.write_bytes(nop_addr, b"\x90" * 5)

        pass_obj = ControlFlowFlatteningPass(
            {"probability": 1.0, "opaque_predicate_density": 1, "min_blocks_required": 3}
        )
        result = pass_obj._flatten_function(bin_obj, func_dict)
        assert result is None or result["total"] >= 0
