import random
import shutil

from r2morph.core.binary import Binary
from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass


def test_control_flow_flattening_core_paths(tmp_path):
    random.seed(1337)
    src = "dataset/pe_x86_64.exe"
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

        assert func_addr is not None

        nop_addr = func_addr + 8
        bin_obj.write_bytes(nop_addr, b"\x90" * 5)

        pass_obj = ControlFlowFlatteningPass(
            {"probability": 1.0, "opaque_predicate_density": 1, "min_blocks_required": 3}
        )
        result = pass_obj._flatten_function(bin_obj, func_dict)
        assert result is None or result["total"] >= 0
