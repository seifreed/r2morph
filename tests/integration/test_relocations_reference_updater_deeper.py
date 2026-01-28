import shutil
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.relocations.reference_updater import ReferenceUpdater


def _copy_binary(tmp_path: Path, name: str) -> Path:
    src = Path("dataset/elf_x86_64")
    dst = tmp_path / name
    shutil.copy2(src, dst)
    return dst


def test_reference_updater_paths(tmp_path: Path):
    binary_path = _copy_binary(tmp_path, "elf_ref_updater")

    with Binary(binary_path, writable=True) as bin_obj:
        bin_obj.analyze("aa")
        updater = ReferenceUpdater(bin_obj)

        insns = bin_obj.r2.cmdj("aoj 1 @ 0") or []
        assert insns
        insn = insns[0]
        addr = insn.get("addr", 0)
        size = insn.get("size", 1)
        new_target = addr + size + 1

        updated_jump = updater.update_jump_target(addr, addr, new_target)
        assert isinstance(updated_jump, bool)

        updated_call = updater.update_call_target(addr, addr, new_target)
        assert isinstance(updated_call, bool)

        arch_info = bin_obj.get_arch_info()
        ptr_size = arch_info["bits"] // 8
        current_hex = bin_obj.r2.cmd(f"p8 {ptr_size} @ 0x0")
        current_bytes = bytes.fromhex(current_hex.strip()) if current_hex else b"\x00" * ptr_size
        current_value = int.from_bytes(current_bytes, byteorder="little")

        updated_ptr = updater.update_data_pointer(0, current_value, current_value + 1, ptr_size=ptr_size)
        assert isinstance(updated_ptr, bool)

        refs = updater.find_references_to(addr)
        assert isinstance(refs, list)

        updated_count = updater.update_all_references_to(addr, new_target)
        assert isinstance(updated_count, int)
