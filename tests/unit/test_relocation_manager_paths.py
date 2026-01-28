import shutil
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.relocations.manager import RelocationManager


def _copy_binary(tmp_path: Path, name: str) -> Path:
    src = Path("dataset/elf_x86_64")
    dst = tmp_path / name
    shutil.copy2(src, dst)
    return dst


def test_relocation_manager_basic_paths(tmp_path: Path):
    binary_path = _copy_binary(tmp_path, "elf_x86_64_mut")

    with Binary(binary_path, writable=True) as bin_obj:
        bin_obj.analyze("aa")
        manager = RelocationManager(bin_obj)

        manager.add_relocation(0x1000, 0x2000, 16, "move")
        assert manager.get_new_address(0x1000) == 0x2000
        assert manager.get_new_address(0x1008) == 0x2008

        updated = manager.update_all_references()
        assert isinstance(updated, int)


def test_relocation_manager_update_control_flow(tmp_path: Path):
    binary_path = _copy_binary(tmp_path, "elf_x86_64_rel")

    with Binary(binary_path, writable=True) as bin_obj:
        bin_obj.analyze("aa")
        manager = RelocationManager(bin_obj)

        insns = bin_obj.r2.cmdj("aoj 1 @ 0") or []
        assert insns

        insn = insns[0]
        from_addr = insn.get("addr", 0)
        new_target = from_addr + insn.get("size", 1) + 1

        updated = manager._update_control_flow_ref(
            from_addr,
            from_addr,
            new_target,
            insn.get("mnemonic", "jmp"),
        )
        assert isinstance(updated, bool)
