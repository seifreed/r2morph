import platform
import shutil
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.relocations.manager import RelocationManager
from tests.utils.platform_binaries import get_platform_binary, ensure_exists


def _copy_binary(tmp_path: Path, name: str) -> Path:
    src = Path(get_platform_binary("generic"))
    if platform.system() == "Windows":
        fallback = Path("dataset/pe_x86_64.exe")
        if ensure_exists(fallback):
            src = fallback
    if not ensure_exists(src):
        return tmp_path / name
    dst = tmp_path / name
    shutil.copy2(src, dst)
    return dst


def test_relocation_manager_basic_paths(tmp_path: Path):
    binary_path = _copy_binary(tmp_path, "elf_x86_64_mut")
    if not binary_path.exists():
        return

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
    if not binary_path.exists():
        return

    with Binary(binary_path, writable=True) as bin_obj:
        bin_obj.analyze("aa")
        manager = RelocationManager(bin_obj)

        sections = bin_obj.get_sections()
        section = next(
            (s for s in sections if (s.get("vaddr") or s.get("paddr"))),
            None,
        )
        if section is None:
            return
        base_addr = int(section.get("vaddr", section.get("paddr", 0)) or 0)
        insns = bin_obj.r2.cmdj(f"aoj 1 @ 0x{base_addr:x}") or []
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
