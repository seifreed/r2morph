import shutil
import platform
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.relocations.reference_updater import ReferenceUpdater
from tests.utils.platform_binaries import get_platform_binary, ensure_exists


def _find_writable_code_region(bin_obj, minimum_size: int = 16) -> int:
    fallback = 0
    for section in bin_obj.get_sections():
        size = section.get("size") or 0
        vaddr = section.get("vaddr")
        perm = section.get("perm") or ""
        if vaddr is None:
            continue
        if size >= minimum_size and "x" in perm:
            return int(vaddr)
        if size >= minimum_size and not fallback:
            fallback = int(vaddr)
    return fallback


def _read_bytes(bin_obj, addr: int, size: int) -> bytes:
    hex_bytes = bin_obj.r2.cmd(f"p8 {size} @ 0x{addr:x}").strip()
    return bytes.fromhex(hex_bytes) if hex_bytes else b""


def test_reference_updater_updates_call_jump_and_data(tmp_path):
    src_candidates = [Path("dataset/pe_x86_64.exe"), Path(get_platform_binary("generic"))]
    src_binary = next((p for p in src_candidates if ensure_exists(p)), None)
    if not src_binary:
        return
    bin_path = tmp_path / src_binary.name
    shutil.copy2(src_binary, bin_path)

    with Binary(bin_path, writable=True) as bin_obj:
        bin_obj.analyze("aa")
        ref_updater = ReferenceUpdater(bin_obj)

        base_addr = _find_writable_code_region(bin_obj, minimum_size=12)
        assert base_addr != 0

        call_addr = base_addr
        jmp_addr = base_addr + 5

        call_bytes = b"\xE8\x00\x00\x00\x00"
        jmp_bytes = b"\xE9\x00\x00\x00\x00"
        assert bin_obj.write_bytes(call_addr, call_bytes) is True
        assert bin_obj.write_bytes(jmp_addr, jmp_bytes) is True

        call_info = bin_obj.r2.cmdj(f"aoj 1 @ 0x{call_addr:x}") or []
        jmp_info = bin_obj.r2.cmdj(f"aoj 1 @ 0x{jmp_addr:x}") or []
        assert call_info
        assert jmp_info

        call_size = call_info[0].get("size", 0)
        jmp_size = jmp_info[0].get("size", 0)
        assert call_size > 0
        assert jmp_size > 0

        call_old = _read_bytes(bin_obj, call_addr, call_size)
        jmp_old = _read_bytes(bin_obj, jmp_addr, jmp_size)

        call_old_target = call_addr + call_size
        call_new_target = call_old_target + 4
        assert ref_updater.update_call_target(call_addr, call_old_target, call_new_target) is True
        assert call_addr in ref_updater.updated_refs

        jmp_old_target = jmp_addr + jmp_size
        jmp_new_target = jmp_old_target + 4
        assert ref_updater.update_jump_target(jmp_addr, jmp_old_target, jmp_new_target) is True
        assert jmp_addr in ref_updater.updated_refs

        call_new = _read_bytes(bin_obj, call_addr, call_size)
        jmp_new = _read_bytes(bin_obj, jmp_addr, jmp_size)
        assert call_new != call_old
        assert jmp_new != jmp_old

        sections = bin_obj.get_sections()
        ptr_section = next(
            (s for s in sections if "w" in (s.get("perm") or "")),
            sections[0],
        )
        ptr_addr = int(ptr_section.get("vaddr", ptr_section.get("paddr", 0))) or base_addr
        ptr_size = bin_obj.get_arch_info().get("bits", 64) // 8
        old_value = 0x1122334455667788
        new_value = 0x8877665544332211

        bin_obj.write_bytes(ptr_addr, old_value.to_bytes(ptr_size, byteorder="little"))
        assert ref_updater.update_data_pointer(ptr_addr, old_value, new_value) is True
        assert ptr_addr in ref_updater.updated_refs

        mismatch = ref_updater.update_data_pointer(ptr_addr, old_value, new_value)
        assert mismatch is False
