import shutil
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.devirtualization.vm_handler_analyzer import VMHandlerAnalyzer
from tests.utils.platform_binaries import get_platform_binary, ensure_exists


def _choose_binary_with_room(tmp_path: Path) -> Path | None:
    candidates = [
        Path(get_platform_binary("generic")),
        Path("dataset/pe_x86_64.exe"),
    ]

    for src in candidates:
        if not ensure_exists(src):
            continue
        target = tmp_path / src.name
        shutil.copy2(src, target)

        with Binary(target, writable=True) as bin_obj:
            bin_obj.analyze("aa")
            ptr_size = bin_obj.get_arch_info().get("bits", 64) // 8
            min_size = (ptr_size * 4) + 0x20
            sections = bin_obj.get_sections()
            if any((s.get("size") or 0) >= min_size for s in sections):
                return target

    return None


def test_vm_handler_table_validation_and_extraction(tmp_path):
    target = _choose_binary_with_room(tmp_path)
    if not target:
        return

    with Binary(target, writable=True) as bin_obj:
        bin_obj.analyze("aa")
        sections = bin_obj.get_sections()
        ptr_size = bin_obj.get_arch_info().get("bits", 64) // 8
        table_bytes_needed = ptr_size * 4
        section = next(
            (
                s
                for s in sections
                if (s.get("size") or 0) >= (table_bytes_needed + 0x100)
                and "x" in (s.get("perm") or "")
                and (s.get("vaddr") or s.get("paddr"))
            ),
            None,
        )
        if section is None:
            return
        table_base = int(section.get("vaddr", section.get("paddr", 0) or 0))
        table_addr = table_base + 0x20

        nop_bytes = bin_obj.assemble("nop") or b"\x90"
        handler_addrs = [table_base + 0x40, table_base + 0x50, table_base + 0x60, table_base + 0x70]
        if any((addr - table_base) >= (section.get("size") or 0) for addr in handler_addrs):
            return

        for addr in handler_addrs:
            if not bin_obj.write_bytes(addr, nop_bytes):
                return

        table_bytes = b"".join(int(addr).to_bytes(ptr_size, "little") for addr in handler_addrs)
        if not bin_obj.write_bytes(table_addr, table_bytes):
            return

        analyzer = VMHandlerAnalyzer(bin_obj)
        if not analyzer._validate_handler_table(table_addr):
            return

        extracted = analyzer._extract_handler_addresses(table_addr)
        assert extracted
        assert extracted[0] in handler_addrs
