import shutil
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.devirtualization.vm_handler_analyzer import VMHandlerAnalyzer
from tests.utils.platform_binaries import get_platform_binary, ensure_exists


def test_vm_handler_table_validation_and_extraction(tmp_path):
    src = get_platform_binary("generic")
    if not ensure_exists(Path(src)):
        return
    target = tmp_path / "pe_vm_table.exe"
    shutil.copy2(src, target)

    with Binary(target, writable=True) as bin_obj:
        bin_obj.analyze("aa")
        functions = bin_obj.get_functions()
        addrs = [f.get("offset") or f.get("addr") for f in functions if (f.get("offset") or f.get("addr"))]
        assert addrs

        sections = bin_obj.get_sections()
        section = next(
            (s for s in sections if "x" in (s.get("perm") or "")),
            sections[0],
        )
        table_addr = int(section.get("vaddr", section.get("paddr", 0) or 0)) + 0x20
        ptr_size = bin_obj.get_arch_info().get("bits", 64) // 8

        table_entries = addrs[:4]
        table_bytes = b"".join(int(addr).to_bytes(ptr_size, "little") for addr in table_entries)
        bin_obj.write_bytes(table_addr, table_bytes)

        analyzer = VMHandlerAnalyzer(bin_obj)
        assert analyzer._validate_handler_table(table_addr) is True

        extracted = analyzer._extract_handler_addresses(table_addr)
        assert extracted
        assert extracted[0] in table_entries
