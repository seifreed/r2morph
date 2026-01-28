from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary


def _get_section_vaddr(binary: Binary) -> int:
    sections = binary.get_sections()
    if not sections:
        raise RuntimeError("No sections available")
    for section in sections:
        perm = str(section.get("perm") or "").lower()
        vaddr = section.get("vaddr")
        paddr = section.get("paddr")
        size = section.get("size") or section.get("vsize") or 0
        if size and ("x" in perm or "r" in perm) and (vaddr or paddr):
            return int(vaddr or paddr)
    return int(sections[0].get("vaddr", 0) or sections[0].get("paddr", 0) or 0)

def _map_vaddr_to_paddr(binary: Binary, vaddr: int) -> int | None:
    if not binary.r2:
        return None

    paddr_str = binary.r2.cmd(f"s2p 0x{vaddr:x}").strip()
    if paddr_str:
        try:
            return int(paddr_str, 16)
        except ValueError:
            pass

    for section in binary.get_sections():
        sec_vaddr = section.get("vaddr")
        sec_paddr = section.get("paddr")
        size = section.get("size") or section.get("vsize") or 0
        if sec_vaddr is None or sec_paddr is None or not size:
            continue
        if sec_vaddr <= vaddr < sec_vaddr + size:
            return int(sec_paddr + (vaddr - sec_vaddr))

    return None


def test_binary_write_bytes_and_nop_fill(tmp_path: Path) -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    work_path = tmp_path / "sample.bin"
    work_path.write_bytes(source.read_bytes())

    with Binary(work_path, writable=True, low_memory=True) as binary:
        binary.analyze()
        vaddr = _get_section_vaddr(binary)

        assert binary.write_bytes(vaddr, b"\x90")
        assert binary.nop_fill(vaddr + 1, 3)

        paddr = _map_vaddr_to_paddr(binary, vaddr)
        if paddr is None:
            pytest.skip("Unable to map vaddr to file offset for verification")

    data = work_path.read_bytes()
    assert data[paddr : paddr + 4] == b"\x90" * 4


def test_binary_resolve_symbolic_vars_and_assemble(tmp_path: Path) -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    work_path = tmp_path / "sample.bin"
    work_path.write_bytes(source.read_bytes())

    with Binary(work_path, writable=True) as binary:
        binary.analyze()

        resolved = binary._resolve_symbolic_vars("mov eax, [var_10h]")
        assert "[rsp + 0x10]" in resolved

        movzx_bytes = binary._assemble_movzx_movsx_fallback("movzx eax, al")
        assert isinstance(movzx_bytes, (bytes, bytearray))
        assert movzx_bytes is not None

        assembled = binary.assemble("movzx eax, al")
        assert isinstance(assembled, (bytes, bytearray))

        seg_bytes = binary._assemble_segment_prefix_fallback("mov dword fs:[rax], ecx")
        if seg_bytes is not None:
            assert seg_bytes[0] in {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65}


def test_binary_arch_info_and_reload(tmp_path: Path) -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    work_path = tmp_path / "sample.bin"
    work_path.write_bytes(source.read_bytes())

    with Binary(work_path, writable=False, low_memory=True) as binary:
        binary.analyze()
        arch_info = binary.get_arch_info()
        family, bits = binary.get_arch_family()

        assert isinstance(arch_info, dict)
        assert isinstance(family, str)
        assert isinstance(bits, int)

        binary.track_mutation(batch_size=1)
        binary.reload()
        assert binary.r2 is not None
