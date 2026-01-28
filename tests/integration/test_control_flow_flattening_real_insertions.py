from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass


def _section_vaddr_and_paddr(binary: Binary) -> tuple[int, int]:
    sections = binary.get_sections()
    if not sections:
        raise RuntimeError("No sections available")
    vaddr = int(sections[0].get("vaddr", 0) or 0)
    paddr = int(sections[0].get("paddr", vaddr) or vaddr)
    return vaddr, paddr


def test_control_flow_flattening_add_opaque_predicate_x86(tmp_path: Path) -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    work_path = tmp_path / "sample.bin"
    work_path.write_bytes(source.read_bytes())

    with Binary(work_path, writable=True) as binary:
        binary.analyze()
        vaddr, paddr = _section_vaddr_and_paddr(binary)
        size = 12
        binary.write_bytes(vaddr, b"\x90" * size)

        pass_obj = ControlFlowFlatteningPass()
        arch, bits = binary.get_arch_family()
        assert arch == "x86"

        ok = pass_obj._add_opaque_predicate(binary, vaddr, size, arch, bits)
        assert ok is True

    data = work_path.read_bytes()
    assert data[paddr : paddr + size] != b"\x90" * size


def test_control_flow_flattening_insert_dead_code_x86(tmp_path: Path) -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    work_path = tmp_path / "sample.bin"
    work_path.write_bytes(source.read_bytes())

    with Binary(work_path, writable=True) as binary:
        binary.analyze()
        vaddr, paddr = _section_vaddr_and_paddr(binary)
        size = 32
        binary.write_bytes(vaddr, b"\x90" * size)

        pass_obj = ControlFlowFlatteningPass()
        arch, bits = binary.get_arch_family()
        ok = pass_obj._insert_dead_code_with_predicate(binary, vaddr, size, arch, bits)
        if not ok:
            pytest.skip("Dead code insertion not supported by assembler on this binary")

    data = work_path.read_bytes()
    assert data[paddr : paddr + size] != b"\x90" * size


def test_control_flow_flattening_dispatcher_arm() -> None:
    binary_path = Path("dataset/macho_arm64")
    if not binary_path.exists():
        pytest.skip("Mach-O test binary not available")

    with Binary(binary_path) as binary:
        binary.analyze()
        pass_obj = ControlFlowFlatteningPass()
        dispatcher = pass_obj._generate_dispatcher(
            binary, [type("B", (), {"address": 0x1000})(), type("B", (), {"address": 0x2000})()]
        )

    assert dispatcher
    assert any(".dispatcher_loop" in line for line in dispatcher)


def test_control_flow_flattening_dispatcher_x86() -> None:
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF test binary not available")

    with Binary(binary_path) as binary:
        binary.analyze()
        pass_obj = ControlFlowFlatteningPass()
        dispatcher = pass_obj._generate_dispatcher(
            binary, [type("B", (), {"address": 0x1000})(), type("B", (), {"address": 0x2000})()]
        )

    assert dispatcher
    assert any(".dispatcher_loop" in line for line in dispatcher)
    assert any(".block_0" in line for line in dispatcher)
