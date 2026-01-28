from __future__ import annotations

from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass


def test_control_flow_flattening_obfuscate_unconditional_jump(tmp_path: Path) -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    work_path = tmp_path / "jump_sample.bin"
    work_path.write_bytes(source.read_bytes())

    with Binary(work_path, writable=True) as binary:
        binary.analyze()
        sections = binary.get_sections()
        assert sections
        section = next((s for s in sections if s.get("vaddr")), sections[0])
        vaddr = int(section.get("vaddr", 0) or 0)
        assert vaddr > 0

        # Reserve space for jump obfuscation
        binary.write_bytes(vaddr, b"\x90" * 8)

        pass_obj = ControlFlowFlatteningPass()
        ok = pass_obj._obfuscate_jump(
            binary,
            {"offset": vaddr, "size": 5, "disasm": f"jmp 0x{vaddr + 2:x}"},
            {},
            "x86",
            64,
        )
        assert ok is True

    data = work_path.read_bytes()
    assert data != source.read_bytes()
