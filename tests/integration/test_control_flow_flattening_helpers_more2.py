from pathlib import Path
from types import SimpleNamespace

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass


def _copy_binary(tmp_path: Path, name: str) -> Path:
    src = Path("dataset/elf_x86_64")
    dst = tmp_path / name
    dst.write_bytes(src.read_bytes())
    return dst


def test_control_flow_flattening_jump_and_nop_helpers():
    mutator = ControlFlowFlatteningPass()

    assert mutator._is_conditional_jump("je", "x86") is True
    assert mutator._is_conditional_jump("jmp", "x86") is False
    assert mutator._is_conditional_jump("b.eq", "arm") is True
    assert mutator._is_conditional_jump("b", "arm") is False
    assert mutator._is_conditional_jump("jne", "unknown") is True

    instructions = [
        {"mnemonic": "nop", "offset": 0x1000, "size": 1},
        {"mnemonic": "nop", "offset": 0x1001, "size": 1},
        {"mnemonic": "nop", "offset": 0x1002, "size": 1},
        {"mnemonic": "mov", "offset": 0x1003, "size": 2},
    ]
    sequences = mutator._find_nop_sequences(instructions)
    assert sequences == [(0x1000, 3)]


def test_control_flow_flattening_dispatcher_generation(tmp_path: Path):
    binary_path = _copy_binary(tmp_path, "elf_dispatcher")
    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        mutator = ControlFlowFlatteningPass()
        blocks = [SimpleNamespace(address=0x1000), SimpleNamespace(address=0x2000)]
        dispatcher = mutator._generate_dispatcher(bin_obj, blocks)
        assert dispatcher


def test_control_flow_flattening_add_opaque_predicate(tmp_path: Path):
    binary_path = _copy_binary(tmp_path, "elf_predicate")
    with Binary(binary_path, writable=True) as bin_obj:
        bin_obj.analyze("aa")
        mutator = ControlFlowFlatteningPass()
        arch_family, bits = bin_obj.get_arch_family()

        sections = bin_obj.get_sections()
        exec_section = next(
            (sec for sec in sections if "x" in sec.get("perm", "").lower()),
            None,
        )
        if exec_section is None:
            pytest.skip("No executable section found")

        addr = exec_section.get("vaddr", 0) + 0x10
        available_size = 8

        ok = mutator._add_opaque_predicate(bin_obj, addr, available_size, arch_family, bits)
        assert isinstance(ok, bool)
        if ok:
            data_hex = bin_obj.r2.cmd(f"p8 {available_size} @ 0x{addr:x}")
            assert len(bytes.fromhex(data_hex.strip())) == available_size
