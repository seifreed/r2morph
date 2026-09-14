from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.opaque_predicates import OpaquePredicatePass
from tests.utils.assertions import expect


class _PredicateAssembler:
    def __init__(self) -> None:
        self.instructions: list[str] = []

    def assemble(self, instruction: str, _address: int | None = None) -> bytes:
        self.instructions.append(instruction)
        return b"\x74\x00" if instruction.startswith(("jz ", "jnz ", "je ", "jne ")) else b"\x90"


def test_opaque_predicate_generators():
    pass_obj = OpaquePredicatePass()
    x86_pred = pass_obj._generate_x86_predicate("always_true", 64)
    arm_pred = pass_obj._generate_arm_predicate("always_false", 64)

    expect(isinstance(x86_pred, list))
    expect(isinstance(arm_pred, list))
    expect(x86_pred)
    expect(arm_pred)


def test_x86_opaque_predicates_preserve_registers_and_flags():
    predicate = OpaquePredicatePass()._generate_x86_predicate("always_true", 64)

    expect(predicate[0] == "pushfq")
    expect("push r11" in predicate)
    expect("pop r11" in predicate)
    expect(predicate[-1] == "popfq")


def test_opaque_predicate_assembles_local_labels_as_absolute_targets():
    assembler = _PredicateAssembler()
    pass_obj = OpaquePredicatePass()

    assembled = pass_obj._assemble_predicate(
        assembler,
        ["xor rax, rax", "test rax, rax", "jz .real_code", ".real_code:"],
        0x1000,
    )

    expect(assembled == b"\x90\x90\x74\x00")
    expect(all(".real_code" not in instruction for instruction in assembler.instructions))


def test_opaque_predicate_apply_real_binary(tmp_path: Path):
    binary_path = Path("fixtures/dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    temp_binary = tmp_path / "opaque_pred"
    temp_binary.write_bytes(binary_path.read_bytes())

    with Binary(temp_binary, writable=True) as bin_obj:
        bin_obj.analyze()
        pass_obj = OpaquePredicatePass(config={"max_predicates_per_function": 2, "probability": 1.0})
        result = pass_obj.apply(bin_obj)

    expect(not ("mutations_applied" not in result))
