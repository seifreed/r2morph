from io import StringIO
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.core.constants import OPAQUE_PREDICATE_MAX_FUNCTIONS_PER_BINARY
from r2morph.mutations.opaque_predicates import OpaquePredicatePass
from r2morph.utils.logging import setup_logging, shutdown_logging
from tests.utils.assertions import expect

_FUNCTION_ADDRESS_BASE = 0x1000
_FUNCTION_SET_MULTIPLIER = 2


class _PredicateAssembler:
    def __init__(self) -> None:
        self.instructions: list[str] = []

    def assemble(self, instruction: str, _address: int | None = None) -> bytes:
        self.instructions.append(instruction)
        return b"\x74\x00" if instruction.startswith(("jz ", "jnz ", "je ", "jne ")) else b"\x90"


class _FunctionBinary:
    def get_functions(self) -> list[dict[str, int]]:
        return [{"addr": 0x1000, "size": 32}, {"addr": 0x2000, "size": 32}]


class _ManyFunctionsBinary:
    def get_functions(self) -> list[dict[str, int]]:
        function_count = OPAQUE_PREDICATE_MAX_FUNCTIONS_PER_BINARY * _FUNCTION_SET_MULTIPLIER
        return [{"addr": _FUNCTION_ADDRESS_BASE + index, "size": 32} for index in range(function_count)]


class _SingleBlockBinary:
    class _R2:
        @staticmethod
        def cmd(_command: str) -> str:
            return '[{"addr":4096,"size":32}]'

    r2 = _R2()

    @staticmethod
    def get_arch_info() -> dict[str, str]:
        raise AssertionError("single-block functions do not need architecture analysis")


class _RecordingOpaquePredicatePass(OpaquePredicatePass):
    def __init__(self) -> None:
        super().__init__()
        self.injector_ids: list[int] = []
        self.function_addresses: list[int] = []

    def _insert_opaque_predicates(self, binary, func, injector):
        self.injector_ids.append(id(injector))
        self.function_addresses.append(func["addr"])
        return 0


def test_opaque_predicate_generators():
    pass_obj = OpaquePredicatePass()
    x86_pred = pass_obj._generate_x86_predicate("always_true", 64)
    arm_pred = pass_obj._generate_arm_predicate("always_false", 64)

    expect(isinstance(x86_pred, list))
    expect(isinstance(arm_pred, list))
    expect(x86_pred)
    expect(arm_pred)


def test_opaque_predicate_apply_reuses_one_injector_across_functions():
    pass_obj = _RecordingOpaquePredicatePass()

    pass_obj.apply(_FunctionBinary())

    expect(len(set(pass_obj.injector_ids)) == 1)


def test_opaque_predicate_function_analysis_samples_full_binary_within_budget():
    pass_obj = _RecordingOpaquePredicatePass()
    log_output = StringIO()
    setup_logging(level="WARNING", stream=log_output, environ={})

    try:
        pass_obj.apply(_ManyFunctionsBinary())

        expect(
            len(pass_obj.function_addresses) == OPAQUE_PREDICATE_MAX_FUNCTIONS_PER_BINARY
            and pass_obj.function_addresses[0] == _FUNCTION_ADDRESS_BASE
            and pass_obj.function_addresses[-1]
            == _FUNCTION_ADDRESS_BASE + OPAQUE_PREDICATE_MAX_FUNCTIONS_PER_BINARY * _FUNCTION_SET_MULTIPLIER - 1
            and "limited to" in log_output.getvalue()
        )
    finally:
        shutdown_logging()


def test_opaque_predicate_skips_analysis_for_single_block_function():
    pass_obj = OpaquePredicatePass()

    mutations = pass_obj._insert_opaque_predicates(_SingleBlockBinary(), {"addr": 0x1000}, object())

    expect(mutations == 0)


def test_x86_opaque_predicates_require_dead_registers_and_flags():
    predicate = OpaquePredicatePass()._generate_x86_predicate("always_true", 64)

    expect(predicate[0] == "xor r11d, r11d")
    expect("pushfq" not in predicate and "popfq" not in predicate)
    expect("push r11" not in predicate and "pop r11" not in predicate)


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


def test_opaque_predicate_rejects_rip_relative_memory_operand():
    instruction = {
        "addr": 0x1000,
        "bytes": "488d0534120000",
        "disasm": "lea rax, [0x223b]",
    }

    has_pc_relative_memory = OpaquePredicatePass._has_pc_relative_memory_operand(instruction)

    expect(has_pc_relative_memory is True)


def test_opaque_predicate_rejects_non_relative_memory_operand():
    instruction = {
        "addr": 0x1000,
        "bytes": "488b45f8",
        "disasm": "mov rax, [rbp - 8]",
    }

    has_memory = OpaquePredicatePass._has_memory_operand(instruction)

    expect(has_memory is True)


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
