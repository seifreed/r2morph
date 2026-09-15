"""Regression tests for fail-closed VM bytecode encoding."""

from r2morph.core import randomness
from r2morph.mutations.code_virtualization_engine_common import build_vm_scheme
from r2morph.mutations.code_virtualization_engine_encoder import (
    UnsupportedVirtualizationError,
    encode_bytecode,
)
from r2morph.mutations.code_virtualization_engine_models import (
    VirtualizedFpArithOp,
    VirtualizedOp,
)
from tests.utils.assertions import expect


def test_encode_unknown_gp_opcode_rejects_without_emitting_bytecode() -> None:
    try:
        encode_bytecode(
            [VirtualizedOp("not-an-opcode", 0, 1, False, 64)],
            build_vm_scheme(randomness.Random(20260915)),
        )
    except UnsupportedVirtualizationError as error:
        expect("no VM opcode contract" in str(error))
    else:
        raise AssertionError("unknown GP opcode was encoded")


def test_encode_unknown_fp_operation_rejects_without_emitting_bytecode() -> None:
    try:
        encode_bytecode(
            [VirtualizedFpArithOp("not-an-fp-operation", 0, 1, 64)],
            build_vm_scheme(randomness.Random(20260916)),
        )
    except UnsupportedVirtualizationError as error:
        expect("no VM opcode contract" in str(error))
    else:
        raise AssertionError("unknown FP operation was encoded")
