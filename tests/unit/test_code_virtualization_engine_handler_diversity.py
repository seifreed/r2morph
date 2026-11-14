"""Keep duplicate opcode handlers structurally distinct within each VM build."""

from __future__ import annotations

from r2morph.core import randomness
from r2morph.mutations.code_virtualization_engine_codegen import _interpreter_asm
from r2morph.mutations.code_virtualization_engine_common import build_vm_scheme
from scripts.protection_handler_clustering import _HANDLER_PATTERN, _normalise_body
from tests.utils.assertions import expect

_DUPLICATE_HANDLER_COUNT = 2


def _duplicate_handler_bodies(seed: int, operation: tuple[str, bool, int]) -> tuple[tuple[str, ...], ...]:
    scheme = build_vm_scheme(randomness.Random(seed))
    duplicate_indexes = scheme.dup[operation]
    assembly = _interpreter_asm(0, scheme, has_fp=True)
    bodies = {int(match.group(1)): _normalise_body(match.group(2)) for match in _HANDLER_PATTERN.finditer(assembly)}
    return tuple(bodies[index] for index in duplicate_indexes)


def test_duplicate_fp_multiply_handlers_keep_distinct_normalized_bodies() -> None:
    bodies = _duplicate_handler_bodies(20260855, ("fpmul", False, 32))

    expect(len(bodies) == _DUPLICATE_HANDLER_COUNT and bodies[0] != bodies[1])


def test_duplicate_fp_load_handlers_keep_distinct_normalized_bodies() -> None:
    bodies = _duplicate_handler_bodies(20260878, ("fpload", False, 64))

    expect(len(bodies) == _DUPLICATE_HANDLER_COUNT and bodies[0] != bodies[1])
