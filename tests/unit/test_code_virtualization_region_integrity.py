import r2morph.core.randomness as random
from r2morph.mutations.code_virtualization_engine_common import build_vm_scheme
from r2morph.mutations.code_virtualization_region_integrity import (
    checksum_prologue_asm,
    compute_build_checksum,
)


def test_checksum_modes_preserve_distinct_traversal_semantics() -> None:
    code = bytes(range(7))

    block_checksum = compute_build_checksum(code, 84)
    bytewise_checksum = compute_build_checksum(code, 84, bytewise=True)

    assert block_checksum != bytewise_checksum


def test_checksum_bytewise_mode_emits_linear_byte_loop() -> None:
    assembly = checksum_prologue_asm(84, bytewise=True)

    assert "inc rdi" in assembly


def test_checksum_block_mode_emits_guarded_block_loop() -> None:
    assembly = checksum_prologue_asm(84)

    assert "add rdi, 4" in assembly


def test_vm_scheme_checksum_mode_varies_across_seeds() -> None:
    modes = {build_vm_scheme(random.Random(seed)).checksum_bytewise for seed in range(128)}

    assert modes == {False, True}
