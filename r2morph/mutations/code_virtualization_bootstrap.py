"""Direct-threaded bootstrap for VM integrity-dependent setup."""

from __future__ import annotations

import r2morph.core.randomness as random
from r2morph.mutations.code_virtualization_antidebug import tracer_detect_asm
from r2morph.mutations.code_virtualization_dispatch import offset_jump_block

BOOTSTRAP_STAGE_COUNT = 2
BOOTSTRAP_TABLE_SIZE = BOOTSTRAP_STAGE_COUNT * 4
TABLE_KEY_MASK = (1 << 32) - 1
_TABLE_MIX_MASK = 0x7FFFFFFF
_TABLE_MIX_SEED = 0x9E3779B9


def table_key_mix(seed: int) -> int:
    """Return an odd positive multiplier for per-entry table masking."""
    return ((seed ^ _TABLE_MIX_SEED) & _TABLE_MIX_MASK) | 1


def table_entry_key(checksum: int, index: int, mix: int) -> int:
    """Return the 32-bit key used for one relative-offset table entry."""
    broadcast = checksum * 0x01010101
    return (broadcast ^ ((index + 1) * mix)) & TABLE_KEY_MASK


def build_bootstrap_asm(checksum_offset: int, seed: int, ready_asm: str) -> tuple[str, str]:
    """Return indirect bootstrap code and its trailing plaintext offset table."""
    rng = random.Random(seed ^ 0xB00757A9)
    execution_order = ["tracer", "ready"]
    opcodes = list(range(BOOTSTRAP_STAGE_COUNT))
    rng.shuffle(opcodes)
    opcode_by_stage = dict(zip(execution_order, opcodes, strict=True))

    def jump(stage: str) -> str:
        mix = table_key_mix(seed)
        return offset_jump_block(
            index_setup=f"  mov eax, {opcode_by_stage[stage]}\n  mov edx, eax\n  inc edx\n",
            bounds="",
            table_load="  lea r14, [rip+bootstrap_table]\n  mov eax, dword ptr [r14+rax*4]\n",
            table_xors=[
                f"  movzx ecx, byte ptr [rsp+{checksum_offset}]\n"
                f"  imul ecx, ecx, 0x1010101\n  imul edx, edx, {mix}\n  xor ecx, edx\n  xor eax, ecx\n"
            ],
            rng=rng,
        )

    stages = {
        "tracer": tracer_detect_asm(slot=checksum_offset),
        "ready": ready_asm,
    }
    emitted = list(stages)
    rng.shuffle(emitted)
    bodies = []
    for stage in emitted:
        body = stages[stage]
        position = execution_order.index(stage)
        if position + 1 < len(execution_order):
            body += jump(execution_order[position + 1])
        bodies.append(f"bootstrap_{stage}:\n{body}")

    labels_by_opcode = {opcode: stage for stage, opcode in opcode_by_stage.items()}
    table = "bootstrap_table:\n" + "".join(
        f"  .long bootstrap_{labels_by_opcode[index]} - bootstrap_table\n" for index in range(BOOTSTRAP_STAGE_COUNT)
    )
    return jump(execution_order[0]) + "".join(bodies), table


def encrypt_bootstrap_table(data: bytearray, start: int, checksum: int, mix: int) -> None:
    """Encrypt bootstrap offsets with checksum and build-derived index masks."""
    for index in range(BOOTSTRAP_STAGE_COUNT):
        offset = start + index * 4
        entry_key = table_entry_key(checksum, index, mix)
        value = int.from_bytes(data[offset : offset + 4], "little") ^ entry_key
        data[offset : offset + 4] = value.to_bytes(4, "little")
