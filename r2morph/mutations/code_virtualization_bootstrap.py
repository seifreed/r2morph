"""Direct-threaded bootstrap for VM integrity-dependent setup."""

from __future__ import annotations

import r2morph.core.randomness as random
from r2morph.mutations.code_virtualization_antidebug import timing_fold_asm, tracer_detect_asm
from r2morph.mutations.code_virtualization_dispatch import offset_jump_block

BOOTSTRAP_STAGE_COUNT = 3
BOOTSTRAP_TABLE_SIZE = BOOTSTRAP_STAGE_COUNT * 4


def build_bootstrap_asm(checksum_offset: int, seed: int, ready_asm: str) -> tuple[str, str]:
    """Return indirect bootstrap code and its trailing plaintext offset table."""
    rng = random.Random(seed ^ 0xB00757A9)
    probe_order = ["timing", "tracer"]
    rng.shuffle(probe_order)
    execution_order = [*probe_order, "ready"]
    opcodes = list(range(BOOTSTRAP_STAGE_COUNT))
    rng.shuffle(opcodes)
    opcode_by_stage = dict(zip(execution_order, opcodes, strict=True))

    def jump(stage: str) -> str:
        return offset_jump_block(
            index_setup=f"  mov eax, {opcode_by_stage[stage]}\n",
            bounds="",
            table_load="  lea r14, [rip+bootstrap_table]\n  mov eax, dword ptr [r14+rax*4]\n",
            table_xors=[
                f"  movzx ecx, byte ptr [rsp+{checksum_offset}]\n" "  imul ecx, ecx, 0x1010101\n  xor eax, ecx\n"
            ],
            rng=rng,
        )

    stages = {
        "timing": timing_fold_asm(seed, slot=checksum_offset),
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


def encrypt_bootstrap_table(data: bytearray, start: int, checksum: int) -> None:
    """Encrypt bootstrap offsets with the runtime checksum broadcast."""
    key = checksum * 0x01010101
    for index in range(BOOTSTRAP_STAGE_COUNT):
        offset = start + index * 4
        value = int.from_bytes(data[offset : offset + 4], "little") ^ key
        data[offset : offset + 4] = value.to_bytes(4, "little")
