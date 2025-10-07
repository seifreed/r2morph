"""
ARM64 and ARM32 instruction substitution rules.

Provides comprehensive equivalence patterns for ARM architectures.
"""

ARM64_EQUIVALENCE_GROUPS = [
    [
        "mov x0, #0",
        "eor x0, x0, x0",
        "sub x0, x0, x0",
        "and x0, x0, #0",
    ],
    [
        "mov w0, #0",
        "eor w0, w0, w0",
        "sub w0, w0, w0",
        "and w0, w0, #0",
    ],
    [
        "mov x1, #0",
        "eor x1, x1, x1",
        "sub x1, x1, x1",
    ],
    [
        "mov w1, #0",
        "eor w1, w1, w1",
        "sub w1, w1, w1",
    ],
    [
        "mov x2, #0",
        "eor x2, x2, x2",
        "sub x2, x2, x2",
    ],
    [
        "mov x3, #0",
        "eor x3, x3, x3",
        "sub x3, x3, x3",
    ],
    [
        "add x0, x0, #1",
        "sub x0, x0, #-1",
    ],
    [
        "add w0, w0, #1",
        "sub w0, w0, #-1",
    ],
    [
        "add x1, x1, #1",
        "sub x1, x1, #-1",
    ],
    [
        "sub x0, x0, #1",
        "add x0, x0, #-1",
    ],
    [
        "sub w0, w0, #1",
        "add w0, w0, #-1",
    ],
    [
        "neg x0, x0",
        "sub x0, xzr, x0",
    ],
    [
        "neg w0, w0",
        "sub w0, wzr, w0",
    ],
    [
        "mov x0, x0",
        "orr x0, x0, xzr",
        "add x0, x0, #0",
    ],
    [
        "mov w0, w0",
        "orr w0, w0, wzr",
        "add w0, w0, #0",
    ],
    [
        "mvn x0, x0",
        "orn x0, xzr, x0",
    ],
    [
        "mvn w0, w0",
        "orn w0, wzr, w0",
    ],
    [
        "mov x0, #1",
        "movz x0, #1",
    ],
    [
        "mov w0, #1",
        "movz w0, #1",
    ],
    [
        "cmp x0, #0",
        "cmp x0, xzr",
    ],
    [
        "cmp w0, #0",
        "cmp w0, wzr",
    ],
    [
        "tst x0, x1",
        "ands xzr, x0, x1",
    ],
    [
        "tst w0, w1",
        "ands wzr, w0, w1",
    ],
    [
        "mov x0, #-1",
        "movn x0, #0",
    ],
    [
        "lsl x0, x0, #1",
        "add x0, x0, x0",
    ],
    [
        "lsl w0, w0, #1",
        "add w0, w0, w0",
    ],
    [
        "mov x0, x1",
        "csel x0, x1, x1, al",
    ],
]

ARM32_EQUIVALENCE_GROUPS = [
    [
        "mov r0, #0",
        "eor r0, r0, r0",
        "sub r0, r0, r0",
        "and r0, r0, #0",
    ],
    [
        "mov r1, #0",
        "eor r1, r1, r1",
        "sub r1, r1, r1",
    ],
    [
        "mov r2, #0",
        "eor r2, r2, r2",
        "sub r2, r2, r2",
    ],
    [
        "mov r3, #0",
        "eor r3, r3, r3",
        "sub r3, r3, r3",
    ],
    [
        "mov r4, #0",
        "eor r4, r4, r4",
        "sub r4, r4, r4",
    ],
    [
        "add r0, r0, #1",
        "sub r0, r0, #-1",
    ],
    [
        "add r1, r1, #1",
        "sub r1, r1, #-1",
    ],
    [
        "sub r0, r0, #1",
        "add r0, r0, #-1",
    ],
    [
        "sub r1, r1, #1",
        "add r1, r1, #-1",
    ],
    [
        "mov r0, r0",
        "orr r0, r0, #0",
        "add r0, r0, #0",
    ],
    [
        "mov r1, r1",
        "orr r1, r1, #0",
        "add r1, r1, #0",
    ],
    [
        "neg r0, r0",
        "rsb r0, r0, #0",
    ],
    [
        "neg r1, r1",
        "rsb r1, r1, #0",
    ],
    [
        "mvn r0, r0",
        "eor r0, r0, #-1",
    ],
    [
        "cmp r0, #0",
        "tst r0, r0",
    ],
    [
        "mov r0, #1",
        "mvn r0, #-2",
    ],
    [
        "lsl r0, r0, #1",
        "add r0, r0, r0",
    ],
    [
        "lsl r1, r1, #1",
        "add r1, r1, r1",
    ],
    [
        "asr r0, r0, #1",
        "movs r0, r0, asr #1",
    ],
    [
        "mov r0, r1",
        "moveq r0, r1",
        "movne r0, r1",
    ],
    [
        "tst r0, r1",
        "ands r2, r0, r1",
    ],
    [
        "adc r0, r0, #0",
        "adcs r0, r0, #0",
    ],
]

ARM_THUMB_EQUIVALENCE_GROUPS = [
    [
        "movs r0, #0",
        "eors r0, r0",
        "subs r0, r0",
    ],
    [
        "movs r1, #0",
        "eors r1, r1",
        "subs r1, r1",
    ],
    [
        "adds r0, #1",
        "subs r0, #-1",
    ],
    [
        "subs r0, #1",
        "adds r0, #-1",
    ],
    [
        "lsls r0, r0, #1",
        "adds r0, r0, r0",
    ],
]


def get_arm_rules(arch: str, bits: int) -> list:
    """
    Get ARM substitution rules based on architecture.

    Args:
        arch: Architecture string ("arm", "aarch64", etc.)
        bits: Bit width (32 or 64)

    Returns:
        List of equivalence groups
    """
    if "aarch64" in arch.lower() or bits == 64:
        return ARM64_EQUIVALENCE_GROUPS
    elif "thumb" in arch.lower():
        return ARM_THUMB_EQUIVALENCE_GROUPS
    else:
        return ARM32_EQUIVALENCE_GROUPS
