"""
ARM instruction expansion patterns.

Expands simple ARM instructions into more complex equivalents.
"""

ARM64_EXPANSION_PATTERNS = {
    "mov x0, #%d": [
        ["movz x0, #%d", "nop"],
        ["eor x0, x0, x0", "add x0, x0, #%d"],
    ],
    "add x0, x0, #%d": [
        ["add x0, x0, #1"] * None,
    ],
    "sub x0, x0, #%d": [
        ["sub x0, x0, #1"] * None,
    ],
    "nop": [
        ["mov x0, x0"],
        ["add x0, x0, #0"],
        ["sub x0, x0, #0"],
        ["orr x0, x0, xzr"],
    ],
    "cmp x0, x1": [
        ["sub x2, x0, x1", "add x0, x0, #0"],
        ["subs x2, x0, x1"],
    ],
    "mov x0, x1": [
        ["eor x0, x0, x0", "eor x0, x0, x1"],
        ["add x0, xzr, x1"],
        ["orr x0, xzr, x1"],
    ],
    "and x0, x0, x1": [
        ["bic x0, x0, x1", "mvn x0, x0"],
    ],
    "orr x0, x0, x1": [
        ["mvn x0, x0", "bic x0, x0, x1", "mvn x0, x0"],
    ],
    "lsl x0, x0, #1": [
        ["add x0, x0, x0"],
    ],
    "lsr x0, x0, #1": [
        ["udiv x0, x0, #2"],
    ],
    "cset x0, eq": [
        ["mov x0, #0", "cinc x0, x0, eq"],
    ],
    "ldr x0, [x1, #%d]": [
        ["add x2, x1, #%d", "ldr x0, [x2]"],
    ],
    "str x0, [x1, #%d]": [
        ["add x2, x1, #%d", "str x0, [x2]"],
    ],
}

ARM32_EXPANSION_PATTERNS = {
    "mov r0, #%d": [
        ["movw r0, #%d"],
        ["eor r0, r0, r0", "add r0, r0, #%d"],
    ],
    "add r0, r0, #%d": [
        ["add r0, r0, #1"] * None,
    ],
    "sub r0, r0, #%d": [
        ["sub r0, r0, #1"] * None,
    ],
    "nop": [
        ["mov r0, r0"],
        ["add r0, r0, #0"],
        ["andeq r0, r0, r0"],
    ],
    "cmp r0, r1": [
        ["sub r2, r0, r1"],
        ["subs r2, r0, r1"],
    ],
    "mov r0, r1": [
        ["eor r0, r0, r0", "eor r0, r0, r1"],
        ["add r0, r1, #0"],
        ["orr r0, r1, #0"],
    ],
    "lsl r0, r0, #1": [
        ["add r0, r0, r0"],
        ["mov r0, r0, lsl #1"],
    ],
    "and r0, r0, r1": [
        ["bic r0, r0, r1", "mvn r0, r0"],
    ],
    "orr r0, r0, r1": [
        ["mvn r0, r0", "bic r0, r0, r1", "mvn r0, r0"],
    ],
    "moveq r0, r1": [
        ["mov r0, r1"],
    ],
    "ldr r0, [r1, #%d]": [
        ["add r2, r1, #%d", "ldr r0, [r2]"],
    ],
    "str r0, [r1, #%d]": [
        ["add r2, r1, #%d", "str r0, [r2]"],
    ],
    "push {r0}": [
        ["sub sp, sp, #4", "str r0, [sp]"],
    ],
    "pop {r0}": [
        ["ldr r0, [sp]", "add sp, sp, #4"],
    ],
    "push {r0, r1}": [
        ["sub sp, sp, #8", "str r0, [sp]", "str r1, [sp, #4]"],
    ],
    "pop {r0, r1}": [
        ["ldr r0, [sp]", "ldr r1, [sp, #4]", "add sp, sp, #8"],
    ],
}

ARM_THUMB_EXPANSION_PATTERNS = {
    "movs r0, #%d": [
        ["eors r0, r0", "adds r0, #%d"],
    ],
    "adds r0, #%d": [
        ["adds r0, #1"] * None,
    ],
    "subs r0, #%d": [
        ["subs r0, #1"] * None,
    ],
    "nop": [
        ["movs r0, r0"],
        ["adds r0, #0"],
    ],
    "cmp r0, r1": [
        ["subs r2, r0, r1"],
    ],
    "lsls r0, r0, #1": [
        ["adds r0, r0, r0"],
    ],
}


def get_arm_expansion_rules(arch: str, bits: int) -> dict:
    """
    Get ARM expansion rules based on architecture.

    Args:
        arch: Architecture string
        bits: Bit width (32 or 64)

    Returns:
        Dict of expansion patterns
    """
    if "aarch64" in arch.lower() or bits == 64:
        return ARM64_EXPANSION_PATTERNS
    elif "thumb" in arch.lower():
        return ARM_THUMB_EXPANSION_PATTERNS
    else:
        return ARM32_EXPANSION_PATTERNS


ARM64_CALLING_CONVENTION = {
    "argument_regs": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
    "caller_saved": [
        "x0",
        "x1",
        "x2",
        "x3",
        "x4",
        "x5",
        "x6",
        "x7",
        "x8",
        "x9",
        "x10",
        "x11",
        "x12",
        "x13",
        "x14",
        "x15",
        "x16",
        "x17",
        "x18",
    ],
    "callee_saved": ["x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28"],
    "special": {"fp": "x29", "lr": "x30", "sp": "sp", "zr": "xzr"},
    "return_reg": "x0",
}

ARM32_CALLING_CONVENTION = {
    "argument_regs": ["r0", "r1", "r2", "r3"],
    "caller_saved": ["r0", "r1", "r2", "r3", "r12"],
    "callee_saved": ["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"],
    "special": {"fp": "r11", "sp": "r13", "lr": "r14", "pc": "r15"},
    "return_reg": "r0",
}


def get_arm_calling_convention(arch: str, bits: int) -> dict:
    """
    Get ARM calling convention based on architecture.

    Args:
        arch: Architecture string
        bits: Bit width

    Returns:
        Calling convention dict
    """
    if "aarch64" in arch.lower() or bits == 64:
        return ARM64_CALLING_CONVENTION
    else:
        return ARM32_CALLING_CONVENTION
