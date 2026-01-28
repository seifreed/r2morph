"""Dead code generation utilities for metamorphic transformations.

This module provides shared utilities for generating dead code sequences
used by various mutation passes including dead code injection and control
flow flattening.

Dead code is code that never executes but adds complexity to binary analysis.
These utilities generate architecture-appropriate instruction sequences that:
- Preserve register values (using push/pop or self-canceling operations)
- Are syntactically valid assembly
- Can be assembled by radare2's inline assembler
"""

import random
from typing import Any


def generate_x86_dead_code(bits: int = 64, complexity: str = "medium") -> list[str]:
    """
    Generate dead code instructions for x86/x64.

    Args:
        bits: Bit width (32 or 64)
        complexity: Complexity level ("simple", "medium", or "complex")

    Returns:
        List of assembly instructions
    """
    if complexity == "simple":
        return _generate_x86_simple(bits)
    elif complexity == "complex":
        return _generate_x86_complex(bits)
    else:
        return _generate_x86_medium(bits)


def _generate_x86_simple(bits: int) -> list[str]:
    """Generate simple x86 dead code (NOPs or simple ops)."""
    num_nops = random.randint(1, 10)
    return ["nop"] * num_nops


def _generate_x86_medium(bits: int) -> list[str]:
    """
    Generate medium complexity x86 dead code.

    Generates register-preserving instruction sequences that don't
    affect program state. All templates use push/pop pairs or
    self-canceling operations to preserve register values.
    """
    if bits == 64:
        regs = ["rax", "rbx", "rcx", "rdx"]
    else:
        regs = ["eax", "ebx", "ecx", "edx"]

    reg = random.choice(regs)

    templates = [
        # Push/pop with arithmetic in between (register preserved)
        [
            f"push {reg}",
            f"mov {reg}, 12345",
            f"add {reg}, 67890",
            f"xor {reg}, {reg}",
            f"pop {reg}",
        ],
        # Push/pop with NOPs
        [
            f"push {reg}",
            f"mov {reg}, 0",
            "nop",
            "nop",
            f"pop {reg}",
        ],
        # Self-XOR pattern (always results in zero, then restore)
        [
            f"push {reg}",
            f"xor {reg}, {reg}",
            f"add {reg}, 0x41",
            f"sub {reg}, 0x41",
            f"pop {reg}",
        ],
        # Multiple register operations
        [
            f"push {reg}",
            f"not {reg}",
            f"not {reg}",
            f"pop {reg}",
        ],
        # Shift operations that cancel out
        [
            f"push {reg}",
            f"shl {reg}, 2",
            f"shr {reg}, 2",
            f"pop {reg}",
        ],
        # Simple NOP sled with some variety
        [
            "nop",
            f"xchg {reg}, {reg}",
            "nop",
            f"lea {reg}, [{reg}]",
            "nop",
        ],
    ]

    return random.choice(templates)


def _generate_x86_complex(bits: int) -> list[str]:
    """
    Generate complex x86 dead code (multiple operations, arithmetic chains).

    Note: Loop and branch constructs with labels are not supported
    by radare2's inline assembler, so we use longer instruction
    sequences instead.
    """
    if bits == 64:
        regs = ["rax", "rbx", "rcx", "rdx"]
    else:
        regs = ["eax", "ebx", "ecx", "edx"]

    reg_a = random.choice(regs)
    reg_b = random.choice([r for r in regs if r != reg_a])

    templates = [
        # Complex arithmetic chain (register preserved)
        [
            f"push {reg_a}",
            f"mov {reg_a}, 12345",
            f"add {reg_a}, 67890",
            f"sub {reg_a}, 12345",
            f"xor {reg_a}, 0xDEAD",
            f"xor {reg_a}, 0xDEAD",
            f"pop {reg_a}",
        ],
        # Two-register dance (both preserved)
        [
            f"push {reg_a}",
            f"push {reg_b}",
            f"xchg {reg_a}, {reg_b}",
            f"xchg {reg_a}, {reg_b}",
            f"pop {reg_b}",
            f"pop {reg_a}",
        ],
        # Multiplication and division (preserved)
        [
            f"push {reg_a}",
            f"mov {reg_a}, 42",
            f"add {reg_a}, {reg_a}",
            f"add {reg_a}, {reg_a}",
            f"sub {reg_a}, {reg_a}",
            f"pop {reg_a}",
        ],
        # Bitwise operations chain
        [
            f"push {reg_a}",
            f"not {reg_a}",
            f"not {reg_a}",
            f"neg {reg_a}",
            f"neg {reg_a}",
            f"pop {reg_a}",
        ],
        # Mixed operations
        [
            f"push {reg_a}",
            f"push {reg_b}",
            f"mov {reg_a}, 0x1234",
            f"mov {reg_b}, 0x5678",
            f"add {reg_a}, {reg_b}",
            f"sub {reg_a}, {reg_b}",
            f"pop {reg_b}",
            f"pop {reg_a}",
        ],
        # Long NOP equivalent sequence with variety
        [
            "nop",
            f"push {reg_a}",
            f"xor {reg_a}, {reg_a}",
            f"pop {reg_a}",
            "nop",
            f"lea {reg_a}, [{reg_a}]",
            "nop",
            f"xchg {reg_a}, {reg_a}",
        ],
    ]

    return random.choice(templates)


def generate_arm_dead_code(bits: int = 32, complexity: str = "medium") -> list[str]:
    """
    Generate dead code instructions for ARM.

    Args:
        bits: Bit width (32 or 64)
        complexity: Complexity level ("simple", "medium", or "complex")

    Returns:
        List of assembly instructions
    """
    if complexity == "simple":
        return ["nop"] * random.randint(1, 5)
    elif complexity == "complex":
        return _generate_arm_complex(bits)
    else:
        return _generate_arm_medium(bits)


def _generate_arm_medium(bits: int) -> list[str]:
    """Generate medium complexity ARM dead code."""
    if bits == 64:
        regs = ["x0", "x1", "x2", "x3"]
    else:
        regs = ["r0", "r1", "r2", "r3"]

    reg = random.choice(regs)

    templates = [
        # ARM register operations
        [
            f"mov {reg}, #123",
            f"add {reg}, {reg}, #456",
            f"eor {reg}, {reg}, {reg}",
        ],
        # Self-canceling operations
        [
            f"add {reg}, {reg}, #1",
            f"sub {reg}, {reg}, #1",
            "nop",
        ],
    ]

    return random.choice(templates)


def _generate_arm_complex(bits: int) -> list[str]:
    """Generate complex ARM dead code."""
    if bits == 64:
        regs = ["x0", "x1", "x2", "x3"]
    else:
        regs = ["r0", "r1", "r2", "r3"]

    reg = random.choice(regs)
    reg2 = random.choice([r for r in regs if r != reg])

    templates = [
        # Arithmetic chain
        [
            f"mov {reg}, #123",
            f"add {reg}, {reg}, #456",
            f"sub {reg}, {reg}, #456",
            f"sub {reg}, {reg}, #123",
        ],
        # Two-register operations
        [
            f"mov {reg}, {reg2}",
            f"mov {reg2}, {reg}",
            f"eor {reg}, {reg}, {reg}",
        ],
    ]

    return random.choice(templates)


def generate_nop_sequence(arch: str, bits: int, size: int) -> bytes:
    """
    Generate architecture-appropriate NOP sequence.

    Args:
        arch: Architecture ("x86", "arm", etc.)
        bits: Bit width (32 or 64)
        size: Number of bytes to generate

    Returns:
        NOP bytes of the specified size
    """
    if "x86" in arch.lower():
        # x86/x64: single-byte NOP is 0x90
        return b"\x90" * size
    elif "arm" in arch.lower():
        if bits == 64:
            # AArch64: NOP is 0xD503201F (4 bytes, little-endian)
            nop = b"\x1f\x20\x03\xd5"
        else:
            # ARM32: NOP is 0xE320F000 (4 bytes) or 0x00F020E3 little-endian
            nop = b"\x00\xf0\x20\xe3"
        num_nops = size // 4
        return nop * num_nops + b"\x00" * (size % 4)
    else:
        # Generic fallback: zero bytes
        return b"\x00" * size


def generate_register_preserving_sequence(arch: str, bits: int) -> list[str]:
    """
    Generate push/pop sequences that preserve registers.

    These sequences can be used to wrap other code to ensure
    register state is preserved.

    Args:
        arch: Architecture ("x86", "arm", etc.)
        bits: Bit width (32 or 64)

    Returns:
        List of assembly instructions forming a register-preserving wrapper
    """
    if "x86" in arch.lower():
        if bits == 64:
            regs = ["rax", "rbx", "rcx", "rdx"]
        else:
            regs = ["eax", "ebx", "ecx", "edx"]

        reg = random.choice(regs)

        templates = [
            # Simple push/pop
            [f"push {reg}", f"pop {reg}"],
            # Push/pop with nop
            [f"push {reg}", "nop", f"pop {reg}"],
            # Push/pop with self-canceling op
            [f"push {reg}", f"xor {reg}, {reg}", f"pop {reg}"],
        ]

        return random.choice(templates)

    elif "arm" in arch.lower():
        if bits == 64:
            reg = random.choice(["x9", "x10", "x11"])
            # AArch64 uses str/ldr with stack
            return [
                f"str {reg}, [sp, #-16]!",
                f"ldr {reg}, [sp], #16",
            ]
        else:
            reg = random.choice(["r4", "r5", "r6"])
            return [
                f"push {{{reg}}}",
                f"pop {{{reg}}}",
            ]

    return ["nop"]


def generate_x86_dead_code_for_size(max_size: int, bits: int) -> list[str]:
    """
    Generate x86 dead code that fits within a size constraint.

    This is useful for filling NOP sleds or padding with more
    complex dead code sequences.

    Args:
        max_size: Maximum bytes available
        bits: 32 or 64 bit mode

    Returns:
        List of assembly instructions
    """
    if bits == 64:
        reg = random.choice(["rax", "rbx", "rcx", "rdx"])
    else:
        reg = random.choice(["eax", "ebx", "ecx", "edx"])

    # Different complexity levels based on available space
    if max_size >= 15:
        # Full sequence with push/pop preservation
        return [
            f"push {reg}",
            f"mov {reg}, 0x41424344",
            f"xor {reg}, 0x41424344",  # Result is 0
            f"test {reg}, {reg}",       # ZF = 1 (opaque predicate)
            f"pop {reg}",
        ]
    elif max_size >= 8:
        # Medium sequence
        return [
            f"push {reg}",
            f"xor {reg}, {reg}",
            f"pop {reg}",
        ]
    elif max_size >= 5:
        # Small sequence
        return [
            f"push {reg}",
            f"pop {reg}",
            "nop",
        ]
    else:
        # Very small - just NOPs
        return ["nop"] * max_size


def generate_arm_dead_code_for_size(max_size: int, bits: int) -> list[str]:
    """
    Generate ARM dead code that fits within a size constraint.

    Args:
        max_size: Maximum bytes available
        bits: 32 or 64 bit mode

    Returns:
        List of assembly instructions
    """
    if bits == 64:
        reg = random.choice(["x9", "x10", "x11"])
    else:
        reg = random.choice(["r4", "r5", "r6"])

    if max_size >= 12:
        return [
            f"mov {reg}, #0x42",
            f"eor {reg}, {reg}, #0x42",  # Result is 0
            f"cmp {reg}, #0",             # Always equal (ZF=1)
        ]
    elif max_size >= 8:
        return [
            f"eor {reg}, {reg}, {reg}",
            "nop",
        ]
    else:
        return ["nop"]


def generate_dead_code_for_arch(
    arch: str, bits: int, complexity: str = "medium"
) -> list[str]:
    """
    Generate dead code for the specified architecture.

    This is a convenience function that dispatches to the appropriate
    architecture-specific generator.

    Args:
        arch: Architecture family ("x86", "arm", etc.)
        bits: Bit width (32 or 64)
        complexity: Complexity level ("simple", "medium", or "complex")

    Returns:
        List of assembly instructions
    """
    if "x86" in arch.lower():
        return generate_x86_dead_code(bits, complexity)
    elif "arm" in arch.lower():
        return generate_arm_dead_code(bits, complexity)
    else:
        # Fallback to NOPs
        return ["nop"] * random.randint(1, 5)
