"""Pure helpers for semantic invariant checking."""

from __future__ import annotations


def normalize_architecture(arch: str, bits: int) -> str:
    """Normalize a reported architecture string to the checker family."""
    if "x86" in arch or arch == "x86_64":
        return "x86_64" if bits == 64 else "x86"
    if "arm" in arch:
        return "arm64" if bits == 64 else "arm"
    return arch


def compute_stack_delta_for_bytes(code_bytes: bytes, arch: str, word_size: int) -> int:
    """Compute net stack delta from raw instruction bytes."""
    delta = 0

    push_opcodes = {
        "x86": [b"\x50", b"\x51", b"\x52", b"\x53", b"\x54", b"\x55", b"\x56", b"\x57"],
        "x86_64": [b"\x50", b"\x51", b"\x52", b"\x53", b"\x54", b"\x55", b"\x56", b"\x57"],
    }
    pop_opcodes = {
        "x86": [b"\x58", b"\x59", b"\x5a", b"\x5b", b"\x5c", b"\x5d", b"\x5e", b"\x5f"],
        "x86_64": [b"\x58", b"\x59", b"\x5a", b"\x5b", b"\x5c", b"\x5d", b"\x5e", b"\x5f"],
    }

    if arch not in push_opcodes:
        return delta

    for i in range(len(code_bytes)):
        for push_op in push_opcodes.get(arch, []):
            if code_bytes[i : i + len(push_op)] == push_op:
                delta -= word_size
                break

        for pop_op in pop_opcodes.get(arch, []):
            if code_bytes[i : i + len(pop_op)] == pop_op:
                delta += word_size
                break

        if code_bytes[i : i + 2] == b"\x68":
            delta -= word_size
        elif code_bytes[i : i + 2] == b"\x8f":
            delta += word_size

    return delta
