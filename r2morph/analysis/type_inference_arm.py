"""ARM-specific helpers for type inference."""

from __future__ import annotations

import re
from typing import Any

from r2morph.analysis.type_inference_arm_aliases import (
    get_arm_register_aliases,
    propagate_arm_aliases,
)
from r2morph.core.binary import Binary


def infer_arm_register_types(
    factory: Any,
    binary: Binary,
    func_addr: int,
    disasm: list[dict],
    primitive_types: Any,
) -> dict[str, Any]:
    """Infer types for ARM registers in a function."""
    arch_info = binary.get_arch_info()
    arch = arch_info.get("arch", "arm").lower()
    bits = arch_info.get("bits", 32)

    register_types: dict[str, Any] = {}
    reg_aliases = get_arm_register_aliases(arch, bits)

    for insn in disasm:
        disasm_str = insn.get("disasm", "").lower()

        if arch in ("arm64", "aarch64"):
            infer_arm64_register_types(factory, disasm_str, register_types, primitive_types)
        elif arch in ("arm", "arm32"):
            infer_arm32_register_types(factory, disasm_str, register_types, primitive_types)

    propagate_arm_aliases(register_types, reg_aliases)

    return register_types


def infer_arm64_register_types(
    factory: Any,
    disasm_str: str,
    register_types: dict[str, Any],
    primitive_types: Any,
) -> None:
    """Infer types for ARM64 registers from instruction."""
    if "ldr" in disasm_str:
        match = re.search(r"ldr\s+(\w+)", disasm_str)
        if match:
            reg = match.group(1).lower()
            if reg.startswith("x") or reg.startswith("w"):
                register_types[reg] = factory.create_pointer_type()
            elif reg.startswith("d") or reg.startswith("s"):
                register_types[reg] = factory.create_primitive_type(primitive_types.FLOAT64)

    elif "str" in disasm_str:
        match = re.search(r"str\s+(\w+)", disasm_str)
        if match:
            reg = match.group(1).lower()
            if reg not in register_types:
                register_types[reg] = factory.create_primitive_type(primitive_types.UINT64)

    elif "mov" in disasm_str:
        match = re.search(r"mov\s+(\w+)\s*,\s*(\w+)", disasm_str)
        if match:
            dest, src = match.group(1).lower(), match.group(2).lower()
            if src.startswith("#"):
                register_types[dest] = factory.create_primitive_type(primitive_types.INT64)
            elif src in register_types:
                register_types[dest] = register_types[src]

    elif "fmov" in disasm_str:
        match = re.search(r"fmov\s+(\w+)", disasm_str)
        if match:
            reg = match.group(1).lower()
            register_types[reg] = factory.create_primitive_type(primitive_types.FLOAT64)

    elif "add" in disasm_str or "sub" in disasm_str:
        match = re.search(r"(add|sub)\s+(\w+)", disasm_str)
        if match:
            reg = match.group(2).lower()
            if reg not in register_types:
                register_types[reg] = factory.create_primitive_type(primitive_types.INT64)


def infer_arm32_register_types(
    factory: Any,
    disasm_str: str,
    register_types: dict[str, Any],
    primitive_types: Any,
) -> None:
    """Infer types for ARM32 registers from instruction."""
    if "ldr" in disasm_str:
        match = re.search(r"ldr\s+(\w+)", disasm_str)
        if match:
            reg = match.group(1).lower()
            if reg.startswith("r"):
                register_types[reg] = factory.create_pointer_type()
            elif reg.startswith("s"):
                register_types[reg] = factory.create_primitive_type(primitive_types.FLOAT32)
            elif reg.startswith("d"):
                register_types[reg] = factory.create_primitive_type(primitive_types.FLOAT64)

    elif "str" in disasm_str:
        match = re.search(r"str\s+(\w+)", disasm_str)
        if match:
            reg = match.group(1).lower()
            if reg not in register_types:
                register_types[reg] = factory.create_primitive_type(primitive_types.UINT32)

    elif "mov" in disasm_str:
        match = re.search(r"mov\s+(\w+)\s*,\s*(\w+)", disasm_str)
        if match:
            dest, src = match.group(1).lower(), match.group(2).lower()
            if src.startswith("#"):
                register_types[dest] = factory.create_primitive_type(primitive_types.INT32)
            elif src in register_types:
                register_types[dest] = register_types[src]
