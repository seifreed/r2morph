"""Interprocedural helpers for type inference."""

from __future__ import annotations

import copy
import logging
from typing import Any

from r2morph.analysis.type_inference_types import (
    _AAPCS64_ARM64_CONVENTION,
    _AAPCS_ARM32_CONVENTION,
    _CDECL_X86_32_CONVENTION,
    _EMPTY_CONVENTION,
    _SYSV_AMD64_CONVENTION,
    PrimitiveType,
    TypeInfo,
)
from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


def _get_calling_convention(arch: str, bits: int) -> dict[str, Any]:
    """Get calling convention registers for architecture."""
    if arch in ("x86", "amd64", "x86_64"):
        convention = _SYSV_AMD64_CONVENTION if bits == 64 else _CDECL_X86_32_CONVENTION
    elif arch in ("arm", "arm32"):
        convention = _AAPCS_ARM32_CONVENTION
    elif arch in ("arm64", "aarch64"):
        convention = _AAPCS64_ARM64_CONVENTION
    else:
        convention = _EMPTY_CONVENTION
    return copy.deepcopy(convention)


def _infer_function_params(
    factory: Any,
    binary: Binary,
    func_addr: int,
    disasm: list[dict],
    calling_conv: dict[str, Any],
) -> dict[str, TypeInfo]:
    """Infer function parameter types from disassembly."""
    param_types: dict[str, TypeInfo] = {}
    param_regs = calling_conv.get("param_registers", [])

    for insn in disasm[:20]:
        disasm_str = insn.get("disasm", "").lower()

        for i, reg in enumerate(param_regs):
            reg_lower = reg.lower()
            if reg_lower in disasm_str:
                if "mov" in disasm_str and "mem" not in disasm_str:
                    param_types[f"param_{i}"] = factory.create_primitive_type(PrimitiveType.INT64)
                elif "ldr" in disasm_str or "mov" in disasm_str:
                    param_types[f"param_{i}"] = factory.create_pointer_type()

    return param_types


def _infer_all_function_param_types(
    factory: Any,
    binary: Binary,
    calling_convention: dict[str, Any],
) -> dict[int, dict[str, TypeInfo]]:
    """Infer parameter types for every function."""
    function_types: dict[int, dict[str, TypeInfo]] = {}

    for func in binary.get_functions():
        func_addr = func.get("offset", func.get("addr", 0))
        func_name = func.get("name", f"func_{func_addr:x}")

        param_types: dict[str, TypeInfo] = {}
        try:
            disasm = binary.get_function_disasm(func_addr)
            if disasm:
                param_types = _infer_function_params(factory, binary, func_addr, disasm, calling_convention)
        except Exception as e:
            logger.debug(f"Failed to infer params for {func_name}: {e}")

        function_types[func_addr] = param_types

    return function_types


def _propagate_through_calls(
    factory: Any,
    binary: Binary,
    call_graph: dict[int, list[int]],
    function_types: dict[int, dict[str, TypeInfo]],
    calling_conv: dict[str, Any],
) -> None:
    """Propagate type information through call graph edges."""
    calling_conv.get("return_register", "")

    for caller_addr, callees in call_graph.items():
        caller_types = function_types.get(caller_addr, {})

        for callee_addr in callees:
            callee_types = function_types.get(callee_addr, {})

            for param_name, param_type in callee_types.items():
                if param_name not in caller_types:
                    caller_types[param_name] = param_type

    for func_addr, types in function_types.items():
        factory._address_types.update({func_addr + i: t for i, (n, t) in enumerate(types.items())})


def propagate_interprocedural_types(
    factory: Any,
    binary: Binary,
    call_graph: dict[int, list[int]] | None = None,
) -> dict[int, dict[str, TypeInfo]]:
    """Propagate types across function boundaries using call graph."""
    arch_info = binary.get_arch_info()
    arch = arch_info.get("arch", "x86").lower()
    bits = arch_info.get("bits", 64)
    calling_convention = _get_calling_convention(arch, bits)

    function_types = _infer_all_function_param_types(factory, binary, calling_convention)

    if call_graph:
        _propagate_through_calls(factory, binary, call_graph, function_types, calling_convention)

    return function_types
