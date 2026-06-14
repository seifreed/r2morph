"""Function-parameter inference helpers for type inference."""

from __future__ import annotations

import logging
from typing import Any

from r2morph.analysis.type_inference_types import PrimitiveType, TypeInfo
from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


def infer_function_params(
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


def infer_all_function_param_types(
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
                param_types = infer_function_params(factory, binary, func_addr, disasm, calling_convention)
        except Exception as e:
            logger.debug(f"Failed to infer params for {func_name}: {e}")

        function_types[func_addr] = param_types

    return function_types


def propagate_interprocedural_params(
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


__all__ = [
    "infer_function_params",
    "infer_all_function_param_types",
    "propagate_interprocedural_params",
]
