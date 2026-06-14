"""Interprocedural helpers for type inference."""

from __future__ import annotations

from typing import Any

from r2morph.analysis.type_inference_convention_resolver import get_calling_convention
from r2morph.analysis.type_inference_interprocedural_params import (
    infer_all_function_param_types,
    infer_function_params,
    propagate_interprocedural_params,
)
from r2morph.analysis.type_inference_types import TypeInfo
from r2morph.core.binary import Binary


def propagate_interprocedural_types(
    factory: Any,
    binary: Binary,
    call_graph: dict[int, list[int]] | None = None,
) -> dict[int, dict[str, TypeInfo]]:
    """Propagate types across function boundaries using call graph."""
    arch_info = binary.get_arch_info()
    arch = arch_info.get("arch", "x86").lower()
    bits = arch_info.get("bits", 64)
    calling_convention = get_calling_convention(arch, bits)

    function_types = infer_all_function_param_types(factory, binary, calling_convention)

    if call_graph:
        propagate_interprocedural_params(factory, binary, call_graph, function_types, calling_convention)

    return function_types


__all__ = [
    "infer_function_params",
    "infer_all_function_param_types",
    "propagate_interprocedural_params",
    "propagate_interprocedural_types",
]
