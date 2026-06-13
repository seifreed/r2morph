"""Query helpers for type inference results."""

from __future__ import annotations

from typing import Any

from r2morph.core.binary import Binary


def get_struct_layout(factory: Any, binary: Binary, address: int) -> list[Any] | None:
    """Infer struct layout from access patterns."""
    from r2morph.analysis.type_inference import StructField

    fields: list[Any] = []

    try:
        xrefs = binary.r2.cmdj(f"axtj @ {address}") if binary.r2 else []
    except Exception:
        xrefs = []

    if not xrefs:
        return None

    for xref in xrefs:
        offset = xref.get("offset", 0) if isinstance(xref, dict) else 0
        access_type = infer_access_type(factory, binary, xref if isinstance(xref, dict) else {})

        if access_type:
            fields.append(
                StructField(
                    name=f"field_{offset:x}",
                    offset=offset,
                    type_info=access_type,
                )
            )

    fields.sort(key=lambda f: f.offset)
    return fields if fields else None


def infer_access_type(factory: Any, binary: Binary, xref: dict) -> Any | None:
    """Infer the type of a memory access."""
    from r2morph.analysis.type_inference import PrimitiveType

    return factory.create_primitive_type(PrimitiveType.UINT64)


def get_value_range(type_info: Any) -> tuple[int, int] | None:
    """Return the numeric value range for an integer type."""
    if not type_info.is_integer():
        return None

    size = type_info.size
    if size == 1:
        return (0, 255)
    if size == 2:
        return (0, 65535)
    if size == 4:
        return (0, 2**32 - 1)
    if size == 8:
        return (0, 2**64 - 1)
    return None


def is_safe_to_mutate(type_info: Any, mutation_type: str) -> tuple[bool, str]:
    """Check whether a mutation is safe for a value type."""
    if mutation_type == "register_substitution" and type_info.is_pointer():
        return (False, "Register holds pointer - unsafe to substitute")

    if mutation_type == "instruction_expansion" and type_info.is_pointer():
        return (False, "Pointer arithmetic - expansion may break semantics")

    return (True, "Safe to mutate")
