"""Query helpers for type inference results."""

from __future__ import annotations

from typing import Any

from r2morph.analysis.type_inference_types import PrimitiveType, StructField
from r2morph.core.binary import Binary


def get_struct_layout(factory: Any, binary: Binary, address: int) -> list[Any] | None:
    """Infer struct layout from access patterns."""

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
    return factory.create_primitive_type(PrimitiveType.UINT64)
