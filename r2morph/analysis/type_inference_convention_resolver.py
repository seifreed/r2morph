"""Calling-convention selection helpers for type inference."""

from __future__ import annotations

import copy
from typing import Any

from r2morph.analysis.type_inference_conventions import (
    _AAPCS64_ARM64_CONVENTION,
    _AAPCS_ARM32_CONVENTION,
    _CDECL_X86_32_CONVENTION,
    _EMPTY_CONVENTION,
    _SYSV_AMD64_CONVENTION,
)


def get_calling_convention(arch: str, bits: int) -> dict[str, Any]:
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


__all__ = ["get_calling_convention"]
