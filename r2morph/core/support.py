"""
Official support matrix for the mutation engine product.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class SupportMatrix:
    """Machine-readable support matrix for the product."""

    stable_formats: tuple[str, ...] = ("ELF",)
    stable_architectures: tuple[str, ...] = ("x86_64",)
    prolonged_experimental_formats: tuple[str, ...] = ("Mach-O", "PE")
    prolonged_experimental_architectures: tuple[str, ...] = ("arm64", "arm32", "x86")
    stable_mutations: tuple[str, ...] = ("nop", "substitute", "register")
    experimental_mutations: tuple[str, ...] = ("expand", "block")
    stable_validators: tuple[str, ...] = ("structural", "runtime")
    experimental_validators: tuple[str, ...] = ("symbolic",)
    notes: dict[str, Any] = field(
        default_factory=lambda: {
            "primary_product": "metamorphic mutation engine with validation",
            "stable_target": {
                "format": "ELF",
                "architecture": "x86_64",
            },
            "secondary_cli_namespace": "experimental",
            "experimental_areas": [
                "enhanced analysis",
                "devirtualization",
                "anti-analysis",
                "instrumentation",
            ],
            "prolonged_experimental_areas": [
                "cross-format rewriting outside ELF",
                "non-x86_64 production support (arm64, arm32, x86_32)",
                "semantic validation beyond bounded symbolic scope",
            ],
            "architecture_support": {
                "x86_64": {"status": "stable", "passes": ["nop", "substitute", "register"]},
                "x86": {"status": "experimental", "passes": ["nop"]},
                "arm64": {"status": "experimental", "passes": ["nop"]},
                "arm32": {"status": "experimental", "passes": ["nop"]},
            },
        }
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict."""
        return asdict(self)


PRODUCT_SUPPORT = SupportMatrix()


def _normalize_architecture_name(architecture: str, bits: int | None = None) -> str:
    """Normalize architecture labels emitted by analysis backends."""
    normalized_arch = str(architecture).strip()
    lowered = normalized_arch.lower()
    if lowered in {"x86_64", "x86-64", "amd64", "x64"}:
        return "x86_64"
    if lowered == "x86" and bits == 64:
        return "x86_64"
    if lowered in {"x86", "i386", "i686"}:
        return "x86"
    if lowered in {"arm64", "aarch64", "arm64e"}:
        return "arm64"
    if lowered in {"arm", "armv7", "armv7l", "armv7a", "thumb"}:
        return "arm"
    return normalized_arch


def classify_target_support(
    binary_format: str,
    architecture: str,
    bits: int | None = None,
) -> dict[str, Any]:
    """Classify a binary target against the current product support envelope."""
    normalized_format = str(binary_format).strip()
    normalized_arch = _normalize_architecture_name(architecture, bits)
    stable = (
        normalized_format in PRODUCT_SUPPORT.stable_formats and normalized_arch in PRODUCT_SUPPORT.stable_architectures
    )
    prolonged_experimental = (
        normalized_format in PRODUCT_SUPPORT.prolonged_experimental_formats
        or normalized_arch in PRODUCT_SUPPORT.prolonged_experimental_architectures
    )
    if stable:
        tier = "stable"
        reason = "inside primary supported mutation target"
    elif prolonged_experimental:
        tier = "prolonged-experimental"
        reason = "visible in repo/tests but outside the stable product envelope"
    else:
        tier = "unsupported"
        reason = "outside stable and prolonged experimental target sets"
    return {
        "format": normalized_format,
        "architecture": normalized_arch,
        "tier": tier,
        "reason": reason,
        "stable_target": dict(PRODUCT_SUPPORT.notes.get("stable_target", {})),
        "secondary_cli_namespace": PRODUCT_SUPPORT.notes.get("secondary_cli_namespace"),
        "prolonged_experimental_areas": list(PRODUCT_SUPPORT.notes.get("prolonged_experimental_areas", [])),
    }


def is_stable_mutation(name: str) -> bool:
    """Return whether a mutation name is part of the stable core."""
    return name in PRODUCT_SUPPORT.stable_mutations


def is_experimental_mutation(name: str) -> bool:
    """Return whether a mutation name is marked experimental."""
    return name in PRODUCT_SUPPORT.experimental_mutations
