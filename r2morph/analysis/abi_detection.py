"""ABI detection helpers."""

from __future__ import annotations

from r2morph.analysis.abi_models import ABI_SPECS, ABISpec, ABIType
from r2morph.core.binary import Binary
from r2morph.core.constants import ARCH_BITS_64


def detect_abi(binary: Binary) -> ABISpec:
    """Detect the ABI for a binary."""
    arch_info = binary.get_arch_info()
    arch = arch_info.get("arch", "").lower()
    bits = arch_info.get("bits", 64)
    platform = arch_info.get("platform", "").lower()

    abi_key = None
    if "arm" in arch or "aarch" in arch:
        abi_key = "arm64_aapcs" if bits == ARCH_BITS_64 else "arm32_aapcs"
    elif "x86" in arch or "8086" in arch or "amd" in arch or arch == "intel":
        if bits == ARCH_BITS_64:
            abi_key = "x86_64_windows" if "windows" in platform or "pe" in platform else "x86_64_sysv"
        else:
            abi_key = "x86_32_windows" if "windows" in platform or "pe" in platform else "x86_32_linux"

    if abi_key is not None:
        return ABI_SPECS[abi_key]

    return ABISpec(
        abi_type=ABIType.UNKNOWN,
        stack_alignment=16,
        red_zone_size=0,
        shadow_space_size=0,
        callee_saved_regs=[],
        param_regs=[],
        return_regs=[],
    )
