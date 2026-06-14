"""ABI detection helpers."""

from __future__ import annotations

from r2morph.analysis.abi_models import ABI_SPECS, ABISpec, ABIType
from r2morph.core.binary import Binary


def detect_abi(binary: Binary) -> ABISpec:
    """Detect the ABI for a binary."""
    arch_info = binary.get_arch_info()
    arch = arch_info.get("arch", "").lower()
    bits = arch_info.get("bits", 64)
    platform = arch_info.get("platform", "").lower()

    if "arm" in arch or "aarch" in arch:
        if bits == 64:
            return ABI_SPECS["arm64_aapcs"]
        return ABI_SPECS["arm32_aapcs"]

    if "x86" in arch or "8086" in arch or "amd" in arch or arch == "intel":
        if bits == 64:
            if "windows" in platform or "pe" in platform:
                return ABI_SPECS["x86_64_windows"]
            return ABI_SPECS["x86_64_sysv"]
        if "windows" in platform or "pe" in platform:
            return ABI_SPECS["x86_32_windows"]
        return ABI_SPECS["x86_32_linux"]

    return ABISpec(
        abi_type=ABIType.UNKNOWN,
        stack_alignment=16,
        red_zone_size=0,
        shadow_space_size=0,
        callee_saved_regs=[],
        param_regs=[],
        return_regs=[],
    )
