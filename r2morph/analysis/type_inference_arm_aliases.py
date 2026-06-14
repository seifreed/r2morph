"""ARM register alias helpers for type inference."""

from __future__ import annotations

from typing import Any


def get_arm_register_aliases(arch: str, bits: int) -> dict[str, list[str]]:
    """Get ARM register alias mappings."""
    aliases: dict[str, list[str]] = {}

    if arch in ("arm64", "aarch64"):
        for i in range(32):
            aliases[f"x{i}"] = [f"w{i}", f"x{i}"]
            aliases[f"w{i}"] = [f"w{i}", f"x{i}"]

        aliases["x29"] = ["fp", "x29"]
        aliases["x30"] = ["lr", "x30"]
        aliases["sp"] = ["sp", "x31"]

        for i in range(32):
            aliases[f"v{i}.d"] = [f"d{i}", f"v{i}"]
            aliases[f"v{i}.s"] = [f"s{2 * i}", f"v{i}"]
            aliases[f"v{i}.b"] = [f"b{4 * i}", f"v{i}"]

    elif arch in ("arm", "arm32"):
        for i in range(16):
            aliases[f"r{i}"] = [f"r{i}"]

        aliases["fp"] = ["r11", "fp"]
        aliases["ip"] = ["r12", "ip"]
        aliases["sp"] = ["r13", "sp"]
        aliases["lr"] = ["r14", "lr"]
        aliases["pc"] = ["r15", "pc"]

        aliases["s0"] = ["s0", "d0_lower"]
        aliases["d0"] = ["d0", "s0", "s1"]

    return aliases


def propagate_arm_aliases(register_types: dict[str, Any], aliases: dict[str, list[str]]) -> None:
    """Propagate type information through register aliases."""
    for primary_reg, alias_list in aliases.items():
        if primary_reg in register_types:
            type_info = register_types[primary_reg]
            for alias in alias_list:
                if alias not in register_types:
                    register_types[alias] = type_info

    for primary_reg, alias_list in aliases.items():
        if primary_reg not in register_types:
            for alias in alias_list:
                if alias in register_types:
                    register_types[primary_reg] = register_types[alias]
                    break


__all__ = ["get_arm_register_aliases", "propagate_arm_aliases"]
