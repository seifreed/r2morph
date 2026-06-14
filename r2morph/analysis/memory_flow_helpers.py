"""Pure helpers for memory flow stack-frame analysis."""

from __future__ import annotations

import re
from typing import Any


def record_saved_register(disasm: str, addr: int, frame_size: int, stack_frame: dict[str, Any]) -> int:
    """Record a push of a saved register; return the grown frame size."""
    match = re.search(r"push\s+(\w+)", disasm)
    if match:
        stack_frame["saved_regs"].append({"register": match.group(1), "offset": frame_size, "address": f"0x{addr:x}"})
        frame_size += 8
    return frame_size


def record_stack_allocation(disasm: str, addr: int, frame_size: int, stack_frame: dict[str, Any]) -> int:
    """Record a sub sp stack allocation; return the grown frame size."""
    match = re.search(r"sub\s+sp,\s+#?(\d+)", disasm)
    if match:
        size = int(match.group(1))
        frame_size += size
        stack_frame["allocations"].append({"size": size, "address": f"0x{addr:x}"})
    return frame_size


def record_stack_local(disasm: str, addr: int, local_vars: dict[str, dict[str, Any]]) -> None:
    """Record a mov [sp/rbp-N], reg store as a local variable."""
    match = re.search(r"mov\s+\[.*?([+-]?\d+).*?\],\s+(\w+)", disasm)
    if not match:
        return

    offset = int(match.group(1))
    var_name = f"var_{abs(offset)}"
    if var_name not in local_vars:
        local_vars[var_name] = {
            "name": var_name,
            "offset": offset,
            "size": 4,
            "access_type": "write",
            "address": f"0x{addr:x}",
        }
