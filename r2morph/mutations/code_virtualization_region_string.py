"""Decode and emit implicit-memory x86 string instructions."""

from __future__ import annotations

import re
from typing import Any

_PREFIXES = frozenset({"rep", "repe", "repne"})
_WIDTHS = {"b": 8, "w": 16, "d": 32, "q": 64}
_VECTOR_REGISTER = re.compile(r"(?:xmm|ymm|zmm)\d+", re.IGNORECASE)
_TWO_PARTS = 2
_DIRECTION_FLAG = 1 << 10


def decode_string_instruction(text: str) -> list[Any] | None:
    """Return a VM item for a supported implicit-memory string instruction."""
    parts = text.strip().lower().split(None, 1)
    if not parts:
        return None
    prefix = "none"
    mnemonic = parts[0]
    if mnemonic in _PREFIXES:
        prefix = mnemonic
        remainder = parts[1] if len(parts) == _TWO_PARTS else ""
        mnemonic = remainder.split(None, 1)[0] if remainder else ""
    match = re.fullmatch(r"(movs|stos|lods|scas|cmps)([bwdq])", mnemonic)
    if match is None or (len(parts) == _TWO_PARTS and _VECTOR_REGISTER.search(parts[1])):
        return None
    operation, suffix = match.groups()
    if operation in {"movs", "stos", "lods"} and prefix == "repne":
        return None
    if operation in {"cmps", "scas"} and prefix == "rep":
        prefix = "repe"
    return ["string", operation, _WIDTHS[suffix], prefix]


def _string_width_suffix(width: int) -> str:
    suffixes = {8: "b", 16: "w", 32: "d", 64: "q"}
    try:
        return suffixes[width]
    except KeyError as error:
        raise ValueError(f"unsupported string width: {width}") from error


def string_handler_asm(handler_key: str, slot: tuple[int, ...], flags_offset: int) -> str:
    """Render a handler using the guest's implicit string registers."""
    _, operation, width_text, prefix = handler_key.split("_")
    width = int(width_text)
    suffix = _string_width_suffix(width)
    instruction = f"{'' if prefix == 'none' else prefix + ' '}{operation}{suffix}"
    rax_slot = slot[0] * 8
    rcx_slot = slot[1] * 8
    rsi_slot = slot[6] * 8
    rdi_slot = slot[7] * 8
    lines = [
        "  mov r10, rsi\n",
        f"  mov rsi, qword ptr [rsp+{rsi_slot}]\n",
        f"  mov rdi, qword ptr [rsp+{rdi_slot}]\n",
    ]
    repeated = prefix != "none"
    if repeated:
        lines.append(f"  mov rcx, qword ptr [rsp+{rcx_slot}]\n")
    if operation in {"stos", "lods", "scas"}:
        lines.append(f"  mov rax, qword ptr [rsp+{rax_slot}]\n")
    lines.extend(
        [
            f"  push qword ptr [rsp+{flags_offset}]\n",
            "  popfq\n",
            f"  {instruction}\n",
        ]
    )
    if operation in {"cmps", "scas"}:
        lines.extend(["  pushfq\n", f"  pop qword ptr [rsp+{flags_offset}]\n"])
    lines.extend(
        [
            f"  mov qword ptr [rsp+{rsi_slot}], rsi\n",
            f"  mov qword ptr [rsp+{rdi_slot}], rdi\n",
        ]
    )
    if repeated:
        lines.append(f"  mov qword ptr [rsp+{rcx_slot}], rcx\n")
    if operation == "lods":
        lines.append(f"  mov qword ptr [rsp+{rax_slot}], rax\n")
    lines.extend(["  mov rsi, r10\n", "  add rsi, 1\n", "  jmp vm_dispatch\n"])
    return "".join(lines)


def direction_control_handler_asm(mnemonic: str, flags_offset: int) -> str:
    """Update the virtual direction flag without exposing a native flag op."""
    operation = {"cld": f"and r10, -{_DIRECTION_FLAG + 1}", "std": f"or r10, {_DIRECTION_FLAG}"}.get(mnemonic)
    if operation is None:
        raise ValueError(f"unsupported direction-control mnemonic: {mnemonic}")
    return (
        f"  mov r10, qword ptr [rsp+{flags_offset}]\n"
        f"  {operation}\n"
        f"  mov qword ptr [rsp+{flags_offset}], r10\n"
        "  add rsi, 1\n  jmp vm_dispatch\n"
    )
