"""Pure parsing helpers for call graph construction."""

from __future__ import annotations

from r2morph.analysis.call_graph import CallType


def determine_call_type(name: str) -> CallType:
    """Determine the type of a function name."""
    if name.startswith("sym.imp."):
        return CallType.PLT
    if name.startswith("sub."):
        return CallType.DIRECT
    if "." in name and not name.startswith("sub."):
        return CallType.LIBRARY
    return CallType.DIRECT


def extract_call_target(disasm: str) -> int | str | None:
    """Extract call target from disassembly."""
    parts = disasm.split(None, 1)
    if len(parts) < 2:
        return None

    operand = parts[1].strip()

    if operand.startswith("0x"):
        try:
            return int(operand, 16)
        except ValueError:
            pass

    if operand.startswith("[") and operand.endswith("]"):
        return f"indirect:{operand}"

    if operand.startswith("dword [") or operand.startswith("qword ["):
        return f"indirect:{operand}"

    if operand in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"):
        return f"indirect:{operand}"

    return operand


def is_tail_call(disasm: str) -> bool:
    """Check whether an instruction is a tail call."""
    if not disasm.startswith("jmp"):
        return False
    parts = disasm.split(None, 1)
    if len(parts) < 2:
        return False
    operand = parts[1].strip()
    return operand.startswith("0x") or operand in ("rax", "rbx", "rcx", "rdx")
