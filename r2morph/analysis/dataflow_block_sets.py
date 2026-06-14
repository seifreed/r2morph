"""Block-level register set helpers for dataflow analysis."""

from __future__ import annotations

from r2morph.analysis.dataflow_parsing import extract_registers_from_operand


def compute_block_use(instructions: list[dict]) -> set[tuple[str, int]]:
    """Compute registers used before being defined in a block."""
    used: set[tuple[str, int]] = set()
    defined: set[tuple[str, int]] = set()

    for insn in instructions:
        regs_used = _extract_used_registers(insn)
        for reg in regs_used:
            if reg not in defined:
                used.add(reg)

        regs_defined = _extract_defined_registers(insn)
        defined.update(regs_defined)

    return used


def compute_block_def(instructions: list[dict]) -> set[tuple[str, int]]:
    """Compute registers defined in a block."""
    defined: set[tuple[str, int]] = set()

    for insn in instructions:
        defined.update(_extract_defined_registers(insn))

    return defined


def _extract_used_registers(insn: dict) -> set[tuple[str, int]]:
    """Extract registers used by an instruction."""
    used: set[tuple[str, int]] = set()
    disasm = insn.get("disasm", "").lower()

    if not disasm:
        return used

    operand_parts = disasm.split(None, 1)
    if len(operand_parts) < 2:
        return used

    operands = operand_parts[1]
    if "," in operands:
        src_parts = operands.split(",")
        if len(src_parts) >= 2:
            src = src_parts[1].strip()
            used.update(extract_registers_from_operand(src))

    for reg in extract_registers_from_operand(operands):
        if "(" in operands and ")" in operands:
            used.add(reg)

    return used


def _extract_defined_registers(insn: dict) -> set[tuple[str, int]]:
    """Extract registers defined by an instruction."""
    defined: set[tuple[str, int]] = set()
    disasm = insn.get("disasm", "").lower()
    mnemonic = insn.get("type", "").lower()

    if not disasm:
        return defined

    if mnemonic in ("jmp", "ret", "call", "nop"):
        return defined

    operand_parts = disasm.split(None, 1)
    if len(operand_parts) < 2:
        return defined

    operands = operand_parts[1]
    if "," in operands:
        dest = operands.split(",")[0].strip()

        if "[" in dest:
            return defined

        defined.update(extract_registers_from_operand(dest))

    return defined
