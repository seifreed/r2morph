"""Query helpers for dataflow analysis."""

from __future__ import annotations

from r2morph.analysis.cfg import ControlFlowGraph
from r2morph.analysis.dataflow_models import DataFlowResult, Definition, Register


def find_block_containing_address(cfg: ControlFlowGraph, address: int) -> int | None:
    """Find the block containing an address."""
    for block_addr, block in cfg.blocks.items():
        if block.address <= address < block.address + block.size:
            return block_addr
    return None


def get_value_at(cfg: ControlFlowGraph, result: DataFlowResult, address: int, register: Register) -> set[object]:
    """Get possible values for a register at an address."""
    values: set[object] = set()
    block_addr = find_block_containing_address(cfg, address)
    if block_addr is None:
        return values

    reaching = result.reaching_in.get(block_addr, set())
    for defn in reaching:
        if defn.register and defn.register.name == register.name and defn.value is not None:
            values.add(defn.value)
    return values


def is_safe_to_mutate(
    cfg: ControlFlowGraph,
    result: DataFlowResult,
    address: int,
    mutation_type: str,
) -> tuple[bool, str]:
    """Check if it's safe to apply a mutation at an address."""
    block_addr = find_block_containing_address(cfg, address)
    if block_addr is None:
        return (False, "Address not found in CFG")

    live_regs = result.live_in.get(block_addr, set())

    if mutation_type in ("register_swap", "register_substitution"):
        critical_regs = {"rsp", "rbp", "esp", "ebp"}
        for reg in live_regs:
            if reg.name.lower() in critical_regs:
                for alias in reg.aliases():
                    if alias.name.lower() in critical_regs:
                        return (False, f"Critical register {reg.name} is live")

    reaching = result.reaching_in.get(block_addr, set())
    if mutation_type == "instruction_expansion":
        for defn in reaching:
            if defn.register and is_address_calculation(defn):
                return (False, "Address calculation nearby - expansion may break pointer references")

    return (True, "Safe to mutate")


def is_address_calculation(defn: Definition) -> bool:
    """Check if a definition is part of address calculation."""
    if not defn.instruction:
        return False

    insn = defn.instruction.lower()

    if "lea" in insn:
        return True

    if "add" in insn and any(r in insn for r in ["rbp", "rsp", "ebp", "esp"]):
        return True

    if "sub" in insn and any(r in insn for r in ["rbp", "rsp", "ebp", "esp"]):
        return True

    return False
