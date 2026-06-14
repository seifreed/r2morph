"""
Data flow analysis engine for binary analysis.

Provides forward and backward data flow analysis including:
- Reaching definitions
- Liveness analysis
- Def-use chains
- Value set analysis
"""

from __future__ import annotations

import logging
from typing import Any

from r2morph.analysis.cfg import BasicBlock, ControlFlowGraph
from r2morph.analysis.dataflow_block_sets import compute_block_def, compute_block_use
from r2morph.analysis.dataflow_models import (
    DataFlowDirection as _DataFlowDirection,
)
from r2morph.analysis.dataflow_models import (
    DataFlowResult,
    Definition,
    DefUseChain,
    Register,
    Use,
)
from r2morph.analysis.dataflow_parsing import extract_registers_from_operand

DataFlowDirection = _DataFlowDirection

logger = logging.getLogger(__name__)


class DataFlowAnalyzer:
    """
    Core data flow analyzer.

    Performs forward and backward data flow analysis on CFG basic blocks.

    Usage:
        analyzer = DataFlowAnalyzer(cfg)
        result = analyzer.analyze()
        live_regs = result.get_live_registers(address)
    """

    def __init__(self, cfg: ControlFlowGraph):
        self.cfg = cfg
        self._result = DataFlowResult()

    def analyze(self) -> DataFlowResult:
        """
        Perform complete data flow analysis.

        Returns:
            DataFlowResult with liveness, reaching definitions, and def-use chains
        """
        self._compute_liveness()
        self._compute_reaching_definitions()
        self._build_def_use_chains()

        return self._result

    def _compute_liveness(self) -> None:
        """Compute liveness analysis (backward data flow)."""
        self._result.live_in.clear()
        self._result.live_out.clear()

        for addr in self.cfg.blocks:
            self._result.live_in[addr] = set()
            self._result.live_out[addr] = set()

        changed = True
        iterations = 0
        max_iterations = 100

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for addr in sorted(self.cfg.blocks.keys(), reverse=True):
                block = self.cfg.blocks[addr]

                old_out = self._result.live_out[addr].copy()

                for succ_addr in block.successors:
                    if succ_addr in self._result.live_in:
                        self._result.live_out[addr].update(self._result.live_in[succ_addr])

                old_in = self._result.live_in[addr].copy()

                use = self._get_block_use(block)
                defn = self._get_block_def(block)

                self._result.live_in[addr] = use | (self._result.live_out[addr] - defn)

                if self._result.live_in[addr] != old_in or self._result.live_out[addr] != old_out:
                    changed = True

    def _get_block_use(self, block: BasicBlock) -> set[Register]:
        """Get registers used before being defined in a block."""
        return {Register(reg, size) for reg, size in compute_block_use(block.instructions)}

    def _get_block_def(self, block: BasicBlock) -> set[Register]:
        """Get registers defined in a block."""
        return {Register(reg, size) for reg, size in compute_block_def(block.instructions)}

    def _extract_used_registers(self, insn: dict) -> set[Register]:
        """Extract registers used by an instruction."""
        used: set[Register] = set()
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
                for reg in self._extract_registers_from_operand(src):
                    used.add(reg)

        for reg in self._extract_registers_from_operand(operands):
            if "(" in operands and ")" in operands:
                used.add(reg)

        return used

    def _extract_defined_registers(self, insn: dict) -> set[Register]:
        """Extract registers defined by an instruction."""
        defined: set[Register] = set()
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

            for reg in self._extract_registers_from_operand(dest):
                defined.add(reg)

        return defined

    def _extract_registers_from_operand(self, operand: str) -> set[Register]:
        """Extract register names from an operand string."""
        return {Register(reg, size) for reg, size in extract_registers_from_operand(operand)}

    def _compute_reaching_definitions(self) -> None:
        """Compute reaching definitions (forward data flow)."""
        self._result.reaching_in.clear()
        self._result.reaching_out.clear()

        for addr in self.cfg.blocks:
            self._result.reaching_in[addr] = set()
            self._result.reaching_out[addr] = set()

        changed = True
        iterations = 0
        max_iterations = 100

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for addr in sorted(self.cfg.blocks.keys()):
                block = self.cfg.blocks[addr]

                old_in = self._result.reaching_in[addr].copy()

                for pred_addr in block.predecessors:
                    if pred_addr in self._result.reaching_out:
                        self._result.reaching_in[addr].update(self._result.reaching_out[pred_addr])

                gen = self._get_block_gen(block)
                kill = self._get_block_kill(block, gen)

                new_out = gen | (self._result.reaching_in[addr] - kill)

                if self._result.reaching_out[addr] != new_out:
                    self._result.reaching_out[addr] = new_out
                    changed = True
                elif self._result.reaching_in[addr] != old_in:
                    changed = True

    def _get_block_gen(self, block: BasicBlock) -> set[Definition]:
        """Get definitions generated by a block."""
        gen = set()

        for insn in block.instructions:
            addr = insn.get("offset", 0)
            regs_defined = self._extract_defined_registers(insn)

            for reg in regs_defined:
                defn = Definition(address=addr, register=reg, instruction=insn.get("disasm", ""))
                gen.add(defn)

        return gen

    def get_block_definitions(self, block: BasicBlock) -> set[Definition]:
        """Public API to get definitions generated by a block."""
        return self._get_block_gen(block)

    def get_reaching_in(self, block_addr: int) -> set[Definition]:
        """Public API to get reaching definitions for a block."""
        return self._result.reaching_in.get(block_addr, set())

    def get_def_use_chains(self) -> list[DefUseChain]:
        """Public API to get all def-use chains."""
        return self._result.def_use_chains

    def _get_block_kill(self, block: BasicBlock, gen: set[Definition]) -> set[Definition]:
        """Get definitions killed by a block."""
        kill = set()

        defined_regs = set()
        for defn in gen:
            if defn.register:
                defined_regs.add(defn.register)

        for reg in defined_regs:
            for definitions in self._result.reaching_in.values():
                for defn in definitions:
                    if defn.register and defn.register.name == reg.name:
                        kill.add(defn)

        return kill

    def _build_def_use_chains(self) -> None:
        """Build definition-use chains."""
        chains_by_def: dict[tuple[int, str], DefUseChain] = {}

        for addr, block in sorted(self.cfg.blocks.items()):
            for insn in block.instructions:
                insn_addr = insn.get("offset", 0)

                regs_defined = self._extract_defined_registers(insn)
                for reg in regs_defined:
                    key = (insn_addr, reg.name)
                    defn = Definition(address=insn_addr, register=reg)
                    chains_by_def[key] = DefUseChain(
                        definition=defn,
                        register=reg,
                        live_range=(insn_addr, insn_addr),
                    )

        for addr, block in sorted(self.cfg.blocks.items()):
            for insn in block.instructions:
                insn_addr = insn.get("offset", 0)

                regs_used = self._extract_used_registers(insn)
                for reg in regs_used:
                    reaching = self._get_reaching_definition_for(reg, insn_addr)

                    if reaching:
                        key = (reaching.address, reg.name)
                        if key in chains_by_def:
                            use = Use(address=insn_addr, register=reg)
                            chains_by_def[key].add_use(use)

        self._result.def_use_chains = list(chains_by_def.values())

    def _get_reaching_definition_for(self, reg: Register, address: int) -> Definition | None:
        """Get the reaching definition for a register at an address."""
        block_addr = None
        for baddr, block in self.cfg.blocks.items():
            for insn in block.instructions:
                if insn.get("offset", 0) == address:
                    block_addr = baddr
                    break
            if block_addr:
                break

        if block_addr is None:
            return None

        reaching = self._result.reaching_in.get(block_addr, set())

        latest_def: Definition | None = None
        latest_addr = -1

        for defn in reaching:
            if defn.register and defn.register.name == reg.name:
                if defn.address > latest_addr and defn.address < address:
                    latest_def = defn
                    latest_addr = defn.address

        return latest_def

    def get_value_at(self, address: int, register: Register) -> set[Any]:
        """
        Get possible values for a register at an address.

        Args:
            address: Instruction address
            register: Register to analyze

        Returns:
            Set of possible values
        """
        values: set[Any] = set()
        block_addr = None

        for baddr, block in self.cfg.blocks.items():
            for insn in block.instructions:
                if insn.get("offset", 0) == address:
                    block_addr = baddr
                    break
            if block_addr is not None:
                break

        if block_addr is None:
            return values

        reaching = self._result.reaching_in.get(block_addr, set())

        for defn in reaching:
            if defn.register and defn.register.name == register.name:
                if defn.value is not None:
                    values.add(defn.value)

        return values

    def is_safe_to_mutate(self, address: int, mutation_type: str) -> tuple[bool, str]:
        """
        Check if it's safe to apply a mutation at an address.

        Args:
            address: Address to check
            mutation_type: Type of mutation

        Returns:
            Tuple of (is_safe, reason)
        """
        block_addr = None
        for baddr, block in self.cfg.blocks.items():
            for insn in block.instructions:
                if insn.get("offset", 0) == address:
                    block_addr = baddr
                    break
            if block_addr is not None:
                break

        if block_addr is None:
            return (False, "Address not found in CFG")

        live_regs = self._result.live_in.get(block_addr, set())

        if mutation_type in ("register_swap", "register_substitution"):
            critical_regs = {"rsp", "rbp", "esp", "ebp"}
            for reg in live_regs:
                if reg.name.lower() in critical_regs:
                    aliases = reg.aliases()
                    for alias in aliases:
                        if alias.name.lower() in critical_regs:
                            return (False, f"Critical register {reg.name} is live")

        reaching = self._result.reaching_in.get(block_addr, set())

        if mutation_type == "instruction_expansion":
            for defn in reaching:
                if defn.register:
                    if self._is_address_calculation(defn):
                        return (False, "Address calculation nearby - expansion may break pointer references")

        return (True, "Safe to mutate")

    def _is_address_calculation(self, defn: Definition) -> bool:
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
