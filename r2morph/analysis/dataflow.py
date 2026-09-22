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
from collections import deque
from typing import Any

from r2morph.analysis.call_effects import call_register_effects, is_call_instruction
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
    register_definition_covers_use,
)
from r2morph.analysis.dataflow_parsing import extract_registers_from_operand
from r2morph.analysis.dataflow_queries import get_value_at as _get_value_at
from r2morph.analysis.dataflow_queries import is_safe_to_mutate as _is_safe_to_mutate
from r2morph.analysis.flag_effects import FLAGS_RESOURCE_NAME, FLAGS_RESOURCE_SIZE, flag_accesses
from r2morph.analysis.memory_effects import (
    MEMORY_RESOURCE_NAME,
    frame_pointer_registers,
    memory_accesses,
    stack_pointer_registers,
)

_MIN_INSTRUCTION_PART_COUNT = 2
_READ_BOTH_OPERANDS_MNEMONICS = frozenset(
    {
        "adc",
        "add",
        "and",
        "bt",
        "cmp",
        "cmpxchg",
        "imul",
        "or",
        "rcl",
        "rcr",
        "rol",
        "ror",
        "sbb",
        "sar",
        "shl",
        "shr",
        "sub",
        "test",
        "xadd",
        "xchg",
        "xor",
    }
)

DataFlowDirection = _DataFlowDirection

logger = logging.getLogger(__name__)

_MAX_KILL_COMPARISONS = 100_000


class DataFlowAnalyzer:
    """
    Core data flow analyzer.

    Performs forward and backward data flow analysis on CFG basic blocks.

    Usage:
        analyzer = DataFlowAnalyzer(cfg)
        result = analyzer.analyze()
        live_regs = result.get_live_registers(address)
    """

    def __init__(self, cfg: ControlFlowGraph, abi: str = "sysv_amd64"):
        self.cfg = cfg
        self._abi = abi
        self._result = DataFlowResult()
        self._analysis_complete = True
        self._kill_comparisons = 0

    @property
    def analysis_complete(self) -> bool:
        """Return whether all bounded dataflow work completed."""
        return self._analysis_complete

    def analyze(self) -> DataFlowResult:
        """
        Perform complete data flow analysis.

        Returns:
            DataFlowResult with liveness, reaching definitions, and def-use chains
        """
        self._compute_liveness()
        if not self._analysis_complete:
            return self._result
        self._compute_reaching_definitions()
        self._build_def_use_chains()

        return self._result

    def _compute_liveness(self) -> None:
        """Compute liveness analysis (backward data flow)."""
        self._result.live_in.clear()
        self._result.live_out.clear()
        self._analysis_complete = True
        self._kill_comparisons = 0

        block_addresses = set(self.cfg.blocks)
        for addr in block_addresses:
            self._result.live_in[addr] = set()
            self._result.live_out[addr] = set()

        predecessors: dict[int, set[int]] = {addr: set() for addr in block_addresses}
        for addr, block in self.cfg.blocks.items():
            for successor in block.successors:
                if successor in predecessors:
                    predecessors[successor].add(addr)

        pending = deque(sorted(block_addresses, reverse=True))
        queued = set(pending)
        while pending:
            addr = pending.popleft()
            queued.remove(addr)
            block = self.cfg.blocks[addr]
            live_out: set[Register] = set()
            for successor in block.successors:
                live_out.update(self._result.live_in.get(successor, set()))
            live_in = self._get_block_use(block) | (live_out - self._get_block_def(block))

            if live_out == self._result.live_out[addr] and live_in == self._result.live_in[addr]:
                continue

            self._result.live_out[addr] = live_out
            self._result.live_in[addr] = live_in
            for predecessor in sorted(predecessors[addr], reverse=True):
                if predecessor not in queued:
                    pending.append(predecessor)
                    queued.add(predecessor)

    def _get_block_use(self, block: BasicBlock) -> set[Register]:
        """Get registers used before being defined in a block."""
        return {Register(reg, size) for reg, size in compute_block_use(block.instructions, self._abi)}

    def _get_block_def(self, block: BasicBlock) -> set[Register]:
        """Get registers defined in a block."""
        return {Register(reg, size) for reg, size in compute_block_def(block.instructions, self._abi)}

    def _extract_used_registers(self, insn: dict[str, Any]) -> set[Register]:
        """Extract registers used by an instruction."""
        used: set[Register] = set()
        disasm = insn.get("disasm", "").lower()

        if not disasm:
            return used

        if is_call_instruction(insn):
            call_used, _ = call_register_effects(self._abi)
            used.update(Register(reg, size) for reg, size in call_used)

        if memory_accesses(disasm)[0]:
            used.add(Register(MEMORY_RESOURCE_NAME))
        used.update(Register(*register) for register in stack_pointer_registers(disasm, self._abi, read=True))
        used.update(Register(*register) for register in frame_pointer_registers(disasm, self._abi))
        if flag_accesses(disasm)[0]:
            used.add(Register(FLAGS_RESOURCE_NAME, FLAGS_RESOURCE_SIZE))

        operand_parts = disasm.split(None, 1)
        if len(operand_parts) < _MIN_INSTRUCTION_PART_COUNT:
            return used

        operands = operand_parts[1]
        opcode = operand_parts[0]
        if "," in operands:
            src_parts = operands.split(",")
            if len(src_parts) >= _MIN_INSTRUCTION_PART_COUNT:
                src = src_parts[1].strip()
                for reg in self._extract_registers_from_operand(src):
                    used.add(reg)
                dest = src_parts[0].strip()
                if "[" in dest or opcode in _READ_BOTH_OPERANDS_MNEMONICS or opcode.startswith("cmov"):
                    for reg in self._extract_registers_from_operand(dest):
                        used.add(reg)

        for reg in self._extract_registers_from_operand(operands):
            if "(" in operands and ")" in operands:
                used.add(reg)

        return used

    def _extract_defined_registers(self, insn: dict[str, Any]) -> set[Register]:
        """Extract registers defined by an instruction."""
        defined: set[Register] = set()
        disasm = insn.get("disasm", "").lower()
        mnemonic = insn.get("type", "").lower()

        if not disasm:
            return defined

        if mnemonic in ("jmp", "ret", "nop"):
            defined.update(Register(*register) for register in stack_pointer_registers(disasm, self._abi, write=True))
            return defined

        if memory_accesses(disasm)[1]:
            defined.add(Register(MEMORY_RESOURCE_NAME))
        defined.update(Register(*register) for register in stack_pointer_registers(disasm, self._abi, write=True))
        defined.update(Register(*register) for register in frame_pointer_registers(disasm, self._abi))
        if flag_accesses(disasm)[1]:
            defined.add(Register(FLAGS_RESOURCE_NAME, FLAGS_RESOURCE_SIZE))

        if is_call_instruction(insn):
            _, call_defined = call_register_effects(self._abi)
            defined.update(Register(reg, size) for reg, size in call_defined)
            return defined

        operand_parts = disasm.split(None, 1)
        if len(operand_parts) < _MIN_INSTRUCTION_PART_COUNT:
            return defined

        operands = operand_parts[1]
        if "," in operands:
            dest = operands.split(",")[0].strip()

            if "[" not in dest:
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

        block_addresses = set(self.cfg.blocks)
        for addr in block_addresses:
            self._result.reaching_in[addr] = set()
            self._result.reaching_out[addr] = set()

        pending = deque(sorted(block_addresses))
        queued = set(pending)
        while pending:
            addr = pending.popleft()
            queued.remove(addr)
            block = self.cfg.blocks[addr]
            reaching_in: set[Definition] = set()
            for predecessor in block.predecessors:
                reaching_in.update(self._result.reaching_out.get(predecessor, set()))
            gen = self._get_block_gen(block)
            new_out = gen | (reaching_in - self._get_block_kill(block, gen, reaching_in))

            if reaching_in == self._result.reaching_in[addr] and new_out == self._result.reaching_out[addr]:
                continue

            self._result.reaching_in[addr] = reaching_in
            self._result.reaching_out[addr] = new_out
            for successor in sorted(block.successors):
                if successor in block_addresses and successor not in queued:
                    pending.append(successor)
                    queued.add(successor)

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

    def _get_block_kill(
        self,
        block: BasicBlock,
        gen: set[Definition],
        reaching_in: set[Definition] | None = None,
    ) -> set[Definition]:
        """Get definitions killed by a block."""
        kill: set[Definition] = set()

        defined_regs = set()
        for defn in gen:
            if defn.register:
                defined_regs.add(defn.register)

        candidate_definitions = (
            reaching_in
            if reaching_in is not None
            else {definition for definitions in self._result.reaching_in.values() for definition in definitions}
        )
        for reg in defined_regs:
            for defn in candidate_definitions:
                self._kill_comparisons += 1
                if self._kill_comparisons > _MAX_KILL_COMPARISONS:
                    self._analysis_complete = False
                    return kill
                if defn.register and register_definition_covers_use(reg, defn.register):
                    kill.add(defn)

        return kill

    def _build_def_use_chains(self) -> None:
        """Build definition-use chains."""
        chains_by_def: dict[tuple[int, str], DefUseChain] = {}

        for _addr, block in sorted(self.cfg.blocks.items()):
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

        for _addr, block in sorted(self.cfg.blocks.items()):
            for insn in block.instructions:
                insn_addr = insn.get("offset", 0)

                regs_used = self._extract_used_registers(insn)
                for reg in regs_used:
                    reaching = self._get_reaching_definition_for(reg, insn_addr)

                    if reaching:
                        key = (reaching.address, reaching.register.name if reaching.register else reg.name)
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
            if (
                defn.register
                and register_definition_covers_use(defn.register, reg)
                and latest_addr < defn.address < address
            ):
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
        return _get_value_at(self.cfg, self._result, address, register)

    def is_safe_to_mutate(self, address: int, mutation_type: str) -> tuple[bool, str]:
        """
        Check if it's safe to apply a mutation at an address.

        Args:
            address: Address to check
            mutation_type: Type of mutation

        Returns:
            Tuple of (is_safe, reason)
        """
        return _is_safe_to_mutate(self.cfg, self._result, address, mutation_type)
