"""
Liveness analysis module for binary analysis.

Provides detailed liveness computation including:
- Register liveness at each instruction
- Variable liveness tracking
- Live range calculation
- Interference graph construction
"""

import logging
import re
from collections import deque
from typing import Any

from r2morph.analysis.call_effects import call_register_effects, is_call_instruction, return_register_effects
from r2morph.analysis.cfg import BasicBlock, ControlFlowGraph
from r2morph.analysis.dataflow_models import Register
from r2morph.analysis.flag_effects import FLAGS_RESOURCE_NAME, FLAGS_RESOURCE_SIZE, flag_accesses
from r2morph.analysis.liveness_models import (
    _X86_REGISTER_BIT_SIZES,
    InstructionLiveness,
    InterferenceGraph,
    LiveRange,
)
from r2morph.analysis.memory_effects import (
    MEMORY_RESOURCE_NAME,
    frame_pointer_registers,
    memory_accesses,
    stack_pointer_registers,
)

_INSTRUCTION_PART_COUNT = 2
_X86_32_BIT_SIZE = 32
_X86_64_BIT_SIZE = 64
_READ_MODIFY_WRITE_MNEMONICS = frozenset(
    {
        "adc",
        "add",
        "and",
        "bt",
        "cmp",
        "cmpxchg",
        "dec",
        "imul",
        "inc",
        "neg",
        "not",
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
_READ_BOTH_OPERANDS_MNEMONICS = _READ_MODIFY_WRITE_MNEMONICS | {"cmp", "test"}
_MAX_REGISTER_COMPARISONS = 100_000
logger = logging.getLogger(__name__)


class LivenessAnalysis:
    """
    Per-instruction liveness analysis.

    Computes precise liveness information at each instruction,
    live ranges, and interference graphs.

    Usage:
        analyzer = LivenessAnalysis(cfg)
        analyzer.compute()
        is_live = analyzer.is_live_at(register, address)
    """

    def __init__(self, cfg: ControlFlowGraph, abi: str = "sysv_amd64"):
        self.cfg = cfg
        self._abi = abi
        self._instruction_liveness: dict[int, InstructionLiveness] = {}
        self._live_ranges: dict[str, list[LiveRange]] = {}
        self._interference_graph: InterferenceGraph = InterferenceGraph()
        self._block_live_in: dict[int, set[Register]] = {}
        self._block_live_out: dict[int, set[Register]] = {}
        self._analysis_complete = True
        self._comparison_count = 0

    @property
    def analysis_complete(self) -> bool:
        """Return whether liveness finished within its comparison budget."""
        return self._analysis_complete

    def compute(self) -> None:
        """Compute liveness analysis."""
        self._instruction_liveness.clear()
        self._live_ranges.clear()
        self._interference_graph = InterferenceGraph()
        self._analysis_complete = True
        self._comparison_count = 0
        self._compute_block_liveness()
        if not self._analysis_complete:
            return
        if not self._compute_instruction_liveness():
            return
        self._compute_live_ranges()
        self._build_interference_graph()

    def _compute_block_liveness(self) -> None:
        """Compute liveness at block level (backward direction)."""
        block_addresses = set(self.cfg.blocks)
        self._block_live_in = {addr: set() for addr in block_addresses}
        self._block_live_out = {addr: set() for addr in block_addresses}
        block_use = {addr: self._get_block_use(block) for addr, block in self.cfg.blocks.items()}
        block_def = {addr: self._get_block_def(block) for addr, block in self.cfg.blocks.items()}
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
            new_out: set[Register] = set()
            for successor in block.successors:
                new_out.update(self._block_live_in.get(successor, set()))
            new_in = block_use[addr] | (new_out - block_def[addr])

            if new_out == self._block_live_out[addr] and new_in == self._block_live_in[addr]:
                continue

            self._block_live_out[addr] = new_out
            self._block_live_in[addr] = new_in
            for predecessor in sorted(predecessors[addr], reverse=True):
                if predecessor not in queued:
                    pending.append(predecessor)
                    queued.add(predecessor)

    def _get_block_use(self, block: BasicBlock) -> set[Register]:
        """Get registers used before defined in a block."""
        used: set[Register] = set()
        defined: set[Register] = set()

        for insn in block.instructions:
            regs_used = self._extract_registers_used(insn)
            for reg in regs_used:
                if not self._register_in_set(reg, defined):
                    used.add(reg)
                if not self._analysis_complete:
                    return used

            regs_defined = self._extract_registers_defined(insn)
            defined.update(regs_defined)

        return used

    def _get_block_def(self, block: BasicBlock) -> set[Register]:
        """Get registers defined in a block."""
        defined = set()
        for insn in block.instructions:
            regs_def = self._extract_registers_defined(insn)
            defined.update(regs_def)
        return defined

    def _definition_kills_use(self, definition: Register, use: Register) -> bool:
        """Return whether an x86 definition covers a later register use."""
        self._comparison_count += 1
        if self._comparison_count > _MAX_REGISTER_COMPARISONS:
            self._analysis_complete = False
            return False
        if definition.name == use.name:
            return True
        if definition.aliases().isdisjoint(use.aliases()):
            return False
        if definition.size >= use.size:
            return True
        return definition.size == _X86_32_BIT_SIZE and use.size == _X86_64_BIT_SIZE

    def _register_in_set(self, reg: Register, reg_set: set[Register]) -> bool:
        """Check whether a definition set covers a register use."""
        for defined in reg_set:
            if self._definition_kills_use(defined, reg):
                return True
            if not self._analysis_complete:
                return False
        return False

    def _compute_instruction_liveness(self) -> bool:
        """Compute liveness at instruction level."""
        for block_addr, block in self.cfg.blocks.items():
            block_live_out = self._block_live_out.get(block_addr, set())

            current_live: set[Register] = set()
            for r in block_live_out:
                current_live.add(r)

            for insn in reversed(block.instructions):
                addr = insn.get("offset", 0)
                disasm = insn.get("disasm", "")

                insn_live = InstructionLiveness(
                    address=addr,
                    instruction=disasm,
                    live_after=current_live.copy(),
                )

                defined = self._extract_registers_defined(insn)
                used = self._extract_registers_used(insn)

                insn_live.defined = defined
                insn_live.used = used

                remaining_live: set[Register] = set()
                for live_reg in current_live:
                    if not any(self._definition_kills_use(reg, live_reg) for reg in defined):
                        remaining_live.add(live_reg)
                    if not self._analysis_complete:
                        return False
                current_live = remaining_live

                for reg in used:
                    if not self._register_in_set(reg, current_live):
                        current_live.add(reg)
                    if not self._analysis_complete:
                        return False

                insn_live.live_before = current_live.copy()

                self._instruction_liveness[addr] = insn_live
        return True

    def _compute_live_ranges(self) -> None:
        """Compute live ranges for each register."""
        reg_definitions: dict[str, list[tuple[int, int]]] = {}
        reg_uses: dict[str, list[int]] = {}

        for addr, insn_live in sorted(self._instruction_liveness.items()):
            for reg in insn_live.defined:
                if reg.name not in reg_definitions:
                    reg_definitions[reg.name] = []
                reg_definitions[reg.name].append((addr, addr))

            for reg in insn_live.used:
                if reg.name not in reg_uses:
                    reg_uses[reg.name] = []
                reg_uses[reg.name].append(addr)

        for reg_name in set(reg_definitions.keys()) | set(reg_uses.keys()):
            defs = reg_definitions.get(reg_name, [])
            uses = reg_uses.get(reg_name, [])

            if not defs and not uses:
                continue

            all_addrs = sorted(set([d[0] for d in defs] + uses))
            if not all_addrs:
                continue

            range_start = all_addrs[0]
            range_end = all_addrs[-1]

            block_end_addr = range_end
            for block_addr, block in self.cfg.blocks.items():
                if block_addr <= range_end < block_addr + block.size:
                    block_end_addr = block_addr + block.size - 1
                    break

            def_addr = defs[0][0] if defs else None

            lr = LiveRange(
                register=Register(reg_name),
                start_address=range_start,
                end_address=block_end_addr,
                definition_address=def_addr,
                use_addresses=uses.copy(),
            )

            if reg_name not in self._live_ranges:
                self._live_ranges[reg_name] = []
            self._live_ranges[reg_name].append(lr)

    def _build_interference_graph(self) -> None:
        """Build interference from registers live at the same CFG point.

        Numeric live intervals over-approximate control-flow joins: values that
        live on mutually exclusive branches can have overlapping addresses while
        never being live together.  The instruction-level sets already contain
        the precise CFG fixpoint, so use them as the interference source.
        """
        live_registers = set(self._live_ranges)
        live_registers.update(
            register.name
            for liveness in self._instruction_liveness.values()
            for register in liveness.live_before | liveness.live_after
        )
        for reg_name in live_registers:
            self._interference_graph.add_node(reg_name)

        for liveness in self._instruction_liveness.values():
            live = tuple(liveness.live_before | liveness.live_after)
            for index, first in enumerate(live):
                for second in live[index + 1 :]:
                    if not first.aliases().isdisjoint(second.aliases()):
                        self._interference_graph.add_edge(first.name, second.name)

    def _extract_registers_used(self, insn: dict[str, Any]) -> set[Register]:
        """Extract registers used by an instruction."""
        used: set[Register] = set()
        disasm = insn.get("disasm", "").lower()

        if not disasm:
            return used

        mnemonic = insn.get("type", "").lower()
        if mnemonic in ("jmp", "nop"):
            return used

        opcode = disasm.split(None, 1)[0]
        if opcode == "ret":
            used.update(
                Register(register, size)
                for register, size in return_register_effects(self._abi)
                if register in _X86_REGISTER_BIT_SIZES
            )
            used.update(Register(*register) for register in stack_pointer_registers(disasm, self._abi, read=True))
            return used

        # call instructions implicitly use argument registers per ABI
        if is_call_instruction(insn):
            call_used, _ = call_register_effects(self._abi)
            used = {Register(reg_name, reg_size) for reg_name, reg_size in call_used}
            used.add(Register(MEMORY_RESOURCE_NAME))
            # Also extract explicit operand registers (e.g., call rax)
            operand_parts = disasm.split(None, 1)
            if len(operand_parts) >= _INSTRUCTION_PART_COUNT:
                used.update(self._parse_registers_from_string(operand_parts[1]))
            used.update(Register(*register) for register in stack_pointer_registers(disasm, self._abi, read=True))
            return used

        operand_parts = disasm.split(None, 1)
        used.update(Register(*register) for register in frame_pointer_registers(disasm, self._abi))
        if len(operand_parts) >= _INSTRUCTION_PART_COUNT:
            used = self._registers_used_by_operands(operand_parts[1], disasm)
            if memory_accesses(disasm)[0]:
                used.add(Register(MEMORY_RESOURCE_NAME))
            used.update(Register(*register) for register in frame_pointer_registers(disasm, self._abi))
            used.update(Register(*register) for register in stack_pointer_registers(disasm, self._abi, read=True))
            return used
        if flag_accesses(disasm)[0]:
            used.add(Register(FLAGS_RESOURCE_NAME, FLAGS_RESOURCE_SIZE))
        if memory_accesses(disasm)[0]:
            used.add(Register(MEMORY_RESOURCE_NAME))
        used.update(Register(*register) for register in stack_pointer_registers(disasm, self._abi, read=True))
        return used

    def _registers_used_by_operands(self, operands: str, disasm: str) -> set[Register]:
        used: set[Register] = set()
        opcode = disasm.split(None, 1)[0].lower() if disasm else ""
        if "," in operands:
            parts = operands.split(",")
            if len(parts) >= _INSTRUCTION_PART_COUNT:
                for source in parts[1:]:
                    used.update(self._parse_registers_from_string(source.strip()))
            dest = parts[0].strip()
            if "[" in dest or opcode in _READ_BOTH_OPERANDS_MNEMONICS or opcode.startswith("cmov"):
                used.update(self._parse_registers_from_string(dest))
        elif opcode != "pop" and not opcode.startswith("set"):
            used.update(self._parse_registers_from_string(operands))

        if "(" in disasm and ")" in disasm:
            used.update(self._parse_registers_from_string(disasm))

        if flag_accesses(disasm)[0]:
            used.add(Register(FLAGS_RESOURCE_NAME, FLAGS_RESOURCE_SIZE))

        return used

    def _extract_registers_defined(self, insn: dict[str, Any]) -> set[Register]:
        """Extract registers defined by an instruction."""
        defined: set[Register] = set()
        disasm = insn.get("disasm", "").lower()
        mnemonic = insn.get("type", "").lower()
        opcode = disasm.split(None, 1)[0]

        if not disasm:
            return defined

        if mnemonic in ("jmp", "ret", "nop"):
            defined.update(Register(*register) for register in stack_pointer_registers(disasm, self._abi, write=True))
            return defined

        # call instructions implicitly define return value and caller-saved registers per ABI
        if is_call_instruction(insn):
            _, call_defined = call_register_effects(self._abi)
            for reg_name, reg_size in call_defined:
                defined.add(Register(reg_name, reg_size))
            defined.add(Register(FLAGS_RESOURCE_NAME, FLAGS_RESOURCE_SIZE))
            defined.add(Register(MEMORY_RESOURCE_NAME))
            return defined

        defined.update(Register(*register) for register in stack_pointer_registers(disasm, self._abi, write=True))
        defined.update(Register(*register) for register in frame_pointer_registers(disasm, self._abi))

        operand_parts = disasm.split(None, 1)
        if len(operand_parts) >= _INSTRUCTION_PART_COUNT:
            operands = operand_parts[1]
            dest = operands.split(",")[0].strip() if "," in operands else operands.strip()

            if "[" not in dest and opcode not in {"cmp", "test", "pushf", "pushfq"}:
                for reg in self._parse_registers_from_string(dest):
                    defined.add(reg)

        if flag_accesses(disasm)[1]:
            defined.add(Register(FLAGS_RESOURCE_NAME, FLAGS_RESOURCE_SIZE))
        if memory_accesses(disasm)[1]:
            defined.add(Register(MEMORY_RESOURCE_NAME))

        return defined

    def _parse_registers_from_string(self, s: str) -> set[Register]:
        """Parse register names from a string."""
        registers = set()
        s = s.lower()

        for reg, size in _X86_REGISTER_BIT_SIZES.items():
            if re.search(r"\b" + re.escape(reg) + r"\b", s):
                registers.add(Register(reg, size))

        return registers

    def is_live_at(self, register: Register, address: int) -> bool:
        """
        Check if a register is live at an address.

        Args:
            register: Register to check
            address: Instruction address

        Returns:
            True if register is live at address
        """
        if address in self._instruction_liveness:
            live_before = self._instruction_liveness[address].live_before
            return any(not register.aliases().isdisjoint(r.aliases()) for r in live_before)

        return False

    def get_live_registers(self, address: int) -> set[Register]:
        """
        Get all live registers at an address.

        Args:
            address: Instruction address

        Returns:
            Set of live registers
        """
        if address in self._instruction_liveness:
            return self._instruction_liveness[address].live_before.copy()
        return set()

    def get_live_ranges(self, register: Register | None = None) -> list[LiveRange]:
        """
        Get live ranges for a register or all registers.

        Args:
            register: Optional register to filter by

        Returns:
            List of live ranges
        """
        if register:
            return [
                live_range
                for ranges in self._live_ranges.values()
                for live_range in ranges
                if not live_range.register.aliases().isdisjoint(register.aliases())
            ]
        all_ranges = []
        for ranges in self._live_ranges.values():
            all_ranges.extend(ranges)
        return all_ranges

    def get_instruction_liveness(self, address: int) -> InstructionLiveness | None:
        """
        Get liveness information at an instruction.

        Args:
            address: Instruction address

        Returns:
            InstructionLiveness or None
        """
        return self._instruction_liveness.get(address)

    def get_interference_graph(self) -> InterferenceGraph:
        """
        Get the interference graph.

        Returns:
            InterferenceGraph instance
        """
        return self._interference_graph

    def get_block_live_in(self, block_address: int) -> set[Register]:
        """
        Get registers live at block entry.

        Args:
            block_address: Block address

        Returns:
            Set of live registers
        """
        return self._block_live_in.get(block_address, set())

    def get_block_live_out(self, block_address: int) -> set[Register]:
        """
        Get registers live at block exit.

        Args:
            block_address: Block address

        Returns:
            Set of live registers
        """
        return self._block_live_out.get(block_address, set())

    def to_dict(self) -> dict[str, Any]:
        """Convert analysis results to dictionary."""
        return {
            "instruction_liveness": {
                f"0x{addr:x}": il.to_dict() for addr, il in sorted(self._instruction_liveness.items())
            },
            "live_ranges": {reg: [lr.to_dict() for lr in ranges] for reg, ranges in self._live_ranges.items()},
            "interference_graph": self._interference_graph.to_dict(),
        }
