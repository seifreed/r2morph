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
from dataclasses import dataclass, field
from typing import Any

from r2morph.analysis.cfg import BasicBlock, ControlFlowGraph
from r2morph.analysis.dataflow import Register

logger = logging.getLogger(__name__)


@dataclass
class LiveRange:
    """Represents the live range of a register."""

    register: Register
    start_address: int
    end_address: int
    definition_address: int | None = None
    use_addresses: list[int] = field(default_factory=list)

    def __repr__(self) -> str:
        return f"<LiveRange {self.register} 0x{self.start_address:x}-0x{self.end_address:x}>"

    def contains(self, address: int) -> bool:
        """Check if address is within this live range."""
        return self.start_address <= address <= self.end_address

    def overlaps(self, other: "LiveRange") -> bool:
        """Check if this live range overlaps with another."""
        if self.register.name != other.register.name:
            return False
        return self.start_address <= other.end_address and other.start_address <= self.end_address

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "register": self.register.name,
            "start": f"0x{self.start_address:x}",
            "end": f"0x{self.end_address:x}",
            "definition": f"0x{self.definition_address:x}" if self.definition_address else None,
            "uses": [f"0x{addr:x}" for addr in self.use_addresses],
        }


@dataclass
class InstructionLiveness:
    """Liveness information at a specific instruction."""

    address: int
    instruction: str
    live_before: set[Register] = field(default_factory=set)
    live_after: set[Register] = field(default_factory=set)
    defined: set[Register] = field(default_factory=set)
    used: set[Register] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "address": f"0x{self.address:x}",
            "instruction": self.instruction,
            "live_before": sorted([r.name for r in self.live_before]),
            "live_after": sorted([r.name for r in self.live_after]),
            "defined": sorted([r.name for r in self.defined]),
            "used": sorted([r.name for r in self.used]),
        }


@dataclass
class InterferenceGraph:
    """Interference graph for register allocation."""

    edges: dict[str, set[str]] = field(default_factory=dict)

    def add_node(self, register: str) -> None:
        """Add a node to the graph."""
        if register not in self.edges:
            self.edges[register] = set()

    def add_edge(self, reg1: str, reg2: str) -> None:
        """Add an interference edge between two registers."""
        self.add_node(reg1)
        self.add_node(reg2)
        if reg1 != reg2:
            self.edges[reg1].add(reg2)
            self.edges[reg2].add(reg1)

    def interfere(self, reg1: str, reg2: str) -> bool:
        """Check if two registers interfere."""
        return reg2 in self.edges.get(reg1, set())

    def get_neighbors(self, register: str) -> set[str]:
        """Get all registers that interfere with the given register."""
        return self.edges.get(register, set())

    def get_nodes(self) -> set[str]:
        """Get all register nodes in the graph."""
        return set(self.edges.keys())

    def to_dict(self) -> dict[str, list[str]]:
        """Convert to dictionary."""
        return {reg: sorted(neighbors) for reg, neighbors in self.edges.items()}


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

    # ABI-specific register sets for call instruction analysis
    _CALL_USED_REGS = {
        "sysv_amd64": [("rdi", 64), ("rsi", 64), ("rdx", 64), ("rcx", 64), ("r8", 64), ("r9", 64)],
        "win64": [("rcx", 64), ("rdx", 64), ("r8", 64), ("r9", 64)],
        "cdecl_32": [],  # Arguments passed on stack
    }
    _CALL_DEFINED_REGS = {
        "sysv_amd64": [
            ("rax", 64), ("rdx", 64), ("rcx", 64), ("rsi", 64), ("rdi", 64),
            ("r8", 64), ("r9", 64), ("r10", 64), ("r11", 64),
        ],
        "win64": [("rax", 64), ("rcx", 64), ("rdx", 64), ("r8", 64), ("r9", 64), ("r10", 64), ("r11", 64)],
        "cdecl_32": [("eax", 32), ("ecx", 32), ("edx", 32)],
    }

    def __init__(self, cfg: ControlFlowGraph, abi: str = "sysv_amd64"):
        self.cfg = cfg
        self._abi = abi
        self._instruction_liveness: dict[int, InstructionLiveness] = {}
        self._live_ranges: dict[str, list[LiveRange]] = {}
        self._interference_graph: InterferenceGraph = InterferenceGraph()
        self._block_live_in: dict[int, set[Register]] = {}
        self._block_live_out: dict[int, set[Register]] = {}

    def compute(self) -> None:
        """Compute liveness analysis."""
        self._compute_block_liveness()
        self._compute_instruction_liveness()
        self._compute_live_ranges()
        self._build_interference_graph()

    def _compute_block_liveness(self) -> None:
        """Compute liveness at block level (backward direction)."""
        for addr in self.cfg.blocks:
            self._block_live_in[addr] = set()
            self._block_live_out[addr] = set()

        changed = True
        iterations = 0
        max_iterations = 100

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for addr in sorted(self.cfg.blocks.keys(), reverse=True):
                block = self.cfg.blocks[addr]

                old_out = self._block_live_out[addr].copy()

                for succ_addr in block.successors:
                    if succ_addr in self._block_live_in:
                        self._block_live_out[addr].update(self._block_live_in[succ_addr])

                use = self._get_block_use(block)
                defn = self._get_block_def(block)

                self._block_live_in[addr] = use | (self._block_live_out[addr] - defn)

                if self._block_live_out[addr] != old_out:
                    changed = True

    def _get_block_use(self, block: BasicBlock) -> set[Register]:
        """Get registers used before defined in a block."""
        used = set()
        defined = set()

        for insn in block.instructions:
            regs_used = self._extract_registers_used(insn)
            for reg in regs_used:
                if not self._register_in_set(reg, defined):
                    used.add(reg)

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

    def _register_in_set(self, reg: Register, reg_set: set[Register]) -> bool:
        """Check if a register is in a set (by name)."""
        return any(r.name == reg.name for r in reg_set)

    def _compute_instruction_liveness(self) -> None:
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

                for reg in used:
                    if not self._register_in_set(reg, current_live):
                        current_live.add(reg)

                for reg in defined:
                    to_remove = set()
                    for live_reg in current_live:
                        if live_reg.name == reg.name:
                            to_remove.add(live_reg)
                    current_live -= to_remove

                insn_live.live_before = current_live.copy()

                self._instruction_liveness[addr] = insn_live

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
        """Build interference graph from live ranges."""
        for reg_name, ranges in self._live_ranges.items():
            self._interference_graph.add_node(reg_name)

        all_ranges: list[tuple[str, LiveRange]] = []
        for reg_name, ranges in self._live_ranges.items():
            for lr in ranges:
                all_ranges.append((reg_name, lr))

        for i, (reg1, range1) in enumerate(all_ranges):
            for reg2, range2 in all_ranges[i + 1 :]:
                if reg1 != reg2 and range1.overlaps(range2):
                    self._interference_graph.add_edge(reg1, reg2)

    def _extract_registers_used(self, insn: dict) -> set[Register]:
        """Extract registers used by an instruction."""
        used = set()
        disasm = insn.get("disasm", "").lower()

        if not disasm:
            return used

        mnemonic = insn.get("type", "").lower()

        if mnemonic in ("jmp", "ret", "nop"):
            return used

        # call instructions implicitly use argument registers per ABI
        if mnemonic == "call":
            for reg_name, reg_size in self._CALL_USED_REGS.get(self._abi, self._CALL_USED_REGS["sysv_amd64"]):
                used.add(Register(reg_name, reg_size))
            # Also extract explicit operand registers (e.g., call rax)
            operand_parts = disasm.split(None, 1)
            if len(operand_parts) >= 2:
                for reg in self._parse_registers_from_string(operand_parts[1]):
                    used.add(reg)
            return used

        operand_parts = disasm.split(None, 1)
        if len(operand_parts) < 2:
            return used

        operands = operand_parts[1]
        if "," in operands:
            parts = operands.split(",")
            if len(parts) >= 2:
                src = parts[1].strip()
                for reg in self._parse_registers_from_string(src):
                    used.add(reg)
            dest = parts[0].strip()
            if "[" in dest:
                for reg in self._parse_registers_from_string(dest):
                    used.add(reg)
        else:
            for reg in self._parse_registers_from_string(operands):
                used.add(reg)

        if "(" in disasm and ")" in disasm:
            for reg in self._parse_registers_from_string(disasm):
                used.add(reg)

        return used

    def _extract_registers_defined(self, insn: dict) -> set[Register]:
        """Extract registers defined by an instruction."""
        defined = set()
        disasm = insn.get("disasm", "").lower()
        mnemonic = insn.get("type", "").lower()

        if not disasm:
            return defined

        if mnemonic in ("jmp", "ret", "nop"):
            return defined

        # call instructions implicitly define return value and caller-saved registers per ABI
        if mnemonic == "call":
            for reg_name, reg_size in self._CALL_DEFINED_REGS.get(self._abi, self._CALL_DEFINED_REGS["sysv_amd64"]):
                defined.add(Register(reg_name, reg_size))
            return defined

        operand_parts = disasm.split(None, 1)
        if len(operand_parts) < 2:
            return defined

        operands = operand_parts[1]
        if "," in operands:
            dest = operands.split(",")[0].strip()

            if "[" in dest:
                return defined

            for reg in self._parse_registers_from_string(dest):
                defined.add(reg)

        return defined

    def _parse_registers_from_string(self, s: str) -> set[Register]:
        """Parse register names from a string."""
        registers = set()
        s = s.lower()

        size_map = {
            "rax": 64,
            "rbx": 64,
            "rcx": 64,
            "rdx": 64,
            "rsi": 64,
            "rdi": 64,
            "rbp": 64,
            "rsp": 64,
            "r8": 64,
            "r9": 64,
            "r10": 64,
            "r11": 64,
            "r12": 64,
            "r13": 64,
            "r14": 64,
            "r15": 64,
            "eax": 32,
            "ebx": 32,
            "ecx": 32,
            "edx": 32,
            "esi": 32,
            "edi": 32,
            "ebp": 32,
            "esp": 32,
            "r8d": 32,
            "r9d": 32,
            "r10d": 32,
            "r11d": 32,
            "r12d": 32,
            "r13d": 32,
            "r14d": 32,
            "r15d": 32,
            "ax": 16,
            "bx": 16,
            "cx": 16,
            "dx": 16,
            "si": 16,
            "di": 16,
            "bp": 16,
            "sp": 16,
            "r8w": 16,
            "r9w": 16,
            "r10w": 16,
            "r11w": 16,
            "r12w": 16,
            "r13w": 16,
            "r14w": 16,
            "r15w": 16,
            "al": 8,
            "bl": 8,
            "cl": 8,
            "dl": 8,
            "sil": 8,
            "dil": 8,
            "bpl": 8,
            "spl": 8,
            "r8b": 8,
            "r9b": 8,
            "r10b": 8,
            "r11b": 8,
            "r12b": 8,
            "r13b": 8,
            "r14b": 8,
            "r15b": 8,
        }

        for reg, size in size_map.items():
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
            return any(r.name == register.name for r in live_before)

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
            return self._live_ranges.get(register.name, [])
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
