"""
SSA (Static Single Assignment) form generation for data flow analysis.

Provides SSA conversion for improved precision in:
- Constant propagation
- Dead code elimination
- Value numbering
- Type inference
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SSAVariable:
    """Represents an SSA variable with version number."""

    base_name: str
    version: int
    original_register: str | None = None
    definition_address: int | None = None

    def __repr__(self) -> str:
        return f"{self.base_name}_{self.version}"

    def __hash__(self) -> int:
        return hash((self.base_name, self.version))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SSAVariable):
            return False
        return self.base_name == other.base_name and self.version == other.version


@dataclass
class PhiFunction:
    """
    Phi function for SSA at control flow merge points.

    φ(v1, v2, ..., vn) - merges values from different control flow paths
    """

    result: SSAVariable
    operands: list[SSAVariable]
    block_address: int

    def __repr__(self) -> str:
        operands_str = ", ".join(str(op) for op in self.operands)
        return f"{self.result} = φ({operands_str})"

    def to_dict(self) -> dict[str, Any]:
        return {
            "result": str(self.result),
            "operands": [str(op) for op in self.operands],
            "block_address": f"0x{self.block_address:x}",
        }


@dataclass
class SSABlock:
    """Basic block in SSA form."""

    address: int
    instructions: list[dict[str, Any]] = field(default_factory=list)
    phi_functions: list[PhiFunction] = field(default_factory=list)
    definitions: dict[str, SSAVariable] = field(default_factory=dict)
    live_in: set[SSAVariable] = field(default_factory=set)
    live_out: set[SSAVariable] = field(default_factory=set)
    predecessors: list[int] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": f"0x{self.address:x}",
            "phi_functions": [phi.to_dict() for phi in self.phi_functions],
            "definitions": {k: str(v) for k, v in self.definitions.items()},
            "predecessors": [f"0x{p:x}" for p in self.predecessors],
            "successors": [f"0x{s:x}" for s in self.successors],
        }


class SSAConverter:
    """
    Convert control flow graphs to SSA form.

    Uses standard SSA construction algorithm:
    1. Insert phi functions at join points
    2. Rename variables with versions
    3. Propagate definitions through dominance frontier
    """

    def __init__(self):
        self._version_counter: dict[str, int] = {}
        self._current_def: dict[str, list[SSAVariable]] = {}
        self._sealed_blocks: set[int] = set()
        self._incomplete_phis: dict[int, list[tuple[str, SSAVariable]]] = {}

    def convert_to_ssa(
        self,
        blocks: dict[int, dict[str, Any]],
        cfg_edges: list[tuple[int, int]],
    ) -> dict[int, SSABlock]:
        """
        Convert a CFG to SSA form.

        Args:
            blocks: Dictionary mapping addresses to block info
            cfg_edges: List of (from_addr, to_addr) edges

        Returns:
            Dictionary mapping addresses to SSABlock instances
        """
        ssa_blocks: dict[int, SSABlock] = {}

        for addr, block_info in blocks.items():
            ssa_block = SSABlock(
                address=addr,
                instructions=block_info.get("instructions", []),
                predecessors=block_info.get("predecessors", []),
                successors=block_info.get("successors", []),
            )
            ssa_blocks[addr] = ssa_block

        self._version_counter.clear()
        self._current_def.clear()
        self._sealed_blocks.clear()
        self._incomplete_phis.clear()

        entry_addr = min(blocks.keys()) if blocks else 0
        self._place_phi_functions(ssa_blocks, entry_addr)

        self._rename_variables(ssa_blocks, entry_addr)

        return ssa_blocks

    def _place_phi_functions(
        self,
        ssa_blocks: dict[int, SSABlock],
        entry_addr: int,
    ) -> None:
        """Place phi functions at dominance frontiers."""
        dominance_frontier = self._compute_dominance_frontier(ssa_blocks)

        for block_addr, ssa_block in ssa_blocks.items():
            if block_addr not in dominance_frontier:
                continue

            frontier = dominance_frontier[block_addr]

            for pred_addr in ssa_block.predecessors:
                if pred_addr in frontier:
                    pred_block = ssa_blocks.get(pred_addr)
                    if pred_block:
                        for reg_name, ssa_var in pred_block.definitions.items():
                            phi = self._create_phi_function(
                                reg_name,
                                block_addr,
                                [pred_addr],
                            )
                            ssa_block.phi_functions.append(phi)

    def _compute_dominance_frontier(
        self,
        ssa_blocks: dict[int, SSABlock],
    ) -> dict[int, set[int]]:
        """
        Compute dominance frontier for each block.

        A block B is in the dominance frontier of block A if:
        - B is not strictly dominated by A
        - B is the successor of a node dominated by A

        Returns:
            Dictionary mapping block address to its dominance frontier
        """
        dominators = self._compute_dominators(ssa_blocks)
        dominance_frontier: dict[int, set[int]] = {}

        for block_addr in ssa_blocks:
            dominance_frontier[block_addr] = set()

        # Compute immediate dominators for the "runner walks up idom" algorithm.
        # The idom of X is the closest (deepest) strict dominator of X.
        # In the dominator tree, depth correlates with dominator set size:
        # if A strictly dominates B, then dom(A) ⊂ dom(B) (B has more dominators).
        # Therefore max by |dom(d)| selects the deepest dominator = idom.
        idom: dict[int, int | None] = {}
        for addr, doms in dominators.items():
            candidates = doms - {addr}
            if candidates:
                idom[addr] = max(candidates, key=lambda d: len(dominators.get(d, set())))
            else:
                idom[addr] = None

        for block_addr, ssa_block in ssa_blocks.items():
            if len(ssa_block.predecessors) >= 2:
                for pred_addr in ssa_block.predecessors:
                    runner = pred_addr
                    idom_block = idom.get(block_addr)

                    while runner != idom_block and runner is not None:
                        if runner not in dominance_frontier:
                            dominance_frontier[runner] = set()
                        dominance_frontier[runner].add(block_addr)

                        runner = idom.get(runner)

        return dominance_frontier

    def _compute_dominators(
        self,
        ssa_blocks: dict[int, SSABlock],
    ) -> dict[int, set[int]]:
        """Compute immediate dominators for each block."""
        if not ssa_blocks:
            return {}

        entry_addr = min(ssa_blocks.keys())
        all_blocks = set(ssa_blocks.keys())

        dominators: dict[int, set[int]] = {}
        dominators[entry_addr] = {entry_addr}

        for addr in ssa_blocks:
            if addr != entry_addr:
                dominators[addr] = all_blocks.copy()

        changed = True
        iterations = 0
        max_iterations = 100

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for addr, ssa_block in ssa_blocks.items():
                if addr == entry_addr:
                    continue

                if ssa_block.predecessors:
                    pred_doms = [dominators.get(p, all_blocks) for p in ssa_block.predecessors]
                    if pred_doms:
                        new_dom = set.intersection(*pred_doms)
                        new_dom.add(addr)

                        if new_dom != dominators.get(addr):
                            dominators[addr] = new_dom
                            changed = True
                else:
                    dominators[addr] = {addr}

        return dominators

    def _create_phi_function(
        self,
        reg_name: str,
        block_addr: int,
        predecessor_addrs: list[int],
    ) -> PhiFunction:
        """Create a phi function for a register at a join point."""
        version = self._version_counter.get(reg_name, 0)
        result_var = SSAVariable(
            base_name=reg_name,
            version=version,
        )

        operands: list[SSAVariable] = []
        for pred_addr in predecessor_addrs:
            operand_version = max(0, version - 1)
            operands.append(
                SSAVariable(
                    base_name=reg_name,
                    version=operand_version,
                )
            )

        return PhiFunction(
            result=result_var,
            operands=operands,
            block_address=block_addr,
        )

    def _rename_variables(
        self,
        ssa_blocks: dict[int, SSABlock],
        entry_addr: int,
    ) -> None:
        """Rename all variables with SSA versions."""
        visited: set[int] = set()

        self._rename_in_block(ssa_blocks, entry_addr, visited)

    def _rename_in_block(
        self,
        ssa_blocks: dict[int, SSABlock],
        block_addr: int,
        visited: set[int],
    ) -> None:
        """Rename variables in a block using DFS traversal."""
        if block_addr in visited:
            return

        visited.add(block_addr)
        ssa_block = ssa_blocks.get(block_addr)

        if not ssa_block:
            return

        for instruction in ssa_block.instructions:
            self._rename_instruction(instruction, ssa_block)

        for phi in ssa_block.phi_functions:
            version = self._get_new_version(phi.result.base_name)
            new_var = SSAVariable(
                base_name=phi.result.base_name,
                version=version,
                definition_address=block_addr,
            )
            ssa_block.definitions[phi.result.base_name] = new_var

        for succ_addr in ssa_block.successors:
            self._rename_in_block(ssa_blocks, succ_addr, visited)

        visited.discard(block_addr)

    def _rename_instruction(
        self,
        instruction: dict[str, Any],
        ssa_block: SSABlock,
    ) -> None:
        """Rename variables in a single instruction."""
        disasm = instruction.get("disasm", "").lower()

        defined_regs = self._extract_defined_registers(disasm)
        used_regs = self._extract_used_registers(disasm)

        for reg in used_regs:
            if reg not in ssa_block.definitions:
                version = self._get_current_version(reg)
                ssa_block.definitions[reg] = SSAVariable(
                    base_name=reg,
                    version=version,
                )

        for reg in defined_regs:
            version = self._get_new_version(reg)
            ssa_block.definitions[reg] = SSAVariable(
                base_name=reg,
                version=version,
                definition_address=instruction.get("offset", 0),
            )

    def _extract_defined_registers(self, disasm: str) -> set[str]:
        """Extract registers that are defined (written to) in an instruction."""
        defined = set()

        if "mov" in disasm or "lea" in disasm or "pop" in disasm:
            import re

            match = re.match(r"\w+\s+(\w+)", disasm)
            if match:
                defined.add(match.group(1).lower())

        return defined

    def _extract_used_registers(self, disasm: str) -> set[str]:
        """Extract registers that are used (read from) in an instruction."""
        used = set()

        import re

        reg_pattern = r"\b([a-z][a-z0-9]*)\b"
        operands = disasm.split(",") if "," in disasm else [disasm]

        if len(operands) > 1:
            for op in operands[1:]:
                for match in re.finditer(reg_pattern, op.lower()):
                    reg = match.group(1)
                    if reg in {
                        "eax",
                        "ebx",
                        "ecx",
                        "edx",
                        "esi",
                        "edi",
                        "ebp",
                        "esp",
                        "rax",
                        "rbx",
                        "rcx",
                        "rdx",
                        "rsi",
                        "rdi",
                        "rbp",
                        "rsp",
                        "r8",
                        "r9",
                        "r10",
                        "r11",
                        "r12",
                        "r13",
                        "r14",
                        "r15",
                    }:
                        used.add(reg)

        return used

    def _get_new_version(self, reg_name: str) -> int:
        """Get a new SSA version for a register."""
        if reg_name not in self._version_counter:
            self._version_counter[reg_name] = 0
        else:
            self._version_counter[reg_name] += 1
        return self._version_counter[reg_name]

    def _get_current_version(self, reg_name: str) -> int:
        """Get the current SSA version for a register."""
        return self._version_counter.get(reg_name, 0)

    def get_ssa_variable_at(
        self,
        reg_name: str,
        address: int,
        ssa_blocks: dict[int, SSABlock],
    ) -> SSAVariable | None:
        """
        Get the SSA version of a variable at a specific address.

        Args:
            reg_name: Name of the register
            address: Address to query
            ssa_blocks: SSA blocks dictionary

        Returns:
            SSAVariable or None if not found
        """
        for block_addr, ssa_block in ssa_blocks.items():
            if block_addr <= address:
                if reg_name in ssa_block.definitions:
                    return ssa_block.definitions[reg_name]

        return None

    def get_all_versions(
        self,
        reg_name: str,
        ssa_blocks: dict[int, SSABlock],
    ) -> list[SSAVariable]:
        """
        Get all SSA versions of a register across all blocks.

        Args:
            reg_name: Name of the register
            ssa_blocks: SSA blocks dictionary

        Returns:
            List of all SSAVariable versions
        """
        versions: list[SSAVariable] = []
        seen_versions: set[int] = set()

        for ssa_block in ssa_blocks.values():
            if reg_name in ssa_block.definitions:
                ssa_var = ssa_block.definitions[reg_name]
                if ssa_var.version not in seen_versions:
                    versions.append(ssa_var)
                    seen_versions.add(ssa_var.version)

        return sorted(versions, key=lambda v: v.version)

    def compute_live_variables_ssa(
        self,
        ssa_blocks: dict[int, SSABlock],
    ) -> dict[int, tuple[set[SSAVariable], set[SSAVariable]]]:
        """
        Compute live-in and live-out variables in SSA form.

        Args:
            ssa_blocks: SSA blocks dictionary

        Returns:
            Dictionary mapping block address to (live_in, live_out)
        """
        live_info: dict[int, tuple[set[SSAVariable], set[SSAVariable]]] = {}

        for block_addr, ssa_block in ssa_blocks.items():
            used = set()
            defined = set()

            for instruction in ssa_block.instructions:
                disasm = instruction.get("disasm", "").lower()
                used.update(self._extract_used_registers(disasm))
                defined.update(self._extract_defined_registers(disasm))

            for phi in ssa_block.phi_functions:
                for operand in phi.operands:
                    used.add(operand)
                defined.add(phi.result)

            live_out: set[SSAVariable] = set()
            live_in: set[SSAVariable] = set()

            for reg in used:
                version = self._get_current_version(reg)
                live_in.add(SSAVariable(base_name=reg, version=version))

            live_info[block_addr] = (live_in, live_out)

        changed = True
        max_iterations = 100
        iteration = 0

        while changed and iteration < max_iterations:
            changed = False
            iteration += 1

            for block_addr, ssa_block in ssa_blocks.items():
                live_in, live_out = live_info[block_addr]

                for succ_addr in ssa_block.successors:
                    if succ_addr in live_info:
                        succ_live_in, _ = live_info[succ_addr]
                        for ssa_var in succ_live_in:
                            if ssa_var not in live_out:
                                live_out.add(ssa_var)
                                changed = True

        return live_info
