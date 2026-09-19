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
import re
from dataclasses import dataclass
from typing import Any

from r2morph.analysis.call_effects import call_register_effects, return_register_effects
from r2morph.analysis.dataflow_models import Register, register_definition_covers_use
from r2morph.analysis.flag_effects import FLAGS_RESOURCE_NAME, flag_accesses
from r2morph.analysis.liveness_models import _X86_REGISTER_BIT_SIZES
from r2morph.analysis.memory_effects import MEMORY_RESOURCE_NAME, memory_accesses, stack_pointer_registers
from r2morph.analysis.ssa_models import PhiFunction, SSABlock, SSAVariable

logger = logging.getLogger(__name__)

_MIN_PHI_PREDECESSORS = 2
_MIN_OPERAND_COUNT = 2
_SSA_REGISTER_NAMES = frozenset(
    {
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
    }
)
_RMW_MNEMONICS = frozenset(
    {
        "adc",
        "add",
        "and",
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
        "xadd",
        "xchg",
        "xor",
    }
)
_SSA_VECTOR_REGISTER_NAMES = frozenset(register for index in range(16) for register in (f"xmm{index}", f"ymm{index}"))
_SSA_READ_BOTH_OPERANDS_MNEMONICS = _RMW_MNEMONICS | {"cmp", "test"}


@dataclass
class _RenameFrame:
    """One in-progress _rename_in_block() recursion, simulated on a stack."""

    block_addr: int
    successors: list[int]
    idx: int = 0


class SSAConverter:
    """
    Convert control flow graphs to SSA form.

    Uses standard SSA construction algorithm:
    1. Insert phi functions at join points
    2. Rename variables with versions
    3. Propagate definitions through dominance frontier
    """

    def __init__(self, abi: str = "sysv_amd64") -> None:
        self._abi = abi
        self._version_counter: dict[str, int] = {}
        self._current_def: dict[str, list[SSAVariable]] = {}
        self._instruction_definitions: dict[int, dict[str, list[SSAVariable]]] = {}
        self._sealed_blocks: set[int] = set()
        self._incomplete_phis: dict[int, list[tuple[str, SSAVariable]]] = {}

    def convert_to_ssa(
        self,
        blocks: dict[int, dict[str, Any]],
    ) -> dict[int, SSABlock]:
        """
        Convert a CFG to SSA form.

        Each block carries its own ``predecessors``/``successors``, which is
        the only control-flow topology the construction reads.

        Args:
            blocks: Dictionary mapping addresses to block info

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
        self._instruction_definitions.clear()
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
        """Place phi functions at the iterated dominance frontier of each
        variable's definition sites (Cytron et al. SSA construction).

        Runs before renaming, so definition sites are recovered by scanning
        each block's instructions rather than from the post-rename
        ``definitions`` map (which is still empty at this point). A block
        that receives a phi becomes a new definition site, so the frontier
        is iterated via a worklist until it stabilises.
        """
        dominance_frontier = self._compute_dominance_frontier(ssa_blocks)

        defsites: dict[str, set[int]] = {}
        for block_addr, ssa_block in ssa_blocks.items():
            for reg in self._block_defined_registers(ssa_block):
                defsites.setdefault(reg, set()).add(block_addr)

        for reg, sites in defsites.items():
            blocks_with_phi: set[int] = set()
            worklist = list(sites)
            while worklist:
                block_addr = worklist.pop()
                for frontier_addr in dominance_frontier.get(block_addr, set()):
                    if frontier_addr in blocks_with_phi:
                        continue
                    frontier_block = ssa_blocks.get(frontier_addr)
                    if frontier_block is None:
                        continue
                    frontier_block.phi_functions.append(
                        self._create_phi_function(reg, frontier_addr, frontier_block.predecessors)
                    )
                    blocks_with_phi.add(frontier_addr)
                    if frontier_addr not in sites:
                        worklist.append(frontier_addr)

    def _block_defined_registers(self, ssa_block: SSABlock) -> set[str]:
        """Registers written by any instruction in the block."""
        defined: set[str] = set()
        for instruction in ssa_block.instructions:
            defined |= self._extract_defined_registers(instruction.get("disasm", "").lower())
        return defined

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
            if len(ssa_block.predecessors) >= _MIN_PHI_PREDECESSORS:
                for pred_addr in ssa_block.predecessors:
                    runner: int | None = pred_addr
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
        for _pred_addr in predecessor_addrs:
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
        """Rename variables in a block using DFS traversal.

        An explicit stack replaces the interpreter call stack so deep
        control-flow graphs no longer raise RecursionError. Each block is
        renamed once; phi functions represent values merged at shared
        successors, so reprocessing a diamond once per incoming path only
        increases cost and corrupts version ordering.
        """
        root_block = self._enter_block(ssa_blocks, block_addr, visited)
        if root_block is None:
            return

        stack: list[_RenameFrame] = [_RenameFrame(block_addr, list(root_block.successors))]
        while stack:
            frame = stack[-1]
            if frame.idx < len(frame.successors):
                succ_addr = frame.successors[frame.idx]
                frame.idx += 1
                child = self._enter_block(ssa_blocks, succ_addr, visited)
                if child is not None:
                    stack.append(_RenameFrame(succ_addr, list(child.successors)))
            else:
                stack.pop()

    def _enter_block(
        self,
        ssa_blocks: dict[int, SSABlock],
        block_addr: int,
        visited: set[int],
    ) -> SSABlock | None:
        """Mirror the entry of the recursive _rename_in_block().

        Returns the block to descend into, or None when the recursive
        version would have returned immediately. A block whose SSABlock is
        missing remains marked visited, and an already-visited block is
        skipped without reprocessing.
        """
        if block_addr in visited:
            return None

        visited.add(block_addr)
        ssa_block = ssa_blocks.get(block_addr)

        if not ssa_block:
            return None

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

        return ssa_block

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
            variable = self._find_alias_definition(ssa_block.definitions, reg)
            if variable is None:
                version = self._get_current_version(reg)
                variable = SSAVariable(
                    base_name=reg,
                    version=version,
                )
            ssa_block.definitions[reg] = variable

        for reg in defined_regs:
            self._remove_overwritten_definitions(ssa_block.definitions, reg)
            version = self._get_new_version(reg)
            variable = SSAVariable(
                base_name=reg,
                version=version,
                definition_address=instruction.get("offset", 0),
            )
            ssa_block.definitions[reg] = variable
            self._instruction_definitions.setdefault(ssa_block.address, {}).setdefault(reg, []).append(variable)

    @staticmethod
    def _register(register_name: str) -> Register:
        """Build a register value with the width used by alias analysis."""
        return Register(register_name, _X86_REGISTER_BIT_SIZES.get(register_name, 64))

    @classmethod
    def _definition_covers_use(cls, definition: str, use: str) -> bool:
        """Return whether an SSA definition supplies a complete register use."""
        return register_definition_covers_use(cls._register(definition), cls._register(use))

    @classmethod
    def _find_alias_definition(
        cls,
        definitions: dict[str, SSAVariable],
        register_name: str,
    ) -> SSAVariable | None:
        """Find the most specific active definition that covers a register use."""
        exact = definitions.get(register_name)
        if exact is not None:
            return exact

        candidates = [
            (name, variable)
            for name, variable in definitions.items()
            if cls._definition_covers_use(name, register_name)
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda item: cls._register(item[0]).size)[1]

    @classmethod
    def _remove_overwritten_definitions(
        cls,
        definitions: dict[str, SSAVariable],
        definition_name: str,
    ) -> None:
        """Drop aliases fully replaced by a new register definition."""
        overwritten = [name for name in definitions if cls._definition_covers_use(definition_name, name)]
        for name in overwritten:
            del definitions[name]

    def _extract_defined_registers(self, disasm: str) -> set[str]:
        """Extract registers that are defined (written to) in an instruction."""
        opcode, _, operands = disasm.partition(" ")
        mnemonic = opcode.lower()
        if mnemonic == "call":
            _, call_defined = call_register_effects(self._abi)
            return {register for register, _ in call_defined} | {
                FLAGS_RESOURCE_NAME,
                MEMORY_RESOURCE_NAME,
            }
        destination = operands.split(",", 1)[0].strip().lower()
        defined: set[str] = set()
        defined.update(register for register, _ in stack_pointer_registers(disasm, self._abi, write=True))
        if destination in _SSA_REGISTER_NAMES | _SSA_VECTOR_REGISTER_NAMES and (
            mnemonic in {"lea", "mov", "pop"}
            or mnemonic in _RMW_MNEMONICS
            or mnemonic.startswith("cmov")
            or mnemonic.startswith("set")
        ):
            defined.add(destination)
        if mnemonic in {"cmp", "test"}:
            defined.discard(destination)
        if flag_accesses(disasm)[1]:
            defined.add(FLAGS_RESOURCE_NAME)
        if memory_accesses(disasm)[1]:
            defined.add(MEMORY_RESOURCE_NAME)
        return defined

    def _extract_used_registers(self, disasm: str) -> set[str]:
        """Extract registers that are used (read from) in an instruction."""
        opcode, _, operands_text = disasm.partition(" ")
        mnemonic = opcode.lower()
        if mnemonic == "ret":
            return {register for register, _ in return_register_effects(self._abi)} | {
                register for register, _ in stack_pointer_registers(disasm, self._abi, read=True)
            }
        if mnemonic == "call":
            call_used, _ = call_register_effects(self._abi)
            call_used_names = {register for register, _ in call_used}
            call_used_names.update(
                match.group(1)
                for match in re.finditer(r"\b([a-z][a-z0-9]*)\b", operands_text.lower())
                if match.group(1) in _SSA_REGISTER_NAMES | _SSA_VECTOR_REGISTER_NAMES
            )
            call_used_names.add(MEMORY_RESOURCE_NAME)
            call_used_names.update(register for register, _ in stack_pointer_registers(disasm, self._abi, read=True))
            return call_used_names
        operands = [operand.strip() for operand in operands_text.split(",")] if operands_text else []
        used: set[str] = set()
        used.update(register for register, _ in stack_pointer_registers(disasm, self._abi, read=True))
        if memory_accesses(disasm)[0]:
            used.add(MEMORY_RESOURCE_NAME)
        if not operands:
            if flag_accesses(disasm)[0]:
                used.add(FLAGS_RESOURCE_NAME)
            return used

        source_operands = operands[1:] if len(operands) >= _MIN_OPERAND_COUNT else []
        if operands[0].startswith("[") or mnemonic in _SSA_READ_BOTH_OPERANDS_MNEMONICS or mnemonic.startswith("cmov"):
            source_operands = operands
        for operand in source_operands:
            used.update(
                match.group(1)
                for match in re.finditer(r"\b([a-z][a-z0-9]*)\b", operand.lower())
                if match.group(1) in _SSA_REGISTER_NAMES | _SSA_VECTOR_REGISTER_NAMES
            )
        if flag_accesses(disasm)[0]:
            used.add(FLAGS_RESOURCE_NAME)
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
        latest_address: int | None = None
        latest_variable: SSAVariable | None = None
        for block_addr, ssa_block in ssa_blocks.items():
            variable = self._find_alias_definition(ssa_block.definitions, reg_name)
            if (
                variable is not None
                and block_addr <= address
                and (latest_address is None or block_addr > latest_address)
            ):
                latest_address = block_addr
                latest_variable = variable
        return latest_variable

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
            ssa_var = self._find_alias_definition(ssa_block.definitions, reg_name)
            if ssa_var is not None and ssa_var.version not in seen_versions:
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
        live_info = self._seed_block_liveness(ssa_blocks)
        self._propagate_liveness(ssa_blocks, live_info)
        for block_addr, (live_in, live_out) in live_info.items():
            ssa_blocks[block_addr].live_in = live_in.copy()
            ssa_blocks[block_addr].live_out = live_out.copy()
        return live_info

    def _seed_block_liveness(
        self,
        ssa_blocks: dict[int, SSABlock],
    ) -> dict[int, tuple[set[SSAVariable], set[SSAVariable]]]:
        """Seed each block's live-in from uses that precede local definitions.

        Phi operands are edge uses and are added while propagating successor
        liveness, rather than being treated as uses in the phi block itself.
        """
        live_info: dict[int, tuple[set[SSAVariable], set[SSAVariable]]] = {}
        dominators = self._compute_dominators(ssa_blocks)

        for block_addr, ssa_block in ssa_blocks.items():
            used: set[str] = set()
            defined: set[str] = set()
            first_use_addresses: dict[str, int] = {}
            for instruction in ssa_block.instructions:
                disasm = instruction.get("disasm", "").lower()
                for register in self._extract_used_registers(disasm):
                    if register not in defined:
                        used.add(register)
                        first_use_addresses.setdefault(register, int(instruction.get("offset", block_addr)))
                defined.update(self._extract_defined_registers(disasm))

            live_in: set[SSAVariable] = set()
            for reg in used:
                version = self._resolve_live_version(
                    reg,
                    block_addr,
                    first_use_addresses[reg],
                    ssa_blocks,
                    dominators,
                )
                live_in.add(SSAVariable(base_name=reg, version=version))

            live_info[block_addr] = (live_in, set())

        return live_info

    def _resolve_live_version(
        self,
        register: str,
        block_addr: int,
        use_address: int,
        ssa_blocks: dict[int, SSABlock],
        dominators: dict[int, set[int]],
    ) -> int:
        """Resolve the definition that dominates a block's first use."""
        candidates: list[tuple[int, int, int, int]] = []
        for definition_block_addr, definition_block in ssa_blocks.items():
            if definition_block_addr not in dominators.get(block_addr, {block_addr}):
                continue
            instruction_definitions = self._instruction_definitions.get(definition_block_addr, {})
            for definition_name, definition_variables in instruction_definitions.items():
                if not self._definition_covers_use(definition_name, register):
                    continue
                for variable in definition_variables:
                    if variable.definition_address is not None and variable.definition_address <= use_address:
                        candidates.append(
                            (
                                len(dominators.get(definition_block_addr, set())),
                                variable.definition_address,
                                definition_block_addr,
                                variable.version,
                            )
                        )
            for definition_name, final_variable in definition_block.definitions.items():
                if (
                    self._definition_covers_use(definition_name, register)
                    and final_variable.definition_address is not None
                    and final_variable.definition_address <= use_address
                ):
                    candidates.append(
                        (
                            len(dominators.get(definition_block_addr, set())),
                            final_variable.definition_address,
                            definition_block_addr,
                            final_variable.version,
                        )
                    )
        if candidates:
            return max(candidates)[3]
        return self._get_current_version(register)

    def _propagate_liveness(
        self,
        ssa_blocks: dict[int, SSABlock],
        live_info: dict[int, tuple[set[SSAVariable], set[SSAVariable]]],
    ) -> None:
        """Solve block liveness with the standard backward transfer function."""
        block_use = {block_addr: live_in.copy() for block_addr, (live_in, _) in live_info.items()}
        changed = True
        while changed:
            changed = False
            for block_addr, ssa_block in reversed(tuple(ssa_blocks.items())):
                old_live_in, old_live_out = live_info[block_addr]
                new_live_out: set[SSAVariable] = set()
                for successor_addr in ssa_block.successors:
                    successor = ssa_blocks.get(successor_addr)
                    successor_live_in = live_info.get(successor_addr, (set(), set()))[0]
                    new_live_out.update(successor_live_in)
                    if successor is not None and block_addr in successor.predecessors:
                        predecessor_index = successor.predecessors.index(block_addr)
                        for phi in successor.phi_functions:
                            if predecessor_index < len(phi.operands):
                                new_live_out.add(phi.operands[predecessor_index])

                defined = {
                    variable.base_name
                    for variable in ssa_block.definitions.values()
                    if variable.definition_address is not None
                }
                defined.update(phi.result.base_name for phi in ssa_block.phi_functions)
                new_live_in = block_use[block_addr] | {
                    variable for variable in new_live_out if variable.base_name not in defined
                }

                if new_live_in != old_live_in or new_live_out != old_live_out:
                    live_info[block_addr] = (new_live_in, new_live_out)
                    changed = True
