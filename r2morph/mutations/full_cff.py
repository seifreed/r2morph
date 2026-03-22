"""
Full Control Flow Flattening with Dispatcher Pattern.

This module implements the complete dispatcher-based control flow flattening:

Original:
    if (cond) { A(); } else { B(); }
    C();

Flattened:
    state = INITIAL
    while (state != EXIT):
        switch (state):
            case INITIAL: state = cond ? STATE_A : STATE_B; break
            case STATE_A: A(); state = STATE_C; break
            case STATE_B: B(); state = STATE_C; break
            case STATE_C: C(); state = EXIT; break

This transformation makes control flow analysis much harder.
"""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from r2morph.core.constants import MINIMUM_FUNCTION_SIZE

if TYPE_CHECKING:
    from r2morph.protocols import BinaryAccessProtocol
from r2morph.mutations.base import MutationPass
from r2morph.analysis.cfg import CFGBuilder, ControlFlowGraph, BasicBlock, BlockType
from r2morph.relocations.cave_injector import CodeCaveInjector, CaveCreationOptions

logger = logging.getLogger(__name__)


class DispatcherType(Enum):
    """Type of dispatcher implementation."""

    SWITCH_TABLE = "switch_table"
    INDIRECT_JUMP = "indirect_jump"
    STATE_MACHINE = "state_machine"


@dataclass
class DispatcherBlock:
    """Dispatcher block information."""

    state_value: int
    block_address: int
    block_size: int
    successor_states: list[int] = field(default_factory=list)
    is_entry: bool = False
    is_exit: bool = False


@dataclass
class CFFConfig:
    """Configuration for control flow flattening."""

    dispatcher_type: DispatcherType = DispatcherType.SWITCH_TABLE
    state_size: int = 4
    randomize_states: bool = True
    use_opaque_predicates: bool = True
    create_new_section: bool = False
    max_functions: int = 3
    min_blocks: int = 3
    probability: float = 0.5


class FullControlFlowFlatteningPass(MutationPass):
    """
    Full control flow flattening with dispatcher pattern.

    This pass transforms natural control flow into a dispatcher-based
    state machine, making reverse engineering significantly more difficult.

    Features:
    - State table generation
    - Dispatcher block creation
    - Block randomization
    - Opaque predicate integration
    - Support for switch table and indirect jump dispatchers
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(name="FullControlFlowFlattening", config=config)
        self.cff_config = CFFConfig(
            dispatcher_type=DispatcherType(self.config.get("dispatcher_type", "switch_table")),
            state_size=self.config.get("state_size", 4),
            randomize_states=self.config.get("randomize_states", True),
            use_opaque_predicates=self.config.get("use_opaque_predicates", True),
            create_new_section=self.config.get("create_new_section", False),
            max_functions=self.config.get("max_functions", 3),
            min_blocks=self.config.get("min_blocks", 3),
            probability=self.config.get("probability", 0.5),
        )

    def apply(self, binary: Any) -> dict[str, Any]:
        """Apply full control flow flattening."""
        if not binary.is_analyzed():
            logger.warning("Binary not analyzed, analyzing now...")
            binary.analyze()

        functions = binary.get_functions()
        total_mutations = 0
        funcs_mutated = 0
        dispatchers_created = 0
        blocks_flattened = 0

        arch_info = binary.get_arch_info()
        arch = arch_info.get("arch", "")
        bits = arch_info.get("bits", 64)

        cfg_builder = CFGBuilder(binary)
        cave_injector = CodeCaveInjector(binary)

        candidates = self._select_candidates(binary, functions)

        for func in candidates[: self.cff_config.max_functions]:
            if random.random() > self.cff_config.probability:
                continue

            func_addr = func.get("offset", func.get("addr", 0))
            func_name = func.get("name", f"0x{func_addr:x}")

            try:
                cfg = cfg_builder.build_cfg(func_addr, func_name)
            except Exception as e:
                logger.debug(f"Failed to build CFG for {func_name}: {e}")
                continue

            if len(cfg.blocks) < self.cff_config.min_blocks:
                continue

            result = self._flatten_function_cff(binary, cfg, cave_injector, arch, bits)

            if result:
                funcs_mutated += 1
                total_mutations += result.get("total_mutations", 0)
                dispatchers_created += result.get("dispatchers", 0)
                blocks_flattened += result.get("blocks_flattened", 0)

        logger.info(
            f"Full CFF: {funcs_mutated} functions flattened, "
            f"{dispatchers_created} dispatchers, {blocks_flattened} blocks"
        )

        return {
            "mutations_applied": total_mutations,
            "functions_mutated": funcs_mutated,
            "dispatchers_created": dispatchers_created,
            "blocks_flattened": blocks_flattened,
            "total_functions": len(functions),
        }

    def _select_candidates(self, binary: Any, functions: list[dict]) -> list[dict]:
        """Select candidate functions for CFF."""
        candidates = []

        for func in functions:
            func_addr = func.get("offset", func.get("addr", 0))
            func_size = func.get("size", 0)
            func_name = func.get("name", "")

            if func_size < MINIMUM_FUNCTION_SIZE:
                continue

            if func_name.startswith("sym.imp.") or func_name.startswith("sub."):
                continue

            try:
                blocks = binary.get_basic_blocks(func_addr)
                if len(blocks) >= self.cff_config.min_blocks:
                    func["_block_count"] = len(blocks)
                    candidates.append(func)
            except Exception:
                continue

        candidates.sort(key=lambda f: f.get("_block_count", 0), reverse=True)
        return candidates

    def _flatten_function_cff(
        self,
        binary: Any,
        cfg: ControlFlowGraph,
        cave_injector: CodeCaveInjector,
        arch: str,
        bits: int,
    ) -> dict[str, int] | None:
        """
        Flatten a function using full dispatcher-based CFF.

        Steps:
        1. Assign state values to each basic block
        2. Generate dispatcher code
        3. Patch block transitions to use state variable
        4. Insert dispatcher code
        """
        blocks = list(cfg.blocks.values())
        if len(blocks) < self.cff_config.min_blocks:
            return None

        dispatcher_blocks = self._create_dispatcher_blocks(cfg)
        if not dispatcher_blocks:
            return None

        state_table = self._generate_state_table(dispatcher_blocks)
        dispatcher_code = self._generate_dispatcher_code(state_table, arch, bits, cfg.function_address)

        if not dispatcher_code:
            return None

        code_bytes = self._assemble_dispatcher(binary, dispatcher_code)
        if not code_bytes:
            return None

        allocation = cave_injector.insert_code(
            code_bytes,
            allow_section_creation=self.cff_config.create_new_section,
        )

        if not allocation:
            logger.warning("Could not allocate space for dispatcher")
            return None

        dispatcher_addr = allocation.address

        patched = self._patch_function_blocks(binary, cfg, dispatcher_blocks, state_table, dispatcher_addr)

        return {
            "total_mutations": patched,
            "dispatchers": 1,
            "blocks_flattened": len(dispatcher_blocks),
        }

    def _create_dispatcher_blocks(self, cfg: ControlFlowGraph) -> list[DispatcherBlock]:
        """Create dispatcher blocks from CFG."""
        blocks = []
        state_counter = 0
        state_mapping: dict[int, int] = {}

        entry_block = cfg.entry_block
        if not entry_block:
            return []

        sorted_blocks = sorted(cfg.blocks.values(), key=lambda b: b.address)

        for block in sorted_blocks:
            state_mapping[block.address] = state_counter

            dispatcher_block = DispatcherBlock(
                state_value=state_counter,
                block_address=block.address,
                block_size=block.size,
                is_entry=(block == entry_block),
                is_exit=(len(block.successors) == 0),
            )

            blocks.append(dispatcher_block)
            state_counter += 1

        for block in sorted_blocks:
            current_state = state_mapping[block.address]
            for succ_addr in block.successors:
                if succ_addr in state_mapping:
                    blocks[current_state].successor_states.append(state_mapping[succ_addr])

        return blocks

    def _generate_state_table(self, dispatcher_blocks: list[DispatcherBlock]) -> dict[int, tuple[int, int | None]]:
        """
        Generate state transition table.

        Returns:
            Dict mapping state -> (next_state_true, next_state_false)
        """
        state_table = {}

        for db in dispatcher_blocks:
            if db.is_exit:
                state_table[db.state_value] = (-1, None)
            elif len(db.successor_states) == 1:
                state_table[db.state_value] = (db.successor_states[0], None)
            elif len(db.successor_states) == 2:
                state_table[db.state_value] = (
                    db.successor_states[0],
                    db.successor_states[1],
                )

        return state_table

    def _generate_dispatcher_code(
        self,
        state_table: dict[int, tuple[int, int | None]],
        arch: str,
        bits: int,
        func_addr: int,
    ) -> list[str] | None:
        """Generate assembly code for the dispatcher."""
        instructions = []

        if arch not in ("x86", "x86_64", "arm", "arm64"):
            logger.warning(f"Unsupported architecture for CFF: {arch}")
            return None

        if arch in ("x86", "x86_64"):
            instructions = self._generate_x86_dispatcher(state_table, bits)
        elif arch in ("arm", "arm64"):
            instructions = self._generate_arm_dispatcher(state_table, bits)

        return instructions

    def _generate_x86_dispatcher(
        self,
        state_table: dict[int, tuple[int, int | None]],
        bits: int,
    ) -> list[str]:
        """Generate x86/x86_64 dispatcher code."""
        instructions = []
        reg = "eax" if bits == 32 else "rax"

        state_values = sorted(state_table.keys())
        if not state_values:
            return []

        initial_state = state_values[0]

        instructions.extend(
            [
                f"mov {reg}, {initial_state}",
                "dispatcher_loop:",
            ]
        )

        for state in state_values:
            next_true, next_false = state_table[state]

            instructions.append(f"cmp {reg}, {state}")
            instructions.append("jne .+8")

            if next_false is not None:
                instructions.append(f"mov {reg}, {next_true}")
                instructions.append("jmp dispatcher_loop")
                instructions.append(f"mov {reg}, {next_false}")
                instructions.append("jmp dispatcher_loop")
            else:
                if next_true == -1:
                    instructions.append("ret")
                else:
                    instructions.append(f"mov {reg}, {next_true}")
                    instructions.append("jmp dispatcher_loop")

        instructions.append("dispatcher_end:")

        return instructions

    def _generate_arm_dispatcher(
        self,
        state_table: dict[int, tuple[int, int | None]],
        bits: int,
    ) -> list[str]:
        """Generate ARM/ARM64 dispatcher code."""
        instructions = []
        reg = "r0" if bits == 32 else "x0"

        state_values = sorted(state_table.keys())
        if not state_values:
            return []

        initial_state = state_values[0]

        instructions.append(f"mov {reg}, #{initial_state}")
        instructions.append("dispatcher_loop:")

        for state in state_values:
            next_true, next_false = state_table[state]

            instructions.append(f"cmp {reg}, #{state}")
            instructions.append("bne .+12")

            if next_false is not None:
                instructions.append(f"mov {reg}, #{next_true}")
                instructions.append("b dispatcher_loop")
                instructions.append(f"mov {reg}, #{next_false}")
                instructions.append("b dispatcher_loop")
            else:
                if next_true == -1:
                    instructions.append("bx lr")
                else:
                    instructions.append(f"mov {reg}, #{next_true}")
                    instructions.append("b dispatcher_loop")

        return instructions

    def _assemble_dispatcher(self, binary: Any, instructions: list[str]) -> bytes | None:
        """
        Assemble dispatcher instructions into bytes.

        Args:
            binary: Any instance for assembly
            instructions: List of assembly instructions

        Returns:
            Assembled bytes or None if assembly fails
        """
        assembled = b""
        failures = []

        for insn in instructions:
            try:
                insn_bytes = binary.assemble(insn)
                if insn_bytes:
                    assembled += insn_bytes
                else:
                    failures.append(insn)
            except Exception as e:
                failures.append(f"{insn}: {e}")
                logger.debug(f"Failed to assemble '{insn}': {e}")

        if failures:
            logger.warning(
                f"Failed to assemble {len(failures)} dispatcher instructions: {failures[:5]}"
                + ("..." if len(failures) > 5 else "")
            )

        return assembled if assembled else None

    def _patch_function_blocks(
        self,
        binary: Any,
        cfg: ControlFlowGraph,
        dispatcher_blocks: list[DispatcherBlock],
        state_table: dict[int, tuple[int, int | None]],
        dispatcher_addr: int,
    ) -> int:
        """Patch function blocks to jump to dispatcher."""
        patches_applied = 0
        func_addr = cfg.function_address

        mutation_checkpoint = self._create_mutation_checkpoint("full_cff")
        baseline = {}
        if self._validation_manager is not None:
            baseline = self._validation_manager.capture_structural_baseline(binary, func_addr)

        for db in dispatcher_blocks:
            if db.is_exit:
                continue

            block_addr = db.block_address

            try:
                block_instrs = binary.get_function_disasm(func_addr)
                block_end = None

                for insn in block_instrs:
                    insn_addr = insn.get("offset", 0)
                    if insn_addr >= block_addr and insn_addr < block_addr + db.block_size:
                        if insn_addr + insn.get("size", 0) > block_addr + db.block_size:
                            block_end = insn_addr
                            break
                        block_end = insn_addr + insn.get("size", 0)

                if block_end:
                    jump_target = dispatcher_addr
                    arch_info = binary.get_arch_info()
                    arch = arch_info.get("arch", "")
                    bits = arch_info.get("bits", 64)

                    if arch in ("x86", "x86_64"):
                        rel_offset = jump_target - (block_end + 5)
                        if rel_offset < -2147483648 or rel_offset > 2147483647:
                            logger.debug(f"Jump offset out of range for block at 0x{block_addr:x}")
                            continue
                        jmp_bytes = b"\xe9" + rel_offset.to_bytes(4, "little", signed=True)

                        original_bytes = binary.read_bytes(block_end, 5)
                        if binary.write_bytes(block_end, jmp_bytes):
                            if original_bytes:
                                self._record_mutation(
                                    function_address=func_addr,
                                    start_address=block_end,
                                    end_address=block_end + 4,
                                    original_bytes=original_bytes,
                                    mutated_bytes=jmp_bytes,
                                    original_disasm="original_block_end",
                                    mutated_disasm=f"jmp 0x{jump_target:x}",
                                    mutation_kind="full_cff",
                                    metadata={
                                        "block_addr": block_addr,
                                        "dispatcher_addr": dispatcher_addr,
                                        "structural_baseline": baseline,
                                    },
                                )
                            patches_applied += 1

            except Exception as e:
                logger.debug(f"Failed to patch block at 0x{block_addr:x}: {e}")

        if patches_applied > 0 and self._validation_manager is not None and mutation_checkpoint is not None:
            if self._records:
                outcome = self._validation_manager.validate_mutation(binary, self._records[-1].to_dict())
                if not outcome.passed:
                    if self._session is not None:
                        self._session.rollback_to(mutation_checkpoint)
                    binary.reload()
                    if self._records:
                        self._records.pop()
                    if self._rollback_policy == "fail-fast":
                        raise RuntimeError("Mutation-level validation failed")
                    return 0

        return patches_applied
