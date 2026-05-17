"""
Control flow flattening mutation pass.

Transforms structured control flow into a dispatcher-based flat structure,
making reverse engineering significantly harder by obscuring the original
program logic.

Control Flow Flattening (CFF) Overview:
---------------------------------------
Control flow flattening is an obfuscation technique that transforms a program's
control flow graph (CFG) from its natural hierarchical structure into a flat
dispatcher-based structure. This technique is widely used in:

- Commercial obfuscators (VMProtect, Themida, OLLVM)
- Malware to hinder analysis
- Software protection to impede reverse engineering

The Dispatcher Pattern:
-----------------------
The core idea is to replace direct control flow (jumps, branches) with indirect
control flow mediated by a state variable and dispatcher loop:

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

Why This Hinders Analysis:
--------------------------
1. Static Analysis: CFG recovery becomes difficult as all blocks appear to
   have edges to all other blocks through the dispatcher
2. Pattern Recognition: Standard decompiler patterns for if/else, loops,
   etc. are destroyed
3. Symbolic Execution: State explosion due to the switch construct
4. Data Flow: The state variable creates artificial dependencies

Research Applications:
----------------------
This module is useful for:
- Studying obfuscation techniques and their effectiveness
- Developing deobfuscation strategies
- Understanding metamorphic transformation patterns
- Testing binary analysis tool resilience

Implementation Notes:
---------------------
This implementation uses a simplified approach that works within existing
function space (doesn't expand the binary):

1. Adds opaque predicates before conditional branches - these are conditions
   that always evaluate the same way but are hard for static analysis to
   determine (e.g., x*x >= 0 is always true for integers)

2. Inserts jump redirections that add indirection to control flow

3. Reorders blocks and patches jumps to obscure the original structure

This approach is similar to block_reordering.py but focuses on adding
complexity through opaque predicates and jump obfuscation rather than
simple block reordering.
"""

from __future__ import annotations

import logging
import random
from typing import Any

from r2morph.core.constants import MINIMUM_FUNCTION_SIZE
from r2morph.mutations.base import MutationPass
from r2morph.mutations.cff_dispatcher import DispatcherGenerator
from r2morph.mutations.cff_jump_obfuscator import JumpObfuscator
from r2morph.mutations.cff_opaque_predicates import OpaquePredicateGenerator
from r2morph.utils.dead_code import (
    generate_arm_dead_code_for_size,
    generate_nop_sequence,
    generate_x86_dead_code_for_size,
)

logger = logging.getLogger(__name__)

# Conditional jump / branch mnemonics, indexed by architecture family.
_X86_CONDITIONAL_JUMPS = frozenset(
    {
        "je",
        "jne",
        "jz",
        "jnz",
        "ja",
        "jae",
        "jb",
        "jbe",
        "jg",
        "jge",
        "jl",
        "jle",
        "jo",
        "jno",
        "js",
        "jns",
        "jp",
        "jnp",
        "jcxz",
        "jecxz",
        "jrcxz",
    }
)

_ARM_CONDITIONAL_BRANCHES = frozenset(
    {
        "beq",
        "bne",
        "bcs",
        "bcc",
        "bmi",
        "bpl",
        "bvs",
        "bvc",
        "bhi",
        "bls",
        "bge",
        "blt",
        "bgt",
        "ble",
        "b.eq",
        "b.ne",
        "b.cs",
        "b.cc",
        "b.mi",
        "b.pl",
        "b.vs",
        "b.vc",
        "b.hi",
        "b.ls",
        "b.ge",
        "b.lt",
        "b.gt",
        "b.le",
        "cbz",
        "cbnz",
    }
)


class ControlFlowFlatteningPass(MutationPass):
    """
    Flattens control flow using opaque predicates and jump obfuscation.

    This mutation pass analyzes binary functions and applies control flow
    obfuscation techniques that hinder reverse engineering. Unlike full
    dispatcher-based flattening, this implementation works within existing
    function space using:

    1. Opaque Predicates: Conditions that always evaluate the same way but
       are hard to determine statically. Example: (x * x) >= 0 is always
       true for integers, but requires symbolic execution to prove.

    2. Jump Obfuscation: Adds indirection to jumps by inserting intermediate
       jump points or converting direct jumps to indirect calculations.

    3. Block Reordering with Fixups: Reorders blocks and patches control flow
       to obscure the original program structure.

    Transformation Techniques:
        - Insert opaque predicates before conditional branches
        - Add dead code paths that can never be taken
        - Create jump chains that obscure direct control flow
        - Modify branch targets to add indirection

    Configuration Options:
        max_functions_to_flatten: Maximum number of functions to process (default: 5)
        min_blocks_required: Minimum basic blocks for flattening (default: 3)
        probability: Probability of applying transformation (default: 0.5)
        opaque_predicate_density: How many predicates per function (default: 3)

    Research Applications:
        - Studying obfuscation effectiveness against analysis tools
        - Testing deobfuscation and symbolic execution engines
        - Understanding commercial protector techniques
        - Benchmarking disassembler and decompiler resilience

    Attributes:
        max_functions: Maximum functions to flatten per run
        min_blocks: Minimum basic block count threshold
        probability: Probability of applying to each candidate function
        opaque_density: Number of opaque predicates to insert per function

    See Also:
        - CFGBuilder: Used for control flow graph construction
        - BasicBlock: Represents individual basic blocks in the CFG
        - BlockReorderingPass: Related mutation that reorders blocks
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize control flow flattening pass.

        Args:
            config: Configuration dictionary
        """
        super().__init__(name="ControlFlowFlattening", config=config)
        self._predicate_generator = OpaquePredicateGenerator()
        self._jump_obfuscator = JumpObfuscator()
        self._dispatcher_gen = DispatcherGenerator()
        self.max_functions = self.config.get("max_functions_to_flatten", 5)
        self.min_blocks = self.config.get("min_blocks_required", 3)
        self.probability = self.config.get("probability", 0.5)
        self.opaque_density = self.config.get("opaque_predicate_density", 3)

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply control flow flattening transformations.

        This method:
        1. Selects candidate functions with sufficient complexity
        2. For each function, analyzes the CFG
        3. Inserts opaque predicates at conditional branch points
        4. Adds jump obfuscation to obscure control flow
        5. Tracks and returns mutation statistics

        Args:
            binary: Any to mutate

        Returns:
            Statistics dict with mutation counts and details
        """
        self._reset_random()
        if not binary.is_analyzed():
            logger.warning("Binary not analyzed, analyzing now...")
            binary.analyze()

        logger.info("Applying control flow flattening")

        functions = binary.get_functions()
        total_mutations = 0
        funcs_mutated = 0
        opaque_predicates_added = 0
        jump_obfuscations = 0
        functions_processed = 0

        candidates = self._select_candidates(binary, functions)

        logger.info(
            f"Control flow flattening: {len(candidates)} candidate functions "
            f"(max {self.max_functions}, min_blocks={self.min_blocks})"
        )

        for func in candidates[: self.max_functions]:
            functions_processed += 1

            # Apply probability filter
            if random.random() > self.probability:
                continue

            result = self._flatten_function(binary, func)
            if result:
                funcs_mutated += 1
                total_mutations += result.get("total", 0)
                opaque_predicates_added += result.get("opaque_predicates", 0)
                jump_obfuscations += result.get("jump_obfuscations", 0)

        logger.info(
            f"Control flow flattening complete: {funcs_mutated} functions mutated, "
            f"{opaque_predicates_added} opaque predicates, {jump_obfuscations} jump obfuscations"
        )

        return {
            "mutations_applied": total_mutations,
            "functions_mutated": funcs_mutated,
            "opaque_predicates_added": opaque_predicates_added,
            "jump_obfuscations": jump_obfuscations,
            "total_functions": len(functions),
            "candidates_found": len(candidates),
            "functions_processed": functions_processed,
        }

    def _select_candidates(self, binary: Any, functions: list[dict]) -> list[dict]:
        """
        Select functions suitable for flattening.

        Filters functions based on:
        - Minimum basic block count (need enough blocks to obscure)
        - Function size (too small functions have no room for transformations)
        - Not being an import/thunk (library functions shouldn't be modified)

        Args:
            binary: Any instance
            functions: List of functions

        Returns:
            List of candidate functions sorted by block count (descending)
        """
        candidates = []

        for func in functions:
            func_addr = func.get("offset", func.get("addr", 0))
            func_size = func.get("size", 0)
            func_name = func.get("name", "")

            # Skip tiny functions
            if func_size < MINIMUM_FUNCTION_SIZE:
                continue

            # Skip imports and thunks
            if func_name.startswith("sym.imp.") or func_name.startswith("sub."):
                continue

            try:
                blocks = binary.get_basic_blocks(func_addr)

                if len(blocks) >= self.min_blocks:
                    # Store block count for sorting
                    func["_block_count"] = len(blocks)
                    candidates.append(func)

            except (ValueError, OSError, BrokenPipeError, RuntimeError) as e:
                logger.debug(f"Failed to analyze function 0x{func_addr:x}: {e}")

        # Sort by block count (more blocks = better candidate for obfuscation)
        candidates.sort(key=lambda f: f.get("_block_count", 0), reverse=True)

        return candidates

    def _flatten_function(self, binary: Any, func: dict) -> dict[str, int] | None:
        """
        Apply control flow flattening transformations to a function.

        This method applies several obfuscation techniques:
        1. Opaque predicates before conditional jumps
        2. Jump table obfuscation (converting direct jumps to calculations)
        3. Dead code insertion after unconditional transfers

        The approach works within existing function space by:
        - Finding padding/slack space in blocks
        - Overwriting existing NOPs or dead code
        - Inserting small sequences that fit available space

        Args:
            binary: Any instance
            func: Function dict

        Returns:
            Dictionary with mutation counts, or None if no mutations applied
        """
        func_addr = func.get("offset", func.get("addr", 0))
        func_name = func.get("name", f"0x{func_addr:x}")

        logger.info(f"Flattening function {func_name}")

        blocks = self._collect_blocks(binary, func_addr, func_name)
        if blocks is None:
            return None

        # Get architecture info
        arch_family, bits = binary.get_arch_family()

        mutations = {
            "opaque_predicates": 0,
            "jump_obfuscations": 0,
            "total": 0,
        }

        baseline = {}
        if self._validation_manager is not None:
            baseline = self._validation_manager.capture_structural_baseline(binary, func_addr)

        mutation_checkpoint = self._create_mutation_checkpoint("cff")

        # Get function disassembly for instruction analysis
        try:
            all_instrs = binary.get_function_disasm(func_addr)
        except (ValueError, OSError, BrokenPipeError, RuntimeError) as e:
            logger.debug(f"Failed to get disasm for {func_name}: {e}")
            return None

        if not all_instrs:
            return None

        # Track how many predicates we've added
        predicates_to_add = min(self.opaque_density, len(blocks) - 1)
        predicates_added = 0

        # Process each block looking for opportunities
        for i, block in enumerate(blocks):
            if predicates_added >= predicates_to_add:
                break

            block_addr = block.get("addr", 0)
            block_size = block.get("size", 0)
            block_end = block_addr + block_size

            # Find instructions in this block
            block_instrs = [ins for ins in all_instrs if block_addr <= ins.get("offset", 0) < block_end]

            if not block_instrs:
                continue

            # Get last instruction of block
            last_insn = block_instrs[-1]
            last_addr = last_insn.get("offset", 0)
            last_insn.get("size", 0)
            mnemonic = last_insn.get("mnemonic", "").lower()

            # Strategy 1: Add opaque predicate before conditional jumps
            if self._is_conditional_jump(mnemonic, arch_family):
                # Look for space before the conditional jump
                if len(block_instrs) >= 2:
                    prev_insn = block_instrs[-2]
                    prev_addr = prev_insn.get("offset", 0)
                    prev_size = prev_insn.get("size", 0)

                    available_space = last_addr - (prev_addr + prev_size)

                    if available_space >= 2:
                        # We have slack space, use it
                        if self._add_opaque_predicate(
                            binary, prev_addr + prev_size, available_space, arch_family, bits
                        ):
                            predicates_added += 1
                            mutations["opaque_predicates"] += 1
                            mutations["total"] += 1
                            logger.debug(
                                f"Added opaque predicate at 0x{prev_addr + prev_size:x} "
                                f"(slack space: {available_space} bytes)"
                            )

            # Strategy 2: Insert jump obfuscation for unconditional jumps
            if mnemonic == "jmp" and i < len(blocks) - 1:
                # Try to obfuscate the jump target
                if self._jump_obfuscator.obfuscate_jump(binary, last_insn, block, arch_family, bits):
                    mutations["jump_obfuscations"] += 1
                    mutations["total"] += 1

        # Strategy 3: Look for NOP sleds we can replace with dead code + opaque predicates
        nop_sequences = self._find_nop_sequences(all_instrs)
        for nop_start, nop_size in nop_sequences:
            if predicates_added >= predicates_to_add:
                break

            if nop_size >= 5:  # Need at least 5 bytes for meaningful dead code
                if self._insert_dead_code_with_predicate(binary, nop_start, nop_size, arch_family, bits):
                    predicates_added += 1
                    mutations["opaque_predicates"] += 1
                    mutations["total"] += 1

        if mutations["total"] > 0:
            self._record_mutation(
                function_address=func_addr,
                start_address=blocks[0].get("addr", 0) if blocks else func_addr,
                end_address=blocks[-1].get("addr", 0) + blocks[-1].get("size", 0) if blocks else func_addr,
                original_bytes=b"",
                mutated_bytes=b"",
                original_disasm="function before CFF",
                mutated_disasm=f"CFF: {mutations['opaque_predicates']} predicates, {mutations['jump_obfuscations']} jumps",
                mutation_kind="control_flow_flattening",
                metadata={
                    "opaque_predicates": mutations["opaque_predicates"],
                    "jump_obfuscations": mutations["jump_obfuscations"],
                    "structural_baseline": baseline,
                },
            )

            if self._validation_manager is not None and mutation_checkpoint is not None:
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
                        logger.debug(f"CFF validation failed for {func_name}, rolled back")
                        return None

            logger.info(
                f"Flattened {func_name}: {mutations['opaque_predicates']} opaque predicates, "
                f"{mutations['jump_obfuscations']} jump obfuscations"
            )
            return mutations

        logger.debug(f"No mutations applied to {func_name}")
        return None

    def _collect_blocks(self, binary: Any, func_addr: int, func_name: str) -> list[Any] | None:
        """Fetch, size-guard, and address-sort the function's basic blocks."""
        try:
            blocks = binary.get_basic_blocks(func_addr)
        except (ValueError, OSError, BrokenPipeError, RuntimeError) as e:
            logger.error(f"Failed to get blocks for {func_name}: {e}")
            return None

        if not blocks or len(blocks) < self.min_blocks:
            logger.debug(f"Function {func_name} has too few blocks")
            return None

        return sorted(blocks, key=lambda b: b.get("addr", 0))

    def _is_conditional_jump(self, mnemonic: str, arch: str) -> bool:
        """
        Check if an instruction is a conditional jump/branch.

        Args:
            mnemonic: Instruction mnemonic
            arch: Architecture family

        Returns:
            True if conditional jump
        """
        mnemonic = mnemonic.lower()

        if arch in ("x86", "x86_64"):
            return mnemonic in _X86_CONDITIONAL_JUMPS
        elif arch in ("arm", "arm64", "aarch64"):
            return mnemonic in _ARM_CONDITIONAL_BRANCHES

        # Generic check for jump-like mnemonics that aren't unconditional
        if mnemonic.startswith("j") and mnemonic not in ("jmp", "j"):
            return True
        if mnemonic.startswith("b") and mnemonic not in ("b", "br", "bx", "blr", "bl"):
            return True

        return False

    def _find_nop_sequences(self, instructions: list[dict]) -> list[tuple[int, int]]:
        """
        Find sequences of NOP instructions that can be replaced.

        Args:
            instructions: List of instruction dictionaries

        Returns:
            List of (start_address, size) tuples for NOP sequences
        """
        sequences = []
        i = 0

        while i < len(instructions):
            insn = instructions[i]
            mnemonic = insn.get("mnemonic", "").lower()

            if mnemonic == "nop":
                start_addr = insn.get("offset", insn.get("addr", 0))
                total_size = insn.get("size", 1)
                j = i + 1

                # Accumulate consecutive NOPs
                while j < len(instructions):
                    next_insn = instructions[j]
                    if next_insn.get("mnemonic", "").lower() != "nop":
                        break
                    total_size += next_insn.get("size", 1)
                    j += 1

                if total_size >= 3:  # Only track sequences of 3+ bytes
                    sequences.append((start_addr, total_size))

                i = j
            else:
                i += 1

        return sequences

    def _add_opaque_predicate(self, binary: Any, addr: int, available_size: int, arch: str, bits: int) -> bool:
        """
        Add an opaque predicate at the specified address.

        Opaque predicates are conditions that always evaluate the same way
        but are difficult to determine through static analysis. Examples:
        - (x * x) >= 0 is always true for integers
        - (x | 1) != 0 is always true
        - (x & 0) == 0 is always true

        Args:
            binary: Any instance
            addr: Address to write the predicate
            available_size: Maximum bytes available
            arch: Architecture family
            bits: Bit width

        Returns:
            True if successfully written
        """
        if arch == "x86":
            # Generate x86 opaque predicate sequences
            predicates = self._predicate_generator.get_x86(bits)
        elif arch == "arm":
            predicates = self._predicate_generator.get_arm(bits)
        else:
            return False

        # Try each predicate until one fits
        for predicate_insns in predicates:
            assembled = b""
            success = True

            for insn in predicate_insns:
                insn_bytes = binary.assemble(insn)
                if insn_bytes is None:
                    success = False
                    break
                assembled += insn_bytes

                if len(assembled) > available_size:
                    success = False
                    break

            if success and len(assembled) <= available_size:
                # Pad with NOPs if needed using shared utility
                if len(assembled) < available_size:
                    assembled += generate_nop_sequence(arch, bits, available_size - len(assembled))

                return bool(binary.write_bytes(addr, assembled))

        return False

    def _insert_dead_code_with_predicate(self, binary: Any, addr: int, size: int, arch: str, bits: int) -> bool:
        """
        Insert dead code containing an opaque predicate into a NOP sled.

        This replaces NOPs with more complex code that:
        1. Never affects program behavior
        2. Contains opaque predicates to confuse analysis
        3. Looks like real code to disassemblers

        Uses the shared dead code generation utilities.

        Args:
            binary: Any instance
            addr: Start address of NOP sequence
            size: Size of NOP sequence
            arch: Architecture family
            bits: Bit width

        Returns:
            True if successfully inserted
        """
        if arch == "x86":
            dead_code = generate_x86_dead_code_for_size(size, bits)
        elif arch == "arm":
            dead_code = generate_arm_dead_code_for_size(size, bits)
        else:
            return False

        # Try to assemble the dead code
        assembled = b""
        for insn in dead_code:
            insn_bytes = binary.assemble(insn)
            if insn_bytes is None:
                # Fall back to NOPs
                return False
            assembled += insn_bytes

            if len(assembled) > size:
                # Too big, fall back
                return False

        if assembled:
            # Pad with NOPs using shared utility
            if len(assembled) < size:
                assembled += generate_nop_sequence(arch, bits, size - len(assembled))

            return bool(binary.write_bytes(addr, assembled))

        return False
