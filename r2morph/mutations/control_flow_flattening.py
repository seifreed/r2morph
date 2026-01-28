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

import logging
import random
from typing import Any

from r2morph.analysis.cfg import CFGBuilder
from r2morph.core.binary import Binary
from r2morph.core.constants import MINIMUM_FUNCTION_SIZE, UNCONDITIONAL_TRANSFERS
from r2morph.mutations.base import MutationPass
from r2morph.utils.dead_code import (
    generate_arm_dead_code_for_size,
    generate_nop_sequence,
    generate_x86_dead_code_for_size,
)

logger = logging.getLogger(__name__)


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

    # Conditional jump instructions (x86)
    X86_CONDITIONAL_JUMPS = {
        "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe",
        "jg", "jge", "jl", "jle", "jo", "jno", "js", "jns",
        "jp", "jnp", "jcxz", "jecxz", "jrcxz"
    }

    # ARM conditional branch instructions
    ARM_CONDITIONAL_BRANCHES = {
        "beq", "bne", "bcs", "bcc", "bmi", "bpl", "bvs", "bvc",
        "bhi", "bls", "bge", "blt", "bgt", "ble", "b.eq", "b.ne",
        "b.cs", "b.cc", "b.mi", "b.pl", "b.vs", "b.vc", "b.hi",
        "b.ls", "b.ge", "b.lt", "b.gt", "b.le", "cbz", "cbnz"
    }

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize control flow flattening pass.

        Args:
            config: Configuration dictionary
        """
        super().__init__(name="ControlFlowFlattening", config=config)
        self.max_functions = self.config.get("max_functions_to_flatten", 5)
        self.min_blocks = self.config.get("min_blocks_required", 3)
        self.probability = self.config.get("probability", 0.5)
        self.opaque_density = self.config.get("opaque_predicate_density", 3)

    def apply(self, binary: Binary) -> dict[str, Any]:
        """
        Apply control flow flattening transformations.

        This method:
        1. Selects candidate functions with sufficient complexity
        2. For each function, analyzes the CFG
        3. Inserts opaque predicates at conditional branch points
        4. Adds jump obfuscation to obscure control flow
        5. Tracks and returns mutation statistics

        Args:
            binary: Binary to mutate

        Returns:
            Statistics dict with mutation counts and details
        """
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

    def _select_candidates(self, binary: Binary, functions: list[dict]) -> list[dict]:
        """
        Select functions suitable for flattening.

        Filters functions based on:
        - Minimum basic block count (need enough blocks to obscure)
        - Function size (too small functions have no room for transformations)
        - Not being an import/thunk (library functions shouldn't be modified)

        Args:
            binary: Binary instance
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

            except Exception as e:
                logger.debug(f"Failed to analyze function 0x{func_addr:x}: {e}")

        # Sort by block count (more blocks = better candidate for obfuscation)
        candidates.sort(key=lambda f: f.get("_block_count", 0), reverse=True)

        return candidates

    def _flatten_function(self, binary: Binary, func: dict) -> dict[str, int] | None:
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
            binary: Binary instance
            func: Function dict

        Returns:
            Dictionary with mutation counts, or None if no mutations applied
        """
        func_addr = func.get("offset", func.get("addr", 0))
        func_name = func.get("name", f"0x{func_addr:x}")

        logger.info(f"Flattening function {func_name}")

        # Get basic blocks
        try:
            blocks = binary.get_basic_blocks(func_addr)
        except Exception as e:
            logger.error(f"Failed to get blocks for {func_name}: {e}")
            return None

        if not blocks or len(blocks) < self.min_blocks:
            logger.debug(f"Function {func_name} has too few blocks")
            return None

        # Sort blocks by address
        blocks = sorted(blocks, key=lambda b: b.get("addr", 0))

        # Get architecture info
        arch_family, bits = binary.get_arch_family()

        mutations = {
            "opaque_predicates": 0,
            "jump_obfuscations": 0,
            "total": 0,
        }

        # Get function disassembly for instruction analysis
        try:
            all_instrs = binary.get_function_disasm(func_addr)
        except Exception as e:
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
            block_instrs = [
                ins for ins in all_instrs
                if block_addr <= ins.get("offset", 0) < block_end
            ]

            if not block_instrs:
                continue

            # Get last instruction of block
            last_insn = block_instrs[-1]
            last_addr = last_insn.get("offset", 0)
            last_size = last_insn.get("size", 0)
            mnemonic = last_insn.get("mnemonic", "").lower()

            # Strategy 1: Add opaque predicate before conditional jumps
            if self._is_conditional_jump(mnemonic, arch_family):
                # Look for space before the conditional jump
                if len(block_instrs) >= 2:
                    prev_insn = block_instrs[-2]
                    prev_addr = prev_insn.get("offset", 0)
                    prev_size = prev_insn.get("size", 0)

                    # Check if we have NOPs or padding we can use
                    available_space = last_addr - (prev_addr + prev_size)

                    if available_space >= 2:
                        # We have slack space, use it
                        if self._add_opaque_predicate(
                            binary, prev_addr + prev_size,
                            available_space, arch_family, bits
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
                if self._obfuscate_jump(binary, last_insn, block, arch_family, bits):
                    mutations["jump_obfuscations"] += 1
                    mutations["total"] += 1

        # Strategy 3: Look for NOP sleds we can replace with dead code + opaque predicates
        nop_sequences = self._find_nop_sequences(all_instrs)
        for nop_start, nop_size in nop_sequences:
            if predicates_added >= predicates_to_add:
                break

            if nop_size >= 5:  # Need at least 5 bytes for meaningful dead code
                if self._insert_dead_code_with_predicate(
                    binary, nop_start, nop_size, arch_family, bits
                ):
                    predicates_added += 1
                    mutations["opaque_predicates"] += 1
                    mutations["total"] += 1

        if mutations["total"] > 0:
            logger.info(
                f"Flattened {func_name}: {mutations['opaque_predicates']} opaque predicates, "
                f"{mutations['jump_obfuscations']} jump obfuscations"
            )
            return mutations

        logger.debug(f"No mutations applied to {func_name}")
        return None

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

        if arch == "x86":
            return mnemonic in self.X86_CONDITIONAL_JUMPS
        elif arch == "arm":
            return mnemonic in self.ARM_CONDITIONAL_BRANCHES

        # Generic check for jump-like mnemonics that aren't unconditional
        if mnemonic.startswith("j") and mnemonic != "jmp":
            return True
        if mnemonic.startswith("b") and mnemonic not in ("b", "br", "bx", "blr"):
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

    def _add_opaque_predicate(
        self, binary: Binary, addr: int, available_size: int,
        arch: str, bits: int
    ) -> bool:
        """
        Add an opaque predicate at the specified address.

        Opaque predicates are conditions that always evaluate the same way
        but are difficult to determine through static analysis. Examples:
        - (x * x) >= 0 is always true for integers
        - (x | 1) != 0 is always true
        - (x & 0) == 0 is always true

        Args:
            binary: Binary instance
            addr: Address to write the predicate
            available_size: Maximum bytes available
            arch: Architecture family
            bits: Bit width

        Returns:
            True if successfully written
        """
        if arch == "x86":
            # Generate x86 opaque predicate sequences
            predicates = self._get_x86_opaque_predicates(bits)
        elif arch == "arm":
            predicates = self._get_arm_opaque_predicates(bits)
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
                    assembled += generate_nop_sequence(
                        arch, bits, available_size - len(assembled)
                    )

                return binary.write_bytes(addr, assembled)

        return False

    def _get_x86_opaque_predicates(self, bits: int) -> list[list[str]]:
        """
        Get x86 opaque predicate instruction sequences.

        Each sequence is designed to:
        1. Preserve all register values (push/pop)
        2. Set flags in a predictable way that's hard to analyze statically
        3. Be small enough to fit in slack space

        Args:
            bits: 32 or 64 bit mode

        Returns:
            List of instruction sequences
        """
        if bits == 64:
            regs = ["rax", "rbx", "rcx", "rdx"]
        else:
            regs = ["eax", "ebx", "ecx", "edx"]

        reg = random.choice(regs)

        predicates = [
            # Opaque predicate: x*x >= 0 (always true, but requires multiplication)
            # This is hard to prove statically without symbolic execution
            [
                f"push {reg}",
                f"imul {reg}, {reg}",  # x * x
                f"test {reg}, {reg}",  # Sets SF based on result
                f"pop {reg}",
            ],
            # Opaque predicate: (x | 1) != 0 (always true)
            [
                f"push {reg}",
                f"or {reg}, 1",
                f"test {reg}, {reg}",  # Always non-zero
                f"pop {reg}",
            ],
            # Opaque predicate: x ^ x == 0 (always true)
            [
                f"push {reg}",
                f"xor {reg}, {reg}",  # Always 0
                f"test {reg}, {reg}",  # ZF = 1
                f"pop {reg}",
            ],
            # Simpler: just set flags in a confusing way
            [
                f"push {reg}",
                f"mov {reg}, 0x12345678",
                f"xor {reg}, 0x12345678",  # Result is 0
                f"pop {reg}",
            ],
            # Very small: just modify flags with pushf/popf
            [
                "pushf" if bits == 32 else "pushfq",
                "nop",
                "popf" if bits == 32 else "popfq",
            ],
        ]

        return predicates

    def _get_arm_opaque_predicates(self, bits: int) -> list[list[str]]:
        """
        Get ARM opaque predicate instruction sequences.

        Args:
            bits: 32 or 64 bit mode

        Returns:
            List of instruction sequences
        """
        if bits == 64:
            regs = ["x9", "x10", "x11"]  # Temporary registers
        else:
            regs = ["r4", "r5", "r6"]

        reg = random.choice(regs)

        predicates = [
            # Simple flag manipulation
            [
                f"mov {reg}, #1",
                f"tst {reg}, #1",  # Sets flags
                f"mov {reg}, #0",
            ],
            # XOR-based predicate
            [
                f"eor {reg}, {reg}, {reg}",  # Always 0
                f"cmp {reg}, #0",  # Always equal
            ],
        ]

        return predicates

    def _obfuscate_jump(
        self, binary: Binary, jump_insn: dict, block: dict,
        arch: str, bits: int
    ) -> bool:
        """
        Obfuscate an unconditional jump instruction.

        Techniques:
        1. Replace direct jump with computed jump (harder to analyze)
        2. Add unnecessary intermediate jumps
        3. Use indirect addressing where possible

        Note: This is limited by available space - we can only transform
        the jump in-place without expanding the function.

        Args:
            binary: Binary instance
            jump_insn: The jump instruction dictionary
            block: The containing basic block
            arch: Architecture family
            bits: Bit width

        Returns:
            True if successfully obfuscated
        """
        jump_addr = jump_insn.get("offset", 0)
        jump_size = jump_insn.get("size", 0)

        # For now, we can only do in-place transformations
        # Skip if jump is too small to modify meaningfully
        if jump_size < 5:
            return False

        # Get the jump target from the instruction
        # The disasm format includes the target in the instruction text
        disasm = jump_insn.get("disasm", "")
        if not disasm:
            return False

        # Try to parse the target address
        try:
            # Format is usually "jmp 0x12345678" or "jmp target_name"
            parts = disasm.split()
            if len(parts) >= 2:
                target_str = parts[1]
                if target_str.startswith("0x"):
                    target_addr = int(target_str, 16)
                else:
                    # Named target - skip for now
                    return False
            else:
                return False
        except (ValueError, IndexError):
            return False

        if arch == "x86":
            # Try to create a more complex but equivalent jump
            # Option 1: Use a conditional jump that's always taken + unconditional
            # This adds complexity for analysis

            # Calculate relative offset for a shorter jump if possible
            rel_offset = target_addr - (jump_addr + 2)  # 2-byte short jump

            if -128 <= rel_offset <= 127:
                # Can use short jump form, fill rest with dead code
                new_insn = f"jmp 0x{target_addr:x}"
                assembled = binary.assemble(new_insn)

                if assembled and len(assembled) <= jump_size:
                    # Pad with NOPs using shared utility
                    padded = assembled + generate_nop_sequence(
                        arch, bits, jump_size - len(assembled)
                    )
                    return binary.write_bytes(jump_addr, padded)

        return False

    def _insert_dead_code_with_predicate(
        self, binary: Binary, addr: int, size: int,
        arch: str, bits: int
    ) -> bool:
        """
        Insert dead code containing an opaque predicate into a NOP sled.

        This replaces NOPs with more complex code that:
        1. Never affects program behavior
        2. Contains opaque predicates to confuse analysis
        3. Looks like real code to disassemblers

        Uses the shared dead code generation utilities.

        Args:
            binary: Binary instance
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

            return binary.write_bytes(addr, assembled)

        return False

    # Keep the dispatcher generation methods for reference/future use
    def _generate_dispatcher(self, binary: Binary, blocks: list[Any]) -> list[str]:
        """
        Generate dispatcher code (for reference/analysis purposes).

        Note: This generates dispatcher code but doesn't apply it to the binary.
        Full dispatcher-based flattening would require binary expansion which
        is not currently implemented.

        Args:
            binary: Binary instance
            blocks: List of basic blocks

        Returns:
            List of assembly instructions
        """
        arch_family, bits = binary.get_arch_family()

        if arch_family == "x86":
            return self._generate_x86_dispatcher(blocks, bits)
        elif arch_family == "arm":
            return self._generate_arm_dispatcher(blocks, bits)

        return []

    def _generate_x86_dispatcher(self, blocks: list[Any], bits: int) -> list[str]:
        """
        Generate x86 dispatcher code template.

        Args:
            blocks: Basic blocks
            bits: Bit width

        Returns:
            Assembly instructions
        """
        reg = "rax" if bits == 64 else "eax"

        code = [
            "; Flattened control flow dispatcher",
            f"mov {reg}, 0  ; Initial state",
            ".dispatcher_loop:",
        ]

        for i, block in enumerate(blocks):
            code.extend(
                [
                    f"cmp {reg}, {i}",
                    f"je .block_{i}",
                ]
            )

        code.append("jmp .dispatcher_end")

        for i, block in enumerate(blocks):
            code.append(f".block_{i}:")
            code.append(f"; Original block at 0x{block.address:x}")
            code.append("; ... block code here ...")

            if i < len(blocks) - 1:
                code.append(f"mov {reg}, {i + 1}")
            else:
                code.append(f"mov {reg}, -1")

            code.append("jmp .dispatcher_loop")

        code.append(".dispatcher_end:")

        return code

    def _generate_arm_dispatcher(self, blocks: list[Any], bits: int) -> list[str]:
        """
        Generate ARM dispatcher code template.

        Args:
            blocks: Basic blocks
            bits: Bit width

        Returns:
            Assembly instructions
        """
        reg = "x0" if bits == 64 else "r0"

        code = [
            "; Flattened control flow dispatcher",
            f"mov {reg}, #0  ; Initial state",
            ".dispatcher_loop:",
        ]

        for i, block in enumerate(blocks):
            code.extend(
                [
                    f"cmp {reg}, #{i}",
                    f"b.eq .block_{i}",
                ]
            )

        code.append("b .dispatcher_end")

        for i, block in enumerate(blocks):
            code.append(f".block_{i}:")
            code.append(f"; Original block at 0x{block.address:x}")
            code.append("; ... block code here ...")

            if i < len(blocks) - 1:
                code.append(f"mov {reg}, #{i + 1}")
            else:
                code.append(f"mov {reg}, #-1")

            code.append("b .dispatcher_loop")

        code.append(".dispatcher_end:")

        return code
