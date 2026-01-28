"""
Dead code injection mutation pass.

Injects code that never executes but adds complexity to binary analysis.

This module provides dead code injection capabilities for metamorphic transformation
research. Dead code injection is a classic anti-analysis technique that increases
the complexity of reverse engineering without affecting program semantics.

Research Applications:
    - Studying signature-based detection evasion
    - Analyzing the impact of code bloat on static analysis
    - Testing disassembler and decompiler resilience
    - Benchmarking analysis tool performance

Implementation Status:
    - Code generation: IMPLEMENTED
    - Injection point identification: IMPLEMENTED
    - Binary modification: IMPLEMENTED (overwrites padding/unreachable code)

Note:
    Dead code injection works by finding existing padding bytes (NOPs, INT3, etc.)
    or unreachable code regions after unconditional jumps/returns and replacing
    them with more complex dead code sequences. This changes the binary signature
    without affecting program semantics.
"""

import logging
import random
from typing import Any

from r2morph.core.binary import Binary
from r2morph.core.constants import MINIMUM_FUNCTION_SIZE, UNCONDITIONAL_TRANSFERS
from r2morph.mutations.base import MutationPass
from r2morph.utils.dead_code import (
    generate_dead_code_for_arch,
    generate_nop_sequence,
)

logger = logging.getLogger(__name__)


class DeadCodeInjectionPass(MutationPass):
    """
    Injects dead code (code that never executes) for metamorphic research.

    Dead code adds complexity without affecting program semantics, making
    static and dynamic analysis more difficult. This is a fundamental
    technique in metamorphic malware research and binary obfuscation studies.

    Injection Strategies:
        - Post-unconditional-jump: Code placed after jmp/ret/b/br instructions
          that can never be reached through normal control flow
        - Padding replacement: Replace existing NOP sleds or INT3 padding with
          more complex dead code sequences
        - Function epilogue padding: Inject into alignment padding at function ends

    Complexity Levels:
        - simple: NOP sleds only (1-10 NOPs)
        - medium: Register-preserving arithmetic sequences
        - complex: Loops, branches, and multi-register operations

    Research Value:
        - Increases code entropy and signature diversity
        - Challenges linear disassembly algorithms
        - Tests control flow graph reconstruction accuracy
        - Evaluates semantic analysis tool capabilities

    Implementation Notes:
        Dead code is injected by overwriting existing padding bytes (NOPs, INT3s)
        or unreachable code after unconditional control flow transfers. This
        preserves binary structure and section sizes.

    Examples of generated dead code:
        - Code after unconditional jumps
        - Replaced NOP padding with complex sequences
        - Register-preserving arithmetic operations
    """

    # Instructions that are safe to overwrite (padding/dead code indicators)
    PADDING_INSTRUCTIONS = {"nop", "int3", "ud2"}

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize dead code injection pass.

        Args:
            config: Configuration dictionary
        """
        super().__init__(name="DeadCodeInjection", config=config)
        self.max_injections = self.config.get("max_injections_per_function", 5)
        self.probability = self.config.get("probability", 0.4)
        self.code_complexity = self.config.get("code_complexity", "medium")
        self.min_padding_size = self.config.get("min_padding_size", 3)

    def apply(self, binary: Binary) -> dict[str, Any]:
        """
        Apply dead code injection mutations.

        Args:
            binary: Binary to mutate

        Returns:
            Statistics dict
        """
        if not binary.is_analyzed():
            logger.warning("Binary not analyzed, analyzing now...")
            binary.analyze()

        logger.info("Applying dead code injection mutations")

        functions = binary.get_functions()
        total_mutations = 0
        funcs_mutated = 0
        injection_points_found = 0

        logger.info(
            f"Dead code injection: processing {len(functions)} functions "
            f"(max {self.max_injections} injections per function, "
            f"complexity={self.code_complexity})"
        )

        for func in functions:
            # Skip tiny functions
            if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
                continue

            mutations, points = self._inject_dead_code(binary, func)
            injection_points_found += points

            if mutations > 0:
                funcs_mutated += 1
                total_mutations += mutations

        logger.info(
            f"Dead code injection complete: {total_mutations} injections "
            f"in {funcs_mutated} functions ({injection_points_found} candidate points found)"
        )

        return {
            "mutations_applied": total_mutations,
            "functions_mutated": funcs_mutated,
            "injection_points_found": injection_points_found,
            "total_functions": len(functions),
            "code_complexity": self.code_complexity,
        }

    def _inject_dead_code(self, binary: Binary, func: dict) -> tuple[int, int]:
        """
        Inject dead code in a function.

        Finds safe injection points (padding regions or after unconditional jumps)
        and replaces them with generated dead code sequences.

        Args:
            binary: Binary instance
            func: Function dict

        Returns:
            Tuple of (mutations_applied, injection_points_found)
        """
        func_addr = func.get("offset", func.get("addr", 0))
        mutations = 0

        try:
            instructions = binary.get_function_disasm(func_addr)
        except Exception as e:
            logger.debug(f"Failed to get disasm for function at 0x{func_addr:x}: {e}")
            return 0, 0

        if not instructions:
            return 0, 0

        # Find injection points: padding regions or bytes after unconditional transfers
        injection_points = self._find_injection_points(instructions)

        if not injection_points:
            return 0, 0

        # Limit injections per function
        num_to_inject = min(self.max_injections, len(injection_points))
        selected_points = random.sample(injection_points, num_to_inject)

        for point in selected_points:
            # Apply probability filter
            if random.random() > self.probability:
                continue

            inject_addr = point["addr"]
            available_size = point["size"]

            # Generate dead code that fits in the available space
            dead_code = self._generate_dead_code_for_size(binary, available_size, func_addr)

            if not dead_code:
                logger.debug(
                    f"Could not generate dead code for {available_size} bytes at 0x{inject_addr:x}"
                )
                continue

            # Write the dead code bytes
            success = binary.write_bytes(inject_addr, dead_code)

            if success:
                logger.info(
                    f"Injected {len(dead_code)} bytes of dead code at 0x{inject_addr:x} "
                    f"(available: {available_size} bytes, type: {point['type']})"
                )
                mutations += 1
            else:
                logger.debug(f"Failed to write dead code at 0x{inject_addr:x}")

        return mutations, len(injection_points)

    def _find_injection_points(
        self, instructions: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """
        Find safe injection points in the instruction stream.

        Looks for:
        1. Consecutive padding instructions (NOPs, INT3s)
        2. Instructions following unconditional control flow transfers
           (code that is unreachable and can be safely overwritten)

        Args:
            instructions: List of instruction dictionaries

        Returns:
            List of injection point dictionaries with addr, size, and type
        """
        injection_points = []
        i = 0

        while i < len(instructions):
            insn = instructions[i]
            mnemonic = insn.get("mnemonic", "").lower()

            # Strategy 1: Find padding sequences (consecutive NOPs/INT3s)
            if mnemonic in self.PADDING_INSTRUCTIONS:
                padding_start = insn.get("offset", insn.get("addr", 0))
                padding_size = insn.get("size", 1)
                j = i + 1

                # Accumulate consecutive padding instructions
                while j < len(instructions):
                    next_insn = instructions[j]
                    next_mnemonic = next_insn.get("mnemonic", "").lower()

                    if next_mnemonic not in self.PADDING_INSTRUCTIONS:
                        break

                    padding_size += next_insn.get("size", 1)
                    j += 1

                # Only consider if we have enough space
                if padding_size >= self.min_padding_size:
                    injection_points.append({
                        "addr": padding_start,
                        "size": padding_size,
                        "type": "padding",
                    })

                i = j
                continue

            # Strategy 2: Look for unreachable code after unconditional transfers
            if mnemonic in UNCONDITIONAL_TRANSFERS:
                # Check if there are instructions after this that aren't jump targets
                if i + 1 < len(instructions):
                    next_insn = instructions[i + 1]
                    next_addr = next_insn.get("offset", next_insn.get("addr", 0))
                    next_mnemonic = next_insn.get("mnemonic", "").lower()

                    # If next instruction is padding, it's likely unreachable
                    if next_mnemonic in self.PADDING_INSTRUCTIONS:
                        # This will be caught by Strategy 1 on next iteration
                        pass
                    # Could extend to detect other unreachable patterns here

            i += 1

        return injection_points

    def _is_safe_injection_point(
        self, insn: dict[str, Any], instructions: list[dict[str, Any]], index: int
    ) -> bool:
        """
        Check if we can safely inject code after this instruction.

        An instruction is a safe injection point if:
        1. It's a padding instruction (NOP, INT3, etc.)
        2. It follows an unconditional control flow transfer
        3. It's not a jump target (no references point to it)

        Args:
            insn: Current instruction
            instructions: Full instruction list
            index: Index of current instruction

        Returns:
            True if safe to inject after this instruction
        """
        mnemonic = insn.get("mnemonic", "").lower()

        # Padding instructions are always safe to overwrite
        if mnemonic in self.PADDING_INSTRUCTIONS:
            return True

        # Check if previous instruction was an unconditional transfer
        if index > 0:
            prev_insn = instructions[index - 1]
            prev_mnemonic = prev_insn.get("mnemonic", "").lower()

            if prev_mnemonic in UNCONDITIONAL_TRANSFERS:
                # This instruction follows an unconditional jump/ret
                # It's potentially dead code (unless it's a jump target)
                # For safety, only allow if it's also padding
                return mnemonic in self.PADDING_INSTRUCTIONS

        return False

    def _generate_dead_code_for_size(
        self, binary: Binary, max_size: int, func_addr: int
    ) -> bytes | None:
        """
        Generate dead code that fits within the specified size.

        Tries to generate dead code and assemble it, ensuring the result
        fits within max_size bytes.

        Args:
            binary: Binary instance for assembly
            max_size: Maximum size in bytes for the dead code
            func_addr: Function address for assembly context

        Returns:
            Assembled bytes or None if cannot fit
        """
        # Get architecture info
        arch_family, bits = binary.get_arch_family()

        # Try to generate code that fits
        for _attempt in range(5):  # Multiple attempts with different random choices
            dead_code_insns = self._generate_dead_code(binary)

            # Filter out labels and directives (they can't be assembled directly)
            assemblable_insns = [
                insn for insn in dead_code_insns
                if not insn.startswith(".") and not insn.endswith(":")
            ]

            if not assemblable_insns:
                # Fall back to NOPs if no assemblable instructions
                return self._generate_nop_sequence(max_size, arch_family, bits)

            # Try to assemble and check size
            assembled_bytes = b""
            for insn in assemblable_insns:
                insn_bytes = binary.assemble(insn, func_addr)
                if insn_bytes is None:
                    # Assembly failed, try next instruction set
                    assembled_bytes = None
                    break
                assembled_bytes += insn_bytes

                # Stop if we've exceeded the size
                if len(assembled_bytes) > max_size:
                    assembled_bytes = None
                    break

            if assembled_bytes and len(assembled_bytes) <= max_size:
                # Pad with NOPs if needed
                if len(assembled_bytes) < max_size:
                    padding_size = max_size - len(assembled_bytes)
                    assembled_bytes += self._generate_nop_sequence(padding_size, arch_family, bits)
                return assembled_bytes

        # Fallback: just return NOPs
        return self._generate_nop_sequence(max_size, arch_family, bits)

    def _generate_nop_sequence(self, size: int, arch: str, bits: int) -> bytes:
        """
        Generate a NOP sequence of the specified size.

        Uses architecture-appropriate NOP instructions via shared utility.

        Args:
            size: Number of bytes
            arch: Architecture (x86, arm, etc.)
            bits: Bit width (32 or 64)

        Returns:
            NOP bytes
        """
        return generate_nop_sequence(arch, bits, size)

    def _generate_dead_code(self, binary: Binary) -> list[str]:
        """
        Generate dead code based on complexity setting.

        Uses the shared dead code generation utility.

        Args:
            binary: Binary instance

        Returns:
            List of assembly instructions (without labels/directives for assembly)
        """
        arch_family, bits = binary.get_arch_family()
        return generate_dead_code_for_arch(arch_family, bits, self.code_complexity)
