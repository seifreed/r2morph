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

from __future__ import annotations

import logging
import random
from typing import Any

from r2morph.core.constants import MINIMUM_FUNCTION_SIZE
from r2morph.mutations.base import MutationPass
from r2morph.mutations.dead_code_injection_helpers import (
    PADDING_INSTRUCTIONS as _PADDING_INSTRUCTIONS,
)
from r2morph.mutations.dead_code_injection_helpers import (
    find_injection_points,
    generate_dead_code,
    generate_dead_code_for_size,
    generate_nop_sequence,
    is_safe_injection_point,
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
    PADDING_INSTRUCTIONS = _PADDING_INSTRUCTIONS

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

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply dead code injection mutations.

        Args:
            binary: Any to mutate

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

        self._reset_random()

        logger.info(
            f"Dead code injection: processing {len(functions)} functions "
            f"(max {self.max_injections} injections per function, "
            f"complexity={self.code_complexity})"
        )

        for func in functions:
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

    def _inject_dead_code(self, binary: Any, func: dict) -> tuple[int, int]:
        """
        Inject dead code in a function.

        Finds safe injection points (padding regions or after unconditional jumps)
        and replaces them with generated dead code sequences.

        Args:
            binary: Any instance
            func: Function dict

        Returns:
            Tuple of (mutations_applied, injection_points_found)
        """
        func_addr = func.get("offset", func.get("addr", 0))
        mutations = 0

        try:
            instructions = binary.get_function_disasm(func_addr)
        except (ValueError, OSError, BrokenPipeError, RuntimeError) as e:
            logger.debug(f"Failed to get disasm for function at 0x{func_addr:x}: {e}")
            return 0, 0

        if not instructions:
            return 0, 0

        injection_points = self._find_injection_points(instructions)

        if not injection_points:
            return 0, 0

        num_to_inject = min(self.max_injections, len(injection_points))
        selected_points = random.sample(injection_points, num_to_inject)

        for point in selected_points:
            if random.random() > self.probability:
                continue

            inject_addr = point["addr"]
            available_size = point["size"]

            dead_code = self._generate_dead_code_for_size(binary, available_size, func_addr)

            if not dead_code:
                logger.debug(f"Could not generate dead code for {available_size} bytes at 0x{inject_addr:x}")
                continue

            original_bytes = binary.read_bytes(inject_addr, available_size)
            if not original_bytes:
                # Cannot read the bytes we would overwrite: we can
                # neither confirm this is safe padding nor record an
                # accurate original. The old code fabricated
                # b"\x90" * available_size, producing a false mutation
                # record and writing dead code over an unverified
                # region. Fail safe: skip this injection point.
                logger.debug(
                    "Skipping dead-code injection at 0x%x: original bytes unreadable",
                    inject_addr,
                )
                continue

            mutation_checkpoint = self._create_mutation_checkpoint("dead_code")
            baseline = {}
            if self._validation_manager is not None:
                baseline = self._validation_manager.capture_structural_baseline(binary, func_addr)

            success = binary.write_bytes(inject_addr, dead_code)

            if success:
                record = self._record_mutation(
                    function_address=func_addr,
                    start_address=inject_addr,
                    end_address=inject_addr + len(dead_code) - 1,
                    original_bytes=original_bytes[: len(dead_code)],
                    mutated_bytes=dead_code,
                    original_disasm=f"padding ({len(dead_code)} bytes)",
                    mutated_disasm=f"dead_code ({len(dead_code)} bytes)",
                    mutation_kind="dead_code_injection",
                    metadata={
                        "injection_point_type": point["type"],
                        "available_size": available_size,
                        "structural_baseline": baseline,
                    },
                )

                if self._validate_mutation_or_rollback(binary, record, mutation_checkpoint):
                    continue

                logger.info(
                    f"Injected {len(dead_code)} bytes of dead code at 0x{inject_addr:x} "
                    f"(available: {available_size} bytes, type: {point['type']})"
                )
                mutations += 1
            else:
                logger.debug(f"Failed to write dead code at 0x{inject_addr:x}")

        return mutations, len(injection_points)

    def _find_injection_points(self, instructions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return find_injection_points(instructions, self.min_padding_size, self.PADDING_INSTRUCTIONS)

    def _is_safe_injection_point(self, insn: dict[str, Any], instructions: list[dict[str, Any]], index: int) -> bool:
        return is_safe_injection_point(insn, instructions, index, self.PADDING_INSTRUCTIONS)

    def _generate_dead_code_for_size(self, binary: Any, max_size: int, func_addr: int) -> bytes | None:
        return generate_dead_code_for_size(binary, max_size, func_addr, self.code_complexity)

    def _generate_nop_sequence(self, size: int, arch: str, bits: int) -> bytes:
        return generate_nop_sequence(arch, bits, size)

    def _generate_dead_code(self, binary: Any) -> list[str]:
        return generate_dead_code(binary, self.code_complexity)
