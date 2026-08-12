"""
NOP insertion mutation pass.

Inserts NOP (no operation) instructions at safe locations in the binary.
Note: Currently only overwrites truly redundant instructions to avoid breaking the binary.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

import r2morph.core.randomness as random
from r2morph.core.constants import MINIMUM_FUNCTION_SIZE
from r2morph.mutations.base import MutationPass
from r2morph.mutations.nop_insertion_helpers import (
    CALLER_SAVED_32BIT as _CALLER_SAVED_32BIT,
)
from r2morph.mutations.nop_insertion_helpers import (
    CALLER_SAVED_64BIT as _CALLER_SAVED_64BIT,
)
from r2morph.mutations.nop_insertion_helpers import (
    CALLER_SAVED_ARM32 as _CALLER_SAVED_ARM32,
)
from r2morph.mutations.nop_insertion_helpers import (
    NOP_EQUIVALENTS_BASE as _NOP_EQUIVALENTS_BASE,
)
from r2morph.mutations.nop_insertion_helpers import (
    REGISTERS_32BIT as _REGISTERS_32BIT,
)
from r2morph.mutations.nop_insertion_helpers import (
    REGISTERS_64BIT as _REGISTERS_64BIT,
)
from r2morph.mutations.nop_insertion_helpers import (
    generate_jmp_dead_code,
    init_nop_equivalents,
    is_safe_self_redundancy,
    select_candidates,
)

logger = logging.getLogger(__name__)

_BITS_32 = 32
_BITS_64 = 64
_CREATIVE_NOP_PROBABILITY = 0.7
_OPERAND_COUNT = 2
_MAX_ARM_MOV_IMMEDIATE = 0xFFFF
_ARM_INSTRUCTION_SIZE_BYTES = 4


class NopInsertionPass(MutationPass):
    """
    Mutation pass that replaces redundant instructions with NOPs or NOP-equivalents.

    This mutation identifies truly redundant instructions (like mov reg, reg)
    and replaces them with NOPs or creative NOP-equivalent instructions to
    change the binary signature without affecting program semantics.

    Config options:
        - max_nops_per_function: Maximum NOPs to insert per function (default: 5)
        - probability: Probability of inserting NOP at candidate location (default: 0.5)
        - use_creative_nops: Use creative NOP equivalents instead of plain NOPs (default: True)
    """

    NOP_EQUIVALENTS_BASE = _NOP_EQUIVALENTS_BASE
    REGISTERS_32BIT = _REGISTERS_32BIT
    REGISTERS_64BIT = _REGISTERS_64BIT
    REGISTERS_ARM32: ClassVar[list[str]] = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7"]
    CALLER_SAVED_32BIT = _CALLER_SAVED_32BIT
    CALLER_SAVED_ARM32 = _CALLER_SAVED_ARM32
    CALLER_SAVED_64BIT = _CALLER_SAVED_64BIT

    def _init_nop_equivalents(self) -> None:
        self.NOP_EQUIVALENTS = init_nop_equivalents()

    def _generate_jmp_dead_code(
        self, size: int, bits: int, binary: Any, function_addr: int | None = None
    ) -> bytes | None:
        return generate_jmp_dead_code(size, bits, binary, function_addr)

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize NOP insertion pass.

        Args:
            config: Configuration dictionary
        """
        super().__init__(name="NopInsertion", config=config)
        self.max_nops = self.config.get("max_nops_per_function", 5)
        self.probability = self.config.get("probability", 0.5)
        self.use_creative_nops = self.config.get("use_creative_nops", True)
        self.force_different = self.config.get("force_different", False)
        self._init_support()

    def _init_support(self) -> None:
        """Set the pass support metadata."""
        self.set_support(
            formats=("ELF", "Mach-O"),
            architectures=("x86_64", "arm64", "arm"),
            validators=("structural", "runtime", "symbolic"),
            stability="stable",
            notes=(
                "safe redundant-instruction replacement",
                "arm64 support via mov-immediate substitution is experimental",
            ),
            validator_capabilities={
                "structural": {
                    "mode": "region",
                    "coverage": "patch integrity + invariant checks",
                },
                "runtime": {
                    "mode": "per-pass + final",
                    "coverage": "sample-based equivalence",
                },
                "symbolic": {
                    "mode": "experimental",
                    "scope": "bounded real-binary observables on replaced regions",
                    "confidence": "medium",
                    "expected_statuses": (
                        "real-binary-observables-match",
                        "real-binary-observable-mismatch",
                        "bounded-only",
                        "without-symbolic-coverage",
                    ),
                },
            },
        )

    def configure_for_memory_constraints(self, factor: float) -> None:
        """Reduce NOP insertion density for memory-efficient mode."""
        original = self.max_nops
        self.max_nops = max(1, int(self.max_nops * factor))
        self.config["max_nops_per_function"] = self.max_nops
        if self.max_nops != original:
            logging.getLogger(__name__).debug(f"Memory-efficient: reduced max_nops from {original} to {self.max_nops}")
        self._init_support()
        self._init_nop_equivalents()

    def _is_safe_self_redundancy(self, register: str, bits: int) -> bool:
        return is_safe_self_redundancy(register, bits)

    def _select_candidates(
        self, binary: Any, functions: list[dict[str, Any]], arch_family: str, bits: int
    ) -> list[tuple[dict[str, Any], list[dict[str, Any]]]]:
        return select_candidates(binary, functions, arch_family, bits, self.max_nops)

    def _write_creative_nop(
        self,
        binary: Any,
        function_address: int,
        instruction: dict[str, Any],
        arch_family: str,
        bits: int,
    ) -> str | None:
        address = instruction.get("addr", 0)
        size = instruction.get("size", 0)
        if size in (3, 4, 5) and arch_family == "x86":
            jump_bytes = self._generate_jmp_dead_code(size, bits, binary, function_address)
            if jump_bytes and binary.write_bytes(address, jump_bytes):
                logger.info(f"Inserted jmp+dead code NOP ({size} bytes) at 0x{address:x}")
                return "jmp+dead-code"

        equivalents = self.NOP_EQUIVALENTS.get(arch_family, [])
        random.shuffle(equivalents)
        for equivalent in equivalents:
            nop_bytes = binary.assemble(equivalent, function_address)
            if not nop_bytes or len(nop_bytes) > size or not binary.write_bytes(address, nop_bytes):
                continue
            if len(nop_bytes) < size:
                binary.nop_fill(address + len(nop_bytes), size - len(nop_bytes))
            logger.info(f"Inserted creative NOP '{equivalent}' at 0x{address:x}")
            return equivalent
        return None

    def _rewrite_candidate(
        self,
        binary: Any,
        function_address: int,
        instruction: dict[str, Any],
        arch_family: str,
        bits: int,
    ) -> str | None:
        if self.use_creative_nops and random.random() < _CREATIVE_NOP_PROBABILITY:
            replacement = self._write_creative_nop(binary, function_address, instruction, arch_family, bits)
            if replacement is not None:
                return replacement

        address = instruction.get("addr", 0)
        size = instruction.get("size", 0)
        if not binary.nop_fill(address, size):
            return None
        logger.info(f"Inserted {size} plain NOPs at 0x{address:x}")
        return f"nop x{size}"

    def _accept_candidate(self, binary: Any, record: Any, checkpoint: Any) -> bool:
        if self._validation_manager is None:
            return True
        outcome = self._validation_manager.validate_mutation(binary, record.to_dict())
        if outcome.passed or checkpoint is None:
            return True
        if self._session is not None:
            self._session.rollback_to(checkpoint)
        binary.reload()
        self._records.pop()
        if self._rollback_policy == "fail-fast":
            raise RuntimeError("Mutation-level validation failed")
        return False

    def _apply_candidate(
        self,
        binary: Any,
        function: dict[str, Any],
        instruction: dict[str, Any],
        arch_family: str,
        bits: int,
    ) -> bool:
        address = instruction.get("addr", 0)
        size = instruction.get("size", 0)
        checkpoint = self._create_mutation_checkpoint("nop")
        baseline = {}
        if self._validation_manager is not None:
            baseline = self._validation_manager.capture_structural_baseline(binary, function["addr"])
        original_bytes = binary.read_bytes(address, size)
        replacement = self._rewrite_candidate(binary, function["addr"], instruction, arch_family, bits)
        if replacement is None:
            return False
        mutated_bytes = binary.read_bytes(address, size)
        if mutated_bytes == original_bytes:
            return False
        record = self._record_mutation(
            function_address=function["addr"],
            start_address=address,
            end_address=address + size - 1,
            original_bytes=original_bytes,
            mutated_bytes=mutated_bytes,
            original_disasm=instruction.get("disasm", ""),
            mutated_disasm=replacement,
            mutation_kind="nop_insertion",
            metadata={"structural_baseline": baseline, "size": size},
        )
        return self._accept_candidate(binary, record, checkpoint)

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply NOP insertion mutations to the binary.

        Args:
            binary: Any instance to mutate

        Returns:
            Dictionary with mutation statistics
        """
        if self._reset_random() is not None:
            self._init_nop_equivalents()

        self._ensure_analyzed(binary)

        arch_family, bits = binary.get_arch_family()
        if arch_family == "arm" and bits == _BITS_64:
            return self._apply_arm64_safe_nops(binary)
        if arch_family == "arm" and bits == _BITS_32:
            return self._apply_arm32_safe_nops(binary)

        functions = binary.get_functions()
        mutations_applied = 0
        functions_mutated = 0

        logger.info(f"NOP insertion: processing {len(functions)} functions (max {self.max_nops} NOPs per function)")

        for func, selected in self._select_candidates(binary, functions, arch_family, bits):
            func_mutations = 0
            for insn in selected:
                address = insn.get("addr", 0)
                if random.random() >= self.probability or address == 0 or insn.get("size", 0) == 0:
                    continue
                try:
                    if not self._apply_candidate(binary, func, insn, arch_family, bits):
                        continue
                    func_mutations += 1
                    mutations_applied += 1
                    self._init_nop_equivalents()
                except (ValueError, OSError, BrokenPipeError, RuntimeError) as e:
                    logger.error(f"Failed to insert NOP at 0x{address:x}: {e}")

            if func_mutations > 0:
                functions_mutated += 1

        logger.info(f"NOP insertion complete: {mutations_applied} NOPs inserted in {functions_mutated} functions")

        return {
            "mutations_applied": mutations_applied,
            "functions_mutated": functions_mutated,
            "total_functions": len(functions),
        }

    @staticmethod
    def _arm64_replacement(disasm: str) -> str | None:
        if disasm in ("nop", "mov x0, x0", "mov xzr, xzr"):
            return random.choice(["mov x0, x0", "add x0, x0, #0", "orr x0, x0, #0"])
        if not disasm.startswith("mov "):
            return None
        parts = [part.strip() for part in disasm.split(",")]
        if len(parts) != _OPERAND_COUNT:
            return None
        destination = parts[0].split()[-1]
        source = parts[1]
        if destination == source and destination.startswith(("x", "w")):
            return f"add {destination}, {destination}, #0"
        if not destination.startswith(("x", "w")) or not (source.startswith("0x") or source.isdigit()):
            return None
        immediate = int(source, 16) if source.startswith("0x") else int(source)
        replacement = None
        if 0 <= immediate <= _MAX_ARM_MOV_IMMEDIATE:
            replacement = f"movz {destination}, {hex(immediate)}"
        return replacement

    def _apply_arm64_instruction(self, binary: Any, function: dict[str, Any], instruction: dict[str, Any]) -> bool:
        address = instruction.get("addr", 0)
        size = instruction.get("size", 0)
        replacement = self._arm64_replacement(instruction.get("disasm", "").lower().replace("#", ""))
        if replacement is None:
            return False
        new_bytes = binary.assemble(replacement, function["addr"])
        if not new_bytes or len(new_bytes) != size:
            return False
        original_bytes = binary.read_bytes(address, size)
        if new_bytes == original_bytes:
            return False
        baseline = {}
        if self._validation_manager is not None:
            baseline = self._validation_manager.capture_structural_baseline(binary, function["addr"])
        if not binary.write_bytes(address, new_bytes):
            return False
        self._record_mutation(
            function_address=function["addr"],
            start_address=address,
            end_address=address + size - 1,
            original_bytes=original_bytes,
            mutated_bytes=binary.read_bytes(address, size),
            original_disasm=instruction.get("disasm", ""),
            mutated_disasm=replacement,
            mutation_kind="nop_insertion",
            metadata={"structural_baseline": baseline, "size": size},
        )
        return True

    def _apply_arm64_safe_nops(self, binary: Any) -> dict[str, Any]:
        """Apply safe ARM64 substitutions that preserve semantics."""
        functions = binary.get_functions()
        mutations_applied = 0
        functions_mutated = 0

        for func in functions:
            if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
                continue

            try:
                instructions = binary.get_function_disasm(func["addr"])
            except (ValueError, OSError, BrokenPipeError, RuntimeError) as e:
                logger.debug(f"Failed to get disasm for {func.get('name')}: {e}")
                continue

            func_mutations = 0
            for insn in instructions:
                if not self._apply_arm64_instruction(binary, func, insn):
                    continue
                func_mutations += 1
                mutations_applied += 1
                if func_mutations >= self.max_nops:
                    break

            if func_mutations > 0:
                functions_mutated += 1

        return {
            "mutations_applied": mutations_applied,
            "functions_mutated": functions_mutated,
            "total_functions": len(functions),
        }

    @staticmethod
    def _is_arm32_nop_like(disasm: str) -> bool:
        if disasm in ("nop", "mov r0, r0"):
            return True
        if not disasm.startswith("mov "):
            return False
        parts = disasm.split(",")
        return len(parts) == _OPERAND_COUNT and parts[0].split()[-1].strip() == parts[1].strip()

    def _apply_arm32_instruction(
        self, binary: Any, function: dict[str, Any], instruction: dict[str, Any], replacements: list[str]
    ) -> bool:
        address = instruction.get("addr", 0)
        size = instruction.get("size", 0)
        disasm = instruction.get("disasm", "").lower().strip()
        if (
            size != _ARM_INSTRUCTION_SIZE_BYTES
            or not self._is_arm32_nop_like(disasm)
            or random.random() >= self.probability
        ):
            return False
        replacement = random.choice(replacements)
        new_bytes = binary.assemble(replacement, function["addr"])
        if not new_bytes or len(new_bytes) != _ARM_INSTRUCTION_SIZE_BYTES:
            return False
        original_bytes = binary.read_bytes(address, size)
        if not binary.write_bytes(address, new_bytes):
            return False
        self._record_mutation(
            function_address=function["addr"],
            start_address=address,
            end_address=address + size - 1,
            original_bytes=original_bytes,
            mutated_bytes=new_bytes,
            original_disasm=disasm,
            mutated_disasm=replacement,
            mutation_kind="nop_insertion",
        )
        return True

    def _apply_arm32_safe_nops(self, binary: Any) -> dict[str, Any]:
        """Apply safe ARM32 NOP substitutions (4-byte instructions)."""
        arm32_nops = self.NOP_EQUIVALENTS.get("arm", self.NOP_EQUIVALENTS_BASE.get("arm", []))
        functions = binary.get_functions()
        mutations_applied = 0
        functions_mutated = 0

        for func in functions:
            if func.get("size", 0) < MINIMUM_FUNCTION_SIZE:
                continue

            try:
                instructions = binary.get_function_disasm(func["addr"])
            except (ValueError, OSError, BrokenPipeError, RuntimeError) as e:
                logger.debug(f"Failed to get disasm for {func.get('name')}: {e}")
                continue

            func_mutations = 0
            for insn in instructions:
                if not self._apply_arm32_instruction(binary, func, insn, arm32_nops):
                    continue
                func_mutations += 1
                mutations_applied += 1
                if func_mutations >= self.max_nops:
                    break

            if func_mutations > 0:
                functions_mutated += 1

        return {
            "mutations_applied": mutations_applied,
            "functions_mutated": functions_mutated,
            "total_functions": len(functions),
        }
