"""
Opaque predicate injection mutation pass.

Injects conditionals that are always true or always false,
but appear complex to analysis tools.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import r2morph.core.randomness as random
from r2morph.core.constants import (
    ARCH_BITS_64,
    OPAQUE_PREDICATE_MIN_FUNCTION_SIZE,
    SIGNED_32_MAX,
    SIGNED_32_MIN,
    X86_RELATIVE_BRANCH_SIZE_BYTES,
)
from r2morph.mutations.base import MutationPass
from r2morph.mutations.relocation_safety import (
    has_memory_operand,
    has_pc_relative_memory_operand,
    instructions_are_relocatable,
)
from r2morph.relocations.cave_injector import CodeCaveInjector

logger = logging.getLogger(__name__)


class OpaquePredicatePass(MutationPass):
    """
    Inserts opaque predicates (always-true or always-false conditions).

    Opaque predicates add complexity to control flow without changing semantics.
    Makes static analysis harder while preserving dynamic behavior.

    Examples:
        - if (x * x >= 0) { real_code; } // Always true
        - if ((x % 2 == 0) || (x % 2 == 1)) { real_code; } // Always true
        - if (x * x < 0) { fake_code; } // Always false
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize opaque predicate pass.

        Args:
            config: Configuration dictionary
        """
        super().__init__(name="OpaquePredicates", config=config)
        self.max_predicates = self.config.get("max_predicates_per_function", 3)
        self.probability = self.config.get("probability", 0.3)

    def apply(self, binary: Any) -> dict[str, Any]:
        """
        Apply opaque predicate mutations.

        Args:
            binary: Any to mutate

        Returns:
            Statistics dict
        """
        self._reset_random()
        logger.info("Applying opaque predicate mutations")

        functions = binary.get_functions()
        total_mutations = 0
        funcs_mutated = 0

        for func in functions:
            func.get("addr", 0)

            if func.get("size", 0) < OPAQUE_PREDICATE_MIN_FUNCTION_SIZE:
                continue

            mutations = self._insert_opaque_predicates(binary, func)

            if mutations > 0:
                funcs_mutated += 1
                total_mutations += mutations

        return {
            "mutations_applied": total_mutations,
            "functions_mutated": funcs_mutated,
        }

    def _insert_opaque_predicates(self, binary: Any, func: dict[str, Any]) -> int:
        """
        Insert opaque predicates in a function.

        Args:
            binary: Any instance
            func: Function dict

        Returns:
            Number of mutations applied
        """
        func_addr = func.get("addr", 0)
        mutations = 0

        try:
            bb_json = binary.r2.cmd(f"afbj @ 0x{func_addr:x}")
            basic_blocks = json.loads(bb_json) if bb_json else []
        except (ValueError, OSError, BrokenPipeError, json.JSONDecodeError) as e:
            logger.debug(f"Failed to get basic blocks: {e}")
            return 0

        num_predicates = min(self.max_predicates, len(basic_blocks) // 2)
        arch_info = binary.get_arch_info()
        if str(arch_info.get("arch", "")).lower() not in {"x86", "x86_64", "amd64"}:
            logger.debug("Skipping opaque predicates: rel32 relocation is only implemented for x86")
            return 0

        mutation_checkpoint = self._create_mutation_checkpoint("opaque_predicate")
        baseline = {}
        if self._validation_manager is not None:
            baseline = self._validation_manager.capture_structural_baseline(binary, func_addr)

        injector = CodeCaveInjector(binary)
        for _ in range(num_predicates):
            if random.random() > self.probability:
                continue

            if not basic_blocks:
                break

            bb = random.choice(basic_blocks)
            bb_addr = bb.get("addr", 0)
            bb_size = bb.get("size", 0)

            predicate_type = random.choice(
                [
                    "always_true",
                    "always_false",
                ]
            )

            predicate = self._generate_predicate(binary, predicate_type)
            relocation = self._relocate_predicate(binary, injector, bb_addr, bb_size, predicate)
            if relocation is None:
                continue
            cave_address, original_bytes, mutated_bytes = relocation
            self._record_mutation(
                function_address=func_addr,
                start_address=bb_addr,
                end_address=bb_addr + len(original_bytes) - 1,
                original_bytes=original_bytes,
                mutated_bytes=mutated_bytes,
                original_disasm=f"block prefix at 0x{bb_addr:x}",
                mutated_disasm=f"opaque {predicate_type} predicate",
                mutation_kind="opaque_predicate",
                metadata={
                    "cave_address": cave_address,
                    "predicate_type": predicate_type,
                    "structural_baseline": baseline,
                },
            )
            mutations += 1
            logger.debug("Inserted %s predicate at 0x%x via cave 0x%x", predicate_type, bb_addr, cave_address)

        if mutations > 0 and self._validation_manager is not None and mutation_checkpoint is not None and self._records:
            outcome = self._validation_manager.validate_mutation(binary, self._records[-1].to_dict())
            if not outcome.passed:
                self._rollback_mutation(binary, mutation_checkpoint)
                return 0

        return mutations

    @staticmethod
    def _has_pc_relative_memory_operand(instruction: dict[str, Any]) -> bool | None:
        """Return whether an x86 instruction uses RIP-relative memory."""
        return has_pc_relative_memory_operand(instruction)

    @staticmethod
    def _has_memory_operand(instruction: dict[str, Any]) -> bool | None:
        """Return whether an x86 instruction accesses memory."""
        return has_memory_operand(instruction)

    @staticmethod
    def _relocatable_prefix(binary: Any, address: int, block_size: int) -> tuple[bytes, int] | None:
        """Return a contiguous, branch-free prefix large enough for a trampoline."""
        try:
            instructions = binary.r2.cmdj(f"pdj {block_size} @ {address}") or []
        except (AttributeError, OSError, RuntimeError, ValueError):
            return None
        prefix: list[dict[str, Any]] = []
        prefix_size = 0
        for instruction in instructions:
            offset = instruction.get("offset", instruction.get("addr"))
            size = instruction.get("size")
            if not isinstance(offset, int) or not isinstance(size, int) or size < 1:
                return None
            if offset != address + prefix_size or prefix_size + size > block_size:
                break
            mnemonic = str(instruction.get("disasm", "")).split(maxsplit=1)[0].lower()
            pc_relative = OpaquePredicatePass._has_pc_relative_memory_operand(instruction)
            memory_operand = has_memory_operand(instruction)
            if (
                mnemonic.startswith("ret")
                or not instructions_are_relocatable([instruction])
                or pc_relative is not False
                or memory_operand is not False
            ):
                break
            prefix.append(instruction)
            prefix_size += size
            if prefix_size >= X86_RELATIVE_BRANCH_SIZE_BYTES:
                original_bytes = binary.read_bytes(address, prefix_size)
                if len(original_bytes) == prefix_size:
                    return bytes(original_bytes), prefix_size
                return None
        return None

    @staticmethod
    def _relative_jump(target: int, source: int) -> bytes | None:
        """Encode an x86 rel32 jump from ``source`` to ``target``."""
        offset = target - (source + X86_RELATIVE_BRANCH_SIZE_BYTES)
        if not SIGNED_32_MIN <= offset <= SIGNED_32_MAX:
            return None
        return b"\xe9" + offset.to_bytes(4, "little", signed=True)

    def _prepare_predicate_relocation(
        self,
        binary: Any,
        injector: CodeCaveInjector,
        block_address: int,
        block_size: int,
        predicate: list[str],
    ) -> tuple[int, int, bytes, bytes, bytes] | None:
        """Build the cave payload and original trampoline without writing bytes."""
        result: tuple[int, int, bytes, bytes, bytes] | None = None
        prefix_data = self._relocatable_prefix(binary, block_address, block_size)
        if prefix_data is not None:
            original_bytes, prefix_size = prefix_data
            probe = self._assemble_predicate(binary, predicate, block_address)
            if probe is not None:
                needed = len(probe) + prefix_size + X86_RELATIVE_BRANCH_SIZE_BYTES
                cave = injector.find_cave_for_code(needed, require_executable=True)
                if cave is not None:
                    allocation = injector.allocate_from_cave(cave, needed, alignment=1)
                    predicate_bytes = self._assemble_predicate(binary, predicate, allocation.address)
                    return_jump = self._relative_jump(
                        block_address + prefix_size,
                        allocation.address + len(predicate_bytes or b"") + prefix_size,
                    )
                    trampoline = self._relative_jump(allocation.address, block_address)
                    if (
                        predicate_bytes is not None
                        and len(predicate_bytes) == len(probe)
                        and return_jump is not None
                        and trampoline is not None
                    ):
                        payload = predicate_bytes + original_bytes + return_jump
                        rewritten = trampoline + b"\x90" * (prefix_size - X86_RELATIVE_BRANCH_SIZE_BYTES)
                        result = allocation.address, needed, payload, rewritten, original_bytes
        return result

    def _relocate_predicate(
        self,
        binary: Any,
        injector: CodeCaveInjector,
        block_address: int,
        block_size: int,
        predicate: list[str],
    ) -> tuple[int, bytes, bytes] | None:
        """Relocate a safe block prefix so predicate injection preserves execution."""
        plan = self._prepare_predicate_relocation(binary, injector, block_address, block_size, predicate)
        if plan is None:
            return None
        cave_address, needed, payload, rewritten, original_bytes = plan
        cave_bytes = binary.read_bytes(cave_address, needed)
        if not binary.write_bytes(cave_address, payload):
            return None
        if binary.write_bytes(block_address, rewritten):
            return cave_address, original_bytes, rewritten
        binary.write_bytes(cave_address, cave_bytes)
        return None

    def _assemble_predicate(self, binary: Any, instructions: list[str], addr: int) -> bytes | None:
        """
        Assemble predicate instructions into bytes.

        Args:
            binary: Any instance
            instructions: List of assembly instructions
            addr: Address to assemble at

        Returns:
            Assembled bytes or None on failure
        """
        label_pattern = re.compile(r"^(?P<mnemonic>j[a-z]+)\s+\.(?P<label>[A-Za-z_][A-Za-z0-9_]*)$")
        sizes: dict[int, int] = {}
        labels: dict[str, int] = {}

        for _ in range(3):
            labels = {}
            current_addr = addr
            for index, insn in enumerate(instructions):
                label = insn.removesuffix(":")
                if insn.startswith("."):
                    labels[label[1:]] = current_addr
                    continue
                match = label_pattern.match(insn)
                assembly = insn
                if match:
                    target = labels.get(match.group("label"), current_addr + sizes.get(index, 2))
                    assembly = f"{match.group('mnemonic')} 0x{target:x}"
                insn_bytes = binary.assemble(assembly, current_addr)
                if insn_bytes is None:
                    return None
                sizes[index] = len(insn_bytes)
                current_addr += len(insn_bytes)

        assembled = bytearray()
        current_addr = addr
        for insn in instructions:
            if insn.startswith("."):
                continue
            match = label_pattern.match(insn)
            assembly = insn
            if match:
                resolved_target = labels.get(match.group("label"))
                if resolved_target is None:
                    return None
                assembly = f"{match.group('mnemonic')} 0x{resolved_target:x}"
            insn_bytes = binary.assemble(assembly, current_addr)
            if insn_bytes is None:
                return None
            assembled.extend(insn_bytes)
            current_addr += len(insn_bytes)

        return bytes(assembled) if assembled else None

    def _generate_predicate(self, binary: Any, predicate_type: str) -> list[str]:
        """
        Generate opaque predicate assembly code.

        Args:
            binary: Any instance
            predicate_type: "always_true" or "always_false"

        Returns:
            List of assembly instructions
        """
        arch_info = binary.get_arch_info()
        arch = arch_info.get("arch", "x86")
        bits = arch_info.get("bits", 64)

        if "x86" in arch.lower():
            return self._generate_x86_predicate(predicate_type, bits)
        elif "arm" in arch.lower():
            return self._generate_arm_predicate(predicate_type, bits)

        return []

    def _generate_x86_predicate(self, predicate_type: str, bits: int) -> list[str]:
        """
        Generate x86 opaque predicate.

        Args:
            predicate_type: Type of predicate
            bits: Bit width

        Returns:
            Assembly instructions
        """
        if bits == ARCH_BITS_64:
            flags_push = "pushfq"
            flags_pop = "popfq"
            scratch = "r11"
            scratch32 = "r11d"
        else:
            flags_push = "pushfd"
            flags_pop = "popfd"
            scratch = "edx"
            scratch32 = scratch

        if predicate_type == "always_true":
            predicates = [
                [
                    flags_push,
                    f"push {scratch}",
                    f"xor {scratch32}, {scratch32}",
                    f"test {scratch32}, {scratch32}",
                    "jz .real_code",
                    "nop",
                    ".real_code:",
                    f"pop {scratch}",
                    flags_pop,
                ],
                [
                    flags_push,
                    f"push {scratch}",
                    f"xor {scratch32}, {scratch32}",
                    f"test {scratch32}, {scratch32}",
                    "jz .real_code",
                    "nop",
                    ".real_code:",
                    f"pop {scratch}",
                    flags_pop,
                ],
                [
                    flags_push,
                    f"push {scratch}",
                    f"xor {scratch32}, {scratch32}",
                    f"test {scratch32}, {scratch32}",
                    "jz .real_code",
                    "nop",
                    ".real_code:",
                    f"pop {scratch}",
                    flags_pop,
                ],
                [
                    flags_push,
                    f"push {scratch}",
                    f"xor {scratch32}, {scratch32}",
                    f"test {scratch32}, {scratch32}",
                    "jz .real_code",
                    "nop",
                    ".real_code:",
                    f"pop {scratch}",
                    flags_pop,
                ],
            ]

        else:
            predicates = [
                [
                    flags_push,
                    f"push {scratch}",
                    f"xor {scratch32}, {scratch32}",
                    f"test {scratch32}, {scratch32}",
                    "jnz .fake_code",
                    "jmp .real_code",
                    ".fake_code:",
                    "nop",
                    ".real_code:",
                    f"pop {scratch}",
                    flags_pop,
                ],
                [
                    flags_push,
                    f"push {scratch}",
                    f"xor {scratch32}, {scratch32}",
                    f"test {scratch32}, {scratch32}",
                    "jne .fake_code",
                    "jmp .real_code",
                    ".fake_code:",
                    "nop",
                    ".real_code:",
                    f"pop {scratch}",
                    flags_pop,
                ],
            ]

        return random.choice(predicates)

    def _generate_arm_predicate(self, predicate_type: str, bits: int) -> list[str]:
        """
        Generate ARM opaque predicate.

        Args:
            predicate_type: Type of predicate
            bits: Bit width

        Returns:
            Assembly instructions
        """
        reg = "x0" if bits == ARCH_BITS_64 else "r0"

        if predicate_type == "always_true":
            predicates = [
                [
                    f"mul {reg}, {reg}, {reg}",
                    f"cmp {reg}, #0",
                    "b.ge .real_code",
                    ".real_code:",
                ],
                [
                    f"cmp {reg}, {reg}",
                    "b.eq .real_code",
                    ".real_code:",
                ],
            ]

        else:
            predicates = [
                [
                    f"mul {reg}, {reg}, {reg}",
                    f"cmp {reg}, #0",
                    "b.lt .fake_code",
                    "b .real_code",
                    ".fake_code:",
                    "nop",
                    ".real_code:",
                ],
            ]

        return random.choice(predicates)
