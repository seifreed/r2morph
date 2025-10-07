"""
NOP insertion mutation pass.

Inserts NOP (no operation) instructions at safe locations in the binary.
Note: Currently only overwrites truly redundant instructions to avoid breaking the binary.
"""

import logging
import random
from typing import Any

from r2morph.core.binary import Binary
from r2morph.mutations.base import MutationPass

logger = logging.getLogger(__name__)


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

    NOP_EQUIVALENTS_BASE = {
        "x86": [
            "xchg eax, eax",
            "xchg ebx, ebx",
            "xchg ecx, ecx",
            "xchg edx, edx",
            "lea eax, [eax]",
            "lea ebx, [ebx]",
            "lea ecx, [ecx]",
            "lea edx, [edx]",
            "mov eax, eax",
            "mov ebx, ebx",
            "mov ecx, ecx",
            "mov edx, edx",
            "xchg rax, rax",
            "xchg rbx, rbx",
            "xchg rcx, rcx",
            "xchg rdx, rdx",
            "lea rax, [rax]",
            "lea rbx, [rbx]",
            "lea rcx, [rcx]",
            "lea rdx, [rdx]",
        ]
    }

    REGISTERS_32BIT = ["eax", "ebx", "ecx", "edx", "esi", "edi"]
    REGISTERS_64BIT = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi"]

    def _init_nop_equivalents(self):
        """
        Initialize and shuffle NOP equivalents (r2morph-style re-seeding).

        This method is called after each successful mutation to ensure
        different NOP patterns are used each time.
        """
        self.NOP_EQUIVALENTS = {}
        for arch, patterns in self.NOP_EQUIVALENTS_BASE.items():
            shuffled = patterns.copy()
            random.shuffle(shuffled)
            self.NOP_EQUIVALENTS[arch] = shuffled

    def _generate_jmp_dead_code(
        self, size: int, bits: int, binary: Binary, function_addr: int | None = None
    ) -> bytes | None:
        """
        Generate jmp + dead code pattern (r2morph-STYLE).

        Creates a short jump that skips over dead code instructions that never execute.
        This is the signature obfuscation technique used by r2morph.

        Args:
            size: Total size needed in bytes
            bits: Architecture bits (32 or 64)
            binary: Binary instance for assembling
            function_addr: Function address for resolving symbolic variables (optional)

        Returns:
            Assembled bytes or None if not possible

        Examples:
            size=3, bits=32 → "jmp 1; inc eax"  (jmp skips inc)
            size=4, bits=64 → "jmp 2; pop rax"  (jmp skips pop)
        """
        regs = self.REGISTERS_32BIT if bits == 32 else self.REGISTERS_64BIT

        patterns = []

        if size == 3 and bits == 32:
            patterns = [
                f"jmp 1; inc {random.choice(regs)}",
                f"jmp 1; push {random.choice(regs)}",
                f"jmp 1; pop {random.choice(regs)}",
            ]

        elif size == 4 and bits == 32:
            patterns = [
                f"jmp 2; inc {random.choice(regs)}; inc {random.choice(regs)}",
                f"jmp 2; push {random.choice(regs)}; pop {random.choice(regs)}",
                f"jmp 2; pop {random.choice(regs)}; push {random.choice(regs)}",
            ]

        elif size == 3 and bits == 64:
            patterns = [
                f"jmp 1; push {random.choice(regs)}",
                f"jmp 1; pop {random.choice(regs)}",
            ]

        elif size == 4 and bits == 64:
            patterns = [
                f"jmp 2; pop {random.choice(regs)}; pop {random.choice(regs)}",
                f"jmp 2; push {random.choice(regs)}; push {random.choice(regs)}",
                f"jmp 2; push {random.choice(regs)}; pop {random.choice(regs)}",
                f"jmp 2; pop {random.choice(regs)}; push {random.choice(regs)}",
            ]

        elif size == 5 and bits == 64:
            patterns = [
                f"jmp 3; push {random.choice(regs)}; push {random.choice(regs)}",
                f"jmp 3; pop {random.choice(regs)}; pop {random.choice(regs)}",
            ]

        if not patterns:
            return None

        random.shuffle(patterns)
        for pattern in patterns:
            try:
                instructions = [i.strip() for i in pattern.split(";")]
                all_bytes = b""

                for inst in instructions:
                    inst_bytes = binary.assemble(inst, function_addr)
                    if not inst_bytes:
                        all_bytes = None
                        break
                    all_bytes += inst_bytes

                if all_bytes and len(all_bytes) == size:
                    return all_bytes

            except Exception as e:
                logger.debug(f"Failed to assemble jmp pattern '{pattern}': {e}")
                continue

        return None

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

        self._init_nop_equivalents()

    def apply(self, binary: Binary) -> dict[str, Any]:
        """
        Apply NOP insertion mutations to the binary.

        Args:
            binary: Binary instance to mutate

        Returns:
            Dictionary with mutation statistics
        """
        if not binary.is_analyzed():
            logger.warning("Binary not analyzed, analyzing now...")
            binary.analyze()

        functions = binary.get_functions()
        mutations_applied = 0
        functions_mutated = 0

        logger.info(
            f"NOP insertion: processing {len(functions)} functions "
            f"(max {self.max_nops} NOPs per function)"
        )

        for func in functions:
            if func.get("size", 0) < 10:
                continue

            try:
                instructions = binary.get_function_disasm(func["addr"])
            except Exception as e:
                logger.debug(f"Failed to get disasm for {func.get('name')}: {e}")
                continue

            candidates = []
            for _i, insn in enumerate(instructions):
                disasm = insn.get("disasm", "").lower()
                insn_type = insn.get("type", "")

                is_redundant = False

                if "mov" in disasm:
                    parts = disasm.split(",")
                    if len(parts) == 2:
                        src = parts[1].strip()
                        dst = parts[0].split()[-1].strip() if " " in parts[0] else ""
                        if src == dst:
                            is_redundant = True

                if any(op in disasm for op in ["add", "sub", "or", "xor"]) and ", 0" in disasm:
                    is_redundant = True

                if insn_type in ["jmp", "cjmp", "call", "ret", "ujmp", "rcall"]:
                    is_redundant = False

                if is_redundant:
                    candidates.append(insn)

            nops_to_insert = min(self.max_nops, len(candidates))
            selected = random.sample(candidates, min(nops_to_insert, len(candidates)))

            func_mutations = 0
            for insn in selected:
                if random.random() < self.probability:
                    addr = insn.get("addr", 0)
                    size = insn.get("size", 0)

                    if addr == 0 or size == 0:
                        continue

                    try:
                        arch_info = binary.get_arch_info()
                        arch = arch_info.get("arch", "unknown")
                        bits = arch_info.get("bits", 32)
                        arch_family = "x86" if arch in ["x86", "x64"] else arch

                        nop_written = False

                        if self.use_creative_nops and random.random() < 0.7:
                            if size in [3, 4, 5] and arch_family == "x86":
                                jmp_bytes = self._generate_jmp_dead_code(
                                    size, bits, binary, func["addr"]
                                )
                                if jmp_bytes:
                                    binary.write_bytes(addr, jmp_bytes)
                                    logger.info(
                                        f"Inserted jmp+dead code NOP ({size} bytes) at 0x{addr:x} "
                                        f"(was: {insn.get('disasm', 'unknown')})"
                                    )
                                    nop_written = True

                            if not nop_written and arch_family in self.NOP_EQUIVALENTS:
                                equivalents = self.NOP_EQUIVALENTS[arch_family]
                                random.shuffle(equivalents)

                                for nop_equiv in equivalents:
                                    nop_bytes = binary.assemble(nop_equiv, func["addr"])
                                    if nop_bytes and len(nop_bytes) <= size:
                                        binary.write_bytes(addr, nop_bytes)

                                        if len(nop_bytes) < size:
                                            binary.nop_fill(
                                                addr + len(nop_bytes), size - len(nop_bytes)
                                            )

                                        logger.info(
                                            f"Inserted creative NOP '{nop_equiv}' at 0x{addr:x} "
                                            f"(was: {insn.get('disasm', 'unknown')})"
                                        )
                                        nop_written = True
                                        break

                        if not nop_written:
                            binary.nop_fill(addr, size)
                            logger.info(
                                f"Inserted {size} plain NOPs at 0x{addr:x} "
                                f"(was: {insn.get('disasm', 'unknown')})"
                            )

                        func_mutations += 1
                        mutations_applied += 1

                        self._init_nop_equivalents()

                    except Exception as e:
                        logger.error(f"Failed to insert NOP at 0x{addr:x}: {e}")

            if func_mutations > 0:
                functions_mutated += 1

        logger.info(
            f"NOP insertion complete: {mutations_applied} NOPs inserted "
            f"in {functions_mutated} functions"
        )

        return {
            "mutations_applied": mutations_applied,
            "functions_mutated": functions_mutated,
            "total_functions": len(functions),
        }
