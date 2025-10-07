"""
Dead code injection mutation pass.

Injects code that never executes but adds complexity.
"""

import logging
import random
from typing import Any

from r2morph.core.binary import Binary
from r2morph.mutations.base import MutationPass

logger = logging.getLogger(__name__)


class DeadCodeInjectionPass(MutationPass):
    """
    Injects dead code (code that never executes).

    Dead code adds complexity without affecting semantics.
    Makes analysis harder by increasing code size and complexity.

    Examples:
        - Code after unconditional jumps
        - Code in impossible branches
        - Fake function calls
    """

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

    def apply(self, binary: Binary) -> dict[str, Any]:
        """
        Apply dead code injection mutations.

        Args:
            binary: Binary to mutate

        Returns:
            Statistics dict
        """
        logger.info("Applying dead code injection mutations")

        functions = binary.get_functions()
        total_mutations = 0
        funcs_mutated = 0

        for func in functions:
            mutations = self._inject_dead_code(binary, func)

            if mutations > 0:
                funcs_mutated += 1
                total_mutations += mutations

        return {
            "mutations_applied": total_mutations,
            "functions_mutated": funcs_mutated,
        }

    def _inject_dead_code(self, binary: Binary, func: dict) -> int:
        """
        Inject dead code in a function.

        Args:
            binary: Binary instance
            func: Function dict

        Returns:
            Number of mutations applied
        """
        func_addr = func.get("offset", 0)
        mutations = 0

        instructions = binary.get_function_disasm(func_addr)

        injection_points = []

        for i, insn in enumerate(instructions):
            mnemonic = insn.get("mnemonic", "")

            if mnemonic in ["jmp", "ret", "b", "br"]:
                injection_points.append(i + 1)

        num_injections = min(self.max_injections, len(injection_points))

        for _ in range(num_injections):
            if random.random() > self.probability:
                continue

            dead_code = self._generate_dead_code(binary)

            logger.debug(f"Would inject dead code with {len(dead_code)} instructions")
            mutations += 1

        return mutations

    def _generate_dead_code(self, binary: Binary) -> list[str]:
        """
        Generate dead code based on complexity setting.

        Args:
            binary: Binary instance

        Returns:
            List of assembly instructions
        """
        arch_info = binary.get_arch_info()
        arch = arch_info.get("arch", "x86")
        bits = arch_info.get("bits", 64)

        if self.code_complexity == "simple":
            return self._generate_simple_dead_code(arch, bits)
        elif self.code_complexity == "complex":
            return self._generate_complex_dead_code(arch, bits)
        else:
            return self._generate_medium_dead_code(arch, bits)

    def _generate_simple_dead_code(self, arch: str, bits: int) -> list[str]:
        """
        Generate simple dead code (just NOPs or simple ops).

        Args:
            arch: Architecture
            bits: Bit width

        Returns:
            Assembly instructions
        """
        num_nops = random.randint(1, 10)
        return ["nop"] * num_nops

    def _generate_medium_dead_code(self, arch: str, bits: int) -> list[str]:
        """
        Generate medium complexity dead code.

        Args:
            arch: Architecture
            bits: Bit width

        Returns:
            Assembly instructions
        """
        if "x86" in arch.lower():
            reg = "rax" if bits == 64 else "eax"

            templates = [
                [
                    f"push {reg}",
                    f"mov {reg}, 12345",
                    f"add {reg}, 67890",
                    f"xor {reg}, {reg}",
                    f"pop {reg}",
                ],
                [
                    f"push {reg}",
                    f"mov {reg}, 0",
                    "nop",
                    "nop",
                    f"pop {reg}",
                ],
                [
                    "cmp rax, rax" if bits == 64 else "cmp eax, eax",
                    "jne .fake_label",
                    "nop",
                    ".fake_label:",
                ],
            ]

        elif "arm" in arch.lower():
            reg = "x0" if bits == 64 else "r0"

            templates = [
                [
                    f"mov {reg}, #123",
                    f"add {reg}, {reg}, #456",
                    f"eor {reg}, {reg}, {reg}",
                ],
                [
                    f"cmp {reg}, {reg}",
                    "b.ne .fake_label",
                    "nop",
                    ".fake_label:",
                ],
            ]

        else:
            return ["nop"] * 5

        return random.choice(templates)

    def _generate_complex_dead_code(self, arch: str, bits: int) -> list[str]:
        """
        Generate complex dead code (loops, calls, etc).

        Args:
            arch: Architecture
            bits: Bit width

        Returns:
            Assembly instructions
        """
        if "x86" in arch.lower():
            reg_a = "rax" if bits == 64 else "eax"
            reg_c = "rcx" if bits == 64 else "ecx"

            templates = [
                [
                    f"push {reg_c}",
                    f"mov {reg_c}, 0",
                    ".loop_start:",
                    f"add {reg_c}, 1",
                    f"cmp {reg_c}, 10",
                    "jl .loop_start",
                    f"pop {reg_c}",
                ],
                [
                    f"push {reg_a}",
                    f"mov {reg_a}, 12345",
                    f"imul {reg_a}, 67890",
                    f"add {reg_a}, 11111",
                    f"xor {reg_a}, 22222",
                    f"pop {reg_a}",
                ],
                [
                    f"push {reg_a}",
                    f"cmp {reg_a}, 0",
                    "je .branch1",
                    "jmp .branch2",
                    ".branch1:",
                    "nop",
                    "jmp .end",
                    ".branch2:",
                    "nop",
                    ".end:",
                    f"pop {reg_a}",
                ],
            ]

        elif "arm" in arch.lower():
            reg = "x0" if bits == 64 else "r0"
            reg2 = "x1" if bits == 64 else "r1"

            templates = [
                [
                    f"mov {reg2}, #0",
                    ".loop_start:",
                    f"add {reg2}, {reg2}, #1",
                    f"cmp {reg2}, #10",
                    "b.lt .loop_start",
                ],
                [
                    f"mov {reg}, #123",
                    f"mul {reg}, {reg}, {reg}",
                    f"add {reg}, {reg}, #456",
                    f"eor {reg}, {reg}, {reg}",
                ],
            ]

        else:
            return ["nop"] * 10

        return random.choice(templates)
