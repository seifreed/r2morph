"""Dispatcher-code templates extracted from ControlFlowFlatteningPass.

Slice 7 of the CFF clean-arch decomposition: the reference x86/ARM
dispatcher-loop generators (not applied to the binary by apply(); used
for analysis/tests). Pure builders with no pass state. Plain
intra-mutations/ collaborator (no protocol, ValidationManager
precedent); imports nothing from r2morph, so the direct import in
control_flow_flattening.py introduces no cycle.
"""

from __future__ import annotations

from typing import Any


class DispatcherGenerator:
    """Builds reference flattened-dispatcher assembly templates."""

    def generate(self, binary: Any, blocks: list[Any]) -> list[str]:
        """
        Generate dispatcher code (for reference/analysis purposes).

        Note: This generates dispatcher code but doesn't apply it to the binary.
        Full dispatcher-based flattening would require binary expansion which
        is not currently implemented.

        Args:
            binary: Any instance
            blocks: List of basic blocks

        Returns:
            List of assembly instructions
        """
        arch_family, bits = binary.get_arch_family()

        if arch_family == "x86":
            return self.generate_x86(blocks, bits)
        elif arch_family == "arm":
            return self.generate_arm(blocks, bits)

        return []

    @staticmethod
    def generate_x86(blocks: list[Any], bits: int) -> list[str]:
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

    @staticmethod
    def generate_arm(blocks: list[Any], bits: int) -> list[str]:
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
