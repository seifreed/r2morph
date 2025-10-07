"""
Data dependency analysis for binary code.

Analyzes data flow and dependencies between instructions.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Set, Tuple

logger = logging.getLogger(__name__)


class DependencyType(Enum):
    """Types of dependencies between instructions."""

    READ_AFTER_WRITE = "RAW"
    WRITE_AFTER_READ = "WAR"
    WRITE_AFTER_WRITE = "WAW"
    READ_AFTER_READ = "RAR"


@dataclass
class Dependency:
    """
    Represents a data dependency between two instructions.
    """

    from_address: int
    to_address: int
    resource: str
    dep_type: DependencyType

    def __repr__(self) -> str:
        return (
            f"<Dep {self.dep_type.value}: 0x{self.from_address:x} -> "
            f"0x{self.to_address:x} on {self.resource}>"
        )


@dataclass
class InstructionDef:
    """
    Definition information for an instruction.
    """

    address: int
    defines: set[str] = field(default_factory=set)
    uses: set[str] = field(default_factory=set)

    def __repr__(self) -> str:
        return f"<InsnDef @ 0x{self.address:x} def={self.defines} use={self.uses}>"


class DependencyAnalyzer:
    """
    Analyzes data dependencies in binary code.

    Tracks register and memory dependencies to understand data flow.
    """

    def __init__(self):
        """Initialize dependency analyzer."""
        self.dependencies: list[Dependency] = []
        self.defs: dict[int, InstructionDef] = {}

    def _parse_operands(self, instruction: dict[str, Any]) -> Tuple[Set[str], Set[str]]:
        """
        Parse instruction to extract defined and used registers.

        Args:
            instruction: Instruction dictionary from radare2

        Returns:
            Tuple of (defines, uses) sets
        """
        defines = set()
        uses = set()

        disasm = instruction.get("disasm", "").lower()
        instruction.get("type", "")

        parts = disasm.split()
        if len(parts) < 2:
            return defines, uses

        mnemonic = parts[0]
        operands_str = " ".join(parts[1:])
        operands = [op.strip() for op in operands_str.split(",")]

        if mnemonic in ["mov", "movzx", "movsx", "lea"]:
            if len(operands) >= 2:
                defines.add(operands[0])
                uses.update(operands[1:])

        elif mnemonic in ["add", "sub", "and", "or", "xor", "imul", "mul"]:
            if len(operands) >= 1:
                defines.add(operands[0])
                uses.add(operands[0])
            if len(operands) >= 2:
                uses.update(operands[1:])

        elif mnemonic in ["inc", "dec", "neg", "not"]:
            if operands:
                defines.add(operands[0])
                uses.add(operands[0])

        elif mnemonic in ["push"]:
            if operands:
                uses.add(operands[0])
            uses.add("rsp")
            defines.add("rsp")

        elif mnemonic in ["pop"]:
            if operands:
                defines.add(operands[0])
            uses.add("rsp")
            defines.add("rsp")

        elif mnemonic in ["call"]:
            defines.update(["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"])
            uses.update(["rdi", "rsi", "rdx", "rcx", "r8", "r9"])

        elif mnemonic in ["ret"]:
            uses.add("rax")
            uses.add("rsp")

        elif mnemonic.startswith("j"):
            pass

        elif mnemonic in ["cmp", "test"]:
            uses.update(operands)
            defines.add("flags")

        defines = {d for d in defines if self._is_register(d)}
        uses = {u for u in uses if self._is_register(u)}

        return defines, uses

    def _is_register(self, operand: str) -> bool:
        """
        Check if operand is a register name.

        Args:
            operand: Operand string

        Returns:
            True if it's a register
        """
        register_prefixes = [
            "rax",
            "rbx",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
            "rbp",
            "rsp",
            "eax",
            "ebx",
            "ecx",
            "edx",
            "esi",
            "edi",
            "ebp",
            "esp",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
            "ax",
            "bx",
            "cx",
            "dx",
            "al",
            "bl",
            "cl",
            "dl",
        ]

        return any(operand.startswith(prefix) for prefix in register_prefixes)

    def analyze_dependencies(self, instructions: list[dict[str, Any]]) -> list[Dependency]:
        """
        Analyze data dependencies in a sequence of instructions.

        Args:
            instructions: List of instruction dictionaries

        Returns:
            List of dependencies found
        """
        self.dependencies = []
        self.defs = {}

        last_def: dict[str, int] = {}
        last_use: dict[str, int] = {}

        for insn in instructions:
            addr = insn.get("offset", 0)

            defines, uses = self._parse_operands(insn)

            self.defs[addr] = InstructionDef(address=addr, defines=defines, uses=uses)

            for reg in uses:
                if reg in last_def:
                    dep = Dependency(
                        from_address=last_def[reg],
                        to_address=addr,
                        resource=reg,
                        dep_type=DependencyType.READ_AFTER_WRITE,
                    )
                    self.dependencies.append(dep)

                if reg in last_use:
                    dep = Dependency(
                        from_address=last_use[reg],
                        to_address=addr,
                        resource=reg,
                        dep_type=DependencyType.READ_AFTER_READ,
                    )
                    self.dependencies.append(dep)

                last_use[reg] = addr

            for reg in defines:
                if reg in last_use:
                    dep = Dependency(
                        from_address=last_use[reg],
                        to_address=addr,
                        resource=reg,
                        dep_type=DependencyType.WRITE_AFTER_READ,
                    )
                    self.dependencies.append(dep)

                if reg in last_def:
                    dep = Dependency(
                        from_address=last_def[reg],
                        to_address=addr,
                        resource=reg,
                        dep_type=DependencyType.WRITE_AFTER_WRITE,
                    )
                    self.dependencies.append(dep)

                last_def[reg] = addr

        logger.debug(
            f"Found {len(self.dependencies)} dependencies in {len(instructions)} instructions"
        )

        return self.dependencies

    def get_dependencies_for_instruction(self, address: int) -> list[Dependency]:
        """
        Get all dependencies involving a specific instruction.

        Args:
            address: Instruction address

        Returns:
            List of dependencies
        """
        return [
            dep
            for dep in self.dependencies
            if dep.from_address == address or dep.to_address == address
        ]

    def has_dependency(self, from_addr: int, to_addr: int) -> bool:
        """
        Check if there's a dependency between two instructions.

        Args:
            from_addr: Source instruction address
            to_addr: Target instruction address

        Returns:
            True if dependency exists
        """
        return any(
            dep.from_address == from_addr and dep.to_address == to_addr for dep in self.dependencies
        )

    def get_dependency_chain(self, start_addr: int) -> list[int]:
        """
        Get the dependency chain starting from an instruction.

        Args:
            start_addr: Starting instruction address

        Returns:
            List of instruction addresses in dependency order
        """
        chain = [start_addr]
        visited = {start_addr}

        current = start_addr
        while True:
            next_deps = [
                dep
                for dep in self.dependencies
                if dep.from_address == current
                and dep.dep_type == DependencyType.READ_AFTER_WRITE
                and dep.to_address not in visited
            ]

            if not next_deps:
                break

            next_dep = next_deps[0]
            chain.append(next_dep.to_address)
            visited.add(next_dep.to_address)
            current = next_dep.to_address

        return chain

    def to_dot(self) -> str:
        """
        Generate GraphViz DOT representation of dependencies.

        Returns:
            DOT format string
        """
        lines = [
            "digraph Dependencies {",
            "  node [shape=box];",
            "",
        ]

        for addr in self.defs:
            lines.append(f'  "0x{addr:x}" [label="0x{addr:x}"];')

        for dep in self.dependencies:
            if dep.dep_type == DependencyType.READ_AFTER_WRITE:
                color = "red"
            elif dep.dep_type == DependencyType.WRITE_AFTER_READ:
                color = "blue"
            elif dep.dep_type == DependencyType.WRITE_AFTER_WRITE:
                color = "green"
            else:
                color = "gray"

            lines.append(
                f'  "0x{dep.from_address:x}" -> "0x{dep.to_address:x}" '
                f'[label="{dep.resource}", color={color}];'
            )

        lines.append("}")
        return "\n".join(lines)
