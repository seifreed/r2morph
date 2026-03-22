"""
Memory flow analysis for tracking memory operations.

Provides analysis of memory access patterns for:
- Memory dependency detection
- Memory alias analysis
- Stack/local variable tracking
- Heap allocation tracking
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class MemoryAccessType(Enum):
    """Type of memory access."""

    READ = "read"
    WRITE = "write"
    READ_WRITE = "read_write"
    ALLOC = "alloc"
    FREE = "free"


@dataclass
class MemoryLocation:
    """Represents a memory location."""

    address: int
    size: int
    name: str = ""
    location_type: str = "unknown"  # stack, heap, global, unknown

    def __hash__(self) -> int:
        return hash((self.address, self.size))

    def __repr__(self) -> str:
        if self.name:
            return f"<Mem 0x{self.address:x}:{self.size} {self.name}>"
        return f"<Mem 0x{self.address:x}:{self.size}>"

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": f"0x{self.address:x}",
            "size": self.size,
            "name": self.name,
            "type": self.location_type,
        }

    def overlaps(self, other: MemoryLocation) -> bool:
        """Check if this location overlaps with another."""
        return self.address < other.address + other.size and other.address < self.address + self.size


@dataclass
class MemoryAccess:
    """Represents a memory access at a specific instruction."""

    address: int  # Instruction address
    location: MemoryLocation
    access_type: MemoryAccessType
    instruction: str = ""
    registers_involved: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "instruction_address": f"0x{self.address:x}",
            "location": self.location.to_dict(),
            "access_type": self.access_type.value,
            "instruction": self.instruction,
            "registers": self.registers_involved,
        }


@dataclass
class MemoryDependency:
    """Represents a dependency between memory accesses."""

    source: MemoryAccess
    target: MemoryAccess
    dependency_type: str  # flow, anti, output
    is_alias: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source.to_dict(),
            "target": self.target.to_dict(),
            "type": self.dependency_type,
            "alias": self.is_alias,
        }


class MemoryFlowAnalyzer:
    """
    Analyzes memory flow patterns in binary code.

    Tracks:
    - Memory accesses (reads, writes, allocations)
    - Memory aliases (potential overlaps)
    - Stack frame layout
    - Heap objects
    """

    def __init__(self):
        self._accesses: dict[int, list[MemoryAccess]] = {}
        self._locations: dict[int, MemoryLocation] = {}
        self._aliases: dict[int, set[int]] = {}
        self._stack_frames: dict[int, dict[str, Any]] = {}
        self._heap_objects: dict[int, dict[str, Any]] = {}

    def analyze_function(
        self,
        instructions: list[dict[str, Any]],
        function_address: int,
    ) -> dict[str, Any]:
        """
        Analyze memory flow for a function.

        Args:
            instructions: List of instruction dictionaries
            function_address: Function start address

        Returns:
            Dictionary with analysis results
        """
        self._accesses.clear()
        self._locations.clear()

        stack_frame = self._analyze_stack_frame(instructions, function_address)

        for insn in instructions:
            addr = insn.get("offset", 0)
            disasm = insn.get("disasm", "").lower()

            self._analyze_instruction(addr, disasm, stack_frame)

        dependencies = self._compute_dependencies()
        aliases = self._detect_aliases()

        return {
            "function_address": f"0x{function_address:x}",
            "memory_accesses": {
                f"0x{addr:x}": [acc.to_dict() for acc in accs] for addr, accs in self._accesses.items()
            },
            "locations": {f"0x{addr:x}": loc.to_dict() for addr, loc in self._locations.items()},
            "dependencies": [dep.to_dict() for dep in dependencies],
            "aliases": {f"0x{addr:x}": [f"0x{a:x}" for a in aliases_set] for addr, aliases_set in aliases.items()},
            "stack_frame": stack_frame,
        }

    def _analyze_stack_frame(
        self,
        instructions: list[dict[str, Any]],
        function_address: int,
    ) -> dict[str, Any]:
        """Analyze stack frame layout for a function."""
        stack_frame: dict[str, Any] = {
            "local_vars": [],
            "saved_regs": [],
            "arguments": [],
            "frame_size": 0,
            "allocations": [],
        }

        frame_size = 0
        local_vars: dict[str, dict[str, Any]] = {}

        for insn in instructions:
            addr = insn.get("offset", 0)
            disasm = insn.get("disasm", "").lower()

            if "push" in disasm:
                import re

                match = re.search(r"push\s+(\w+)", disasm)
                if match:
                    reg = match.group(1)
                    stack_frame["saved_regs"].append(
                        {
                            "register": reg,
                            "offset": frame_size,
                            "address": f"0x{addr:x}",
                        }
                    )
                    frame_size += 8  # Assume 64-bit

            elif "sub" in disasm and "sp" in disasm:
                import re

                match = re.search(r"sub\s+sp,\s+#?(\d+)", disasm)
                if match:
                    size = int(match.group(1))
                    frame_size += size
                    stack_frame["allocations"].append(
                        {
                            "size": size,
                            "address": f"0x{addr:x}",
                        }
                    )

            elif "mov" in disasm and ("[sp" in disasm or "[rbp" in disasm):
                import re

                match = re.search(r"mov\s+\[.*?([+-]?\d+).*?\],\s+(\w+)", disasm)
                if match:
                    offset = int(match.group(1))
                    val = match.group(2)
                    var_name = f"var_{abs(offset)}"
                    if var_name not in local_vars:
                        local_vars[var_name] = {
                            "name": var_name,
                            "offset": offset,
                            "size": 4,  # Default size
                            "access_type": "write",
                            "address": f"0x{addr:x}",
                        }

            elif "mov" in disasm and ("[sp" in disasm or "[rbp" in disasm) and "," in disasm:
                import re

                match = re.search(r"mov\s+(\w+),\s+\[.*?([+-]?\d+).*?\]", disasm)
                if match:
                    reg = match.group(1)
                    offset = int(match.group(2))
                    var_name = f"var_{abs(offset)}"
                    if var_name not in local_vars:
                        local_vars[var_name] = {
                            "name": var_name,
                            "offset": offset,
                            "size": 4,
                            "access_type": "read",
                            "address": f"0x{addr:x}",
                        }

        stack_frame["local_vars"] = list(local_vars.values())
        stack_frame["frame_size"] = frame_size

        return stack_frame

    def _analyze_instruction(
        self,
        addr: int,
        disasm: str,
        stack_frame: dict[str, Any],
    ) -> None:
        """Analyze a single instruction for memory accesses."""
        if not disasm:
            return

        access_type = None
        size = 4  # Default size
        address = 0
        location_name = ""

        if "mov" in disasm and "[" in disasm:
            import re

            read_match = re.search(r"mov\s+(\w+),\s+\[([^\]]+)\]", disasm)
            write_match = re.search(r"mov\s+\[([^\]]+)\],\s+(\w+)", disasm)

            if read_match:
                access_type = MemoryAccessType.READ
                operand = read_match.group(2)
                registers = [read_match.group(1)]
            elif write_match:
                access_type = MemoryAccessType.WRITE
                operand = write_match.group(1)
                registers = [write_match.group(2)]
            else:
                return

            address = self._extract_memory_address(operand, stack_frame)
            size = self._extract_access_size(disasm)
            location_name = self._identify_location(operand, address, stack_frame)

        elif "ldr" in disasm:
            access_type = MemoryAccessType.READ
            import re

            match = re.search(r"ldr\s+\w+,\s+\[([^\]]+)\]", disasm)
            if match:
                operand = match.group(1)
                address = self._extract_memory_address(operand, stack_frame)
                size = self._extract_arm_access_size(disasm)
                location_name = self._identify_location(operand, address, stack_frame)
                registers = [re.search(r"ldr\s+(\w+)", disasm).group(1)] if re.search(r"ldr\s+(\w+)", disasm) else []

        elif "str" in disasm:
            access_type = MemoryAccessType.WRITE
            import re

            match = re.search(r"str\s+\w+,\s+\[([^\]]+)\]", disasm)
            if match:
                operand = match.group(1)
                address = self._extract_memory_address(operand, stack_frame)
                size = self._extract_arm_access_size(disasm)
                location_name = self._identify_location(operand, address, stack_frame)
                registers = [re.search(r"str\s+(\w+)", disasm).group(1)] if re.search(r"str\s+(\w+)", disasm) else []

        elif any(op in disasm for op in ["push", "pop"]):
            import re

            match = re.search(r"(push|pop)\s+(\w+)", disasm)
            if match:
                op = match.group(1)
                reg = match.group(2)
                if op == "push":
                    access_type = MemoryAccessType.WRITE
                    address = -8  # Stack pointer offset
                else:
                    access_type = MemoryAccessType.READ
                    address = 0
                size = 8
                location_name = "stack"
                registers = [reg]

        if access_type and address is not None:
            location = MemoryLocation(
                address=address,
                size=size,
                name=location_name,
                location_type="stack" if "stack" in location_name or address < 0 else "unknown",
            )

            access = MemoryAccess(
                address=addr,
                location=location,
                access_type=access_type,
                instruction=disasm,
                registers_involved=registers if "registers" in dir() else [],
            )

            if addr not in self._accesses:
                self._accesses[addr] = []
            self._accesses[addr].append(access)
            self._locations[address] = location

    def _extract_memory_address(self, operand: str, stack_frame: dict[str, Any]) -> int:
        """Extract memory address from operand."""
        import re

        operand = operand.strip()

        if operand.startswith("0x"):
            try:
                return int(operand, 16)
            except ValueError:
                return 0

        match = re.search(r"([+-]?\d+)", operand)
        if match:
            return int(match.group(1))

        return 0

    def _extract_access_size(self, disasm: str) -> int:
        """Extract memory access size from x86 instruction."""
        disasm_lower = disasm.lower()

        if "byte" in disasm_lower or "movzx" in disasm_lower and "al" in disasm_lower:
            return 1
        elif "word" in disasm_lower or "movzx" in disasm_lower and "ax" in disasm_lower:
            return 2
        elif "dword" in disasm_lower or "movzx" in disasm_lower and "eax" in disasm_lower:
            return 4
        elif "qword" in disasm_lower or ("mov" in disasm_lower and "rax" in disasm_lower):
            return 8
        elif "xmm" in disasm_lower or "movdqu" in disasm_lower or "movaps" in disasm_lower:
            return 16
        elif "ymm" in disasm_lower:
            return 32
        elif "zmm" in disasm_lower:
            return 64

        return 4

    def _extract_arm_access_size(self, disasm: str) -> int:
        """Extract memory access size from ARM instruction."""
        disasm_lower = disasm.lower()

        if "ldrb" in disasm_lower or "strb" in disasm_lower:
            return 1
        elif "ldrh" in disasm_lower or "strh" in disasm_lower:
            return 2
        elif "ldrsw" in disasm_lower:
            return 4
        elif "ldrsb" in disasm_lower:
            return 1
        elif "ldrsh" in disasm_lower:
            return 2
        elif "ldr" in disasm_lower or "str" in disasm_lower:
            if "w" in disasm_lower:
                return 4
            return 8
        elif "ldp" in disasm_lower or "stp" in disasm_lower:
            return 16
        elif "ldp" in disasm_lower and "q" in disasm_lower:
            return 32
        elif "vldr" in disasm_lower:
            if ".d" in disasm_lower:
                return 8
            elif ".s" in disasm_lower:
                return 4
            return 16

        return 4

    def _identify_location(self, operand: str, address: int, stack_frame: dict[str, Any]) -> str:
        """Identify the memory location type."""
        operand_lower = operand.lower()

        if "sp" in operand_lower or "rbp" in operand_lower or "ebp" in operand_lower or "fp" in operand_lower:
            return f"stack_{abs(address)}"
        elif "rbx" in operand_lower or "r12" in operand_lower or "r13" in operand_lower:
            return f"stack_base"

        for var in stack_frame.get("local_vars", []):
            if var.get("offset") == address:
                return var.get("name", f"stack_{abs(address)}")

        return f"unknown_{abs(address) if address else 0}"

    def _compute_dependencies(self) -> list[MemoryDependency]:
        """Compute memory dependencies between accesses."""
        dependencies: list[MemoryDependency] = []
        accesses_list = [(addr, acc) for addr, accs in self._accesses.items() for acc in accs]

        for i, (addr1, acc1) in enumerate(accesses_list):
            for addr2, acc2 in accesses_list[i + 1 :]:
                if acc1.location.overlaps(acc2.location):
                    if acc1.access_type == MemoryAccessType.WRITE and acc2.access_type == MemoryAccessType.READ:
                        dependencies.append(
                            MemoryDependency(
                                source=acc1,
                                target=acc2,
                                dependency_type="flow",
                            )
                        )
                    elif acc1.access_type == MemoryAccessType.READ and acc2.access_type == MemoryAccessType.WRITE:
                        dependencies.append(
                            MemoryDependency(
                                source=acc1,
                                target=acc2,
                                dependency_type="anti",
                            )
                        )
                    elif acc1.access_type == MemoryAccessType.WRITE and acc2.access_type == MemoryAccessType.WRITE:
                        dependencies.append(
                            MemoryDependency(
                                source=acc1,
                                target=acc2,
                                dependency_type="output",
                            )
                        )

        return dependencies

    def _detect_aliases(self) -> dict[int, set[int]]:
        """Detect potential memory aliases."""
        aliases: dict[int, set[int]] = {}

        locations = list(self._locations.items())

        for i, (addr1, loc1) in enumerate(locations):
            for addr2, loc2 in locations[i + 1 :]:
                if loc1.overlaps(loc2):
                    if addr1 not in aliases:
                        aliases[addr1] = set()
                    if addr2 not in aliases:
                        aliases[addr2] = set()

                    aliases[addr1].add(addr2)
                    aliases[addr2].add(addr1)

        return aliases

    def get_accesses_at(self, address: int) -> list[MemoryAccess]:
        """Get all memory accesses at a specific address."""
        return self._accesses.get(address, [])

    def get_location_info(self, address: int) -> MemoryLocation | None:
        """Get information about a memory location."""
        return self._locations.get(address)

    def get_potential_aliases(self, address: int) -> set[int]:
        """Get addresses that might alias with given address."""
        return self._aliases.get(address, set())


class InterproceduralDataFlowAnalyzer:
    """
    Performs interprocedural data flow analysis.

    Tracks data flow across function boundaries using:
    - Function summaries
    - Call graph propagation
    - Context sensitivity
    """

    def __init__(self):
        self._function_summaries: dict[int, dict[str, Any]] = {}
        self._call_graph: dict[int, list[int]] = {}

    def analyze_program(
        self,
        functions: list[dict[str, Any]],
        call_graph: dict[int, list[int]],
    ) -> dict[str, Any]:
        """
        Perform interprocedural analysis on a program.

        Args:
            functions: List of function dictionaries with instructions
            call_graph: Dict mapping function address to list of call targets

        Returns:
            Dictionary with analysis results
        """
        self._call_graph = call_graph
        self._function_summaries.clear()

        for func in functions:
            func_addr = func.get("offset", func.get("addr", 0))
            instructions = func.get("instructions", func.get("disasm", []))

            summary = self._analyze_function_summary(func_addr, instructions)
            self._function_summaries[func_addr] = summary

        propagated = self._propagate_through_call_graph()

        return {
            "function_summaries": {f"0x{addr:x}": summary for addr, summary in self._function_summaries.items()},
            "call_graph": {
                f"0x{caller:x}": [f"0x{callee:x}" for callee in callees] for caller, callees in self._call_graph.items()
            },
            "propagated_values": propagated,
        }

    def _analyze_function_summary(
        self,
        func_addr: int,
        instructions: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Compute a function summary for interprocedural analysis.

        A summary captures:
        - Input/output parameters
        - Side effects
        - Return values
        - Modified globals
        """
        summary: dict[str, Any] = {
            "address": f"0x{func_addr:x}",
            "parameters": [],
            "return_values": [],
            "side_effects": [],
            "modified_registers": set(),
            "read_globals": set(),
            "written_globals": set(),
        }

        for insn in instructions:
            disasm = insn.get("disasm", "").lower()
            addr = insn.get("offset", 0)

            if "mov" in disasm or "ldr" in disasm:
                import re

                match = re.search(r"(mov|ldr)\s+(\w+),", disasm)
                if match:
                    summary["modified_registers"].add(match.group(2))

            if "push" in disasm or "pop" in disasm:
                import re

                match = re.search(r"(push|pop)\s+(\w+)", disasm)
                if match:
                    summary["modified_registers"].add(match.group(2))

            if "call" in disasm or "bl" in disasm:
                summary["side_effects"].append(
                    {
                        "type": "call",
                        "address": f"0x{addr:x}",
                        "instruction": disasm,
                    }
                )

            if "ret" in disasm or "bx lr" in disasm:
                import re

                match = re.search(r"mov\s+(\w+),", disasm)
                if match:
                    summary["return_values"].append(
                        {
                            "register": match.group(1),
                            "type": "return",
                        }
                    )

        summary["modified_registers"] = list(summary["modified_registers"])
        summary["read_globals"] = list(summary["read_globals"])
        summary["written_globals"] = list(summary["written_globals"])

        return summary

    def _propagate_through_call_graph(self) -> dict[str, Any]:
        """Propagate data flow information through the call graph."""
        propagated: dict[str, Any] = {
            "parameter_bindings": {},
            "value_flow": {},
        }

        visited: set[int] = set()

        for func_addr in self._function_summaries:
            self._propagate_from_function(func_addr, visited, propagated)

        return propagated

    def _propagate_from_function(
        self,
        func_addr: int,
        visited: set[int],
        propagated: dict[str, Any],
    ) -> None:
        """Propagate data flow from a function."""
        if func_addr in visited:
            return

        visited.add(func_addr)

        summary = self._function_summaries.get(func_addr, {})
        callees = self._call_graph.get(func_addr, [])

        for callee_addr in callees:
            callee_summary = self._function_summaries.get(callee_addr, {})

            for param in callee_summary.get("parameters", []):
                key = f"0x{func_addr:x}:0x{callee_addr:x}:{param.get('name', 'unknown')}"
                propagated["parameter_bindings"][key] = {
                    "caller": f"0x{func_addr:x}",
                    "callee": f"0x{callee_addr:x}",
                    "parameter": param,
                }

            for ret_val in callee_summary.get("return_values", []):
                key = f"0x{callee_addr:x}:return:{ret_val.get('register', 'unknown')}"
                propagated["value_flow"][key] = {
                    "function": f"0x{callee_addr:x}",
                    "return_value": ret_val,
                    "callers": [f"0x{func_addr:x}"],
                }
