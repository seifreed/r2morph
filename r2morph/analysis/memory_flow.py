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
import re
from typing import Any

from r2morph.analysis.memory_flow_helpers import (
    record_saved_register,
    record_stack_allocation,
    record_stack_local,
)
from r2morph.analysis.memory_flow_interprocedural import InterproceduralDataFlowAnalyzer
from r2morph.analysis.memory_flow_models import (
    MemoryAccess,
    MemoryAccessType,
    MemoryDependency,
    MemoryLocation,
    _DecodedAccess,
)

logger = logging.getLogger(__name__)

__all__ = ["MemoryFlowAnalyzer", "InterproceduralDataFlowAnalyzer"]


class MemoryFlowAnalyzer:
    """
    Analyzes memory flow patterns in binary code.

    Tracks:
    - Memory accesses (reads, writes, allocations)
    - Memory aliases (potential overlaps)
    - Stack frame layout
    - Heap objects
    """

    def __init__(self) -> None:
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
            frame_size = self._scan_stack_instruction(
                disasm,
                addr,
                frame_size,
                stack_frame=stack_frame,
                local_vars=local_vars,
            )

        stack_frame["local_vars"] = list(local_vars.values())
        stack_frame["frame_size"] = frame_size

        return stack_frame

    @staticmethod
    def _scan_stack_instruction(
        disasm: str,
        addr: int,
        frame_size: int,
        *,
        stack_frame: dict[str, Any],
        local_vars: dict[str, dict[str, Any]],
    ) -> int:
        """Update the stack-frame accumulators for one instruction.

        Returns the (possibly grown) frame size.
        """
        if "push" in disasm:
            return record_saved_register(disasm, addr, frame_size, stack_frame)
        if "sub" in disasm and "sp" in disasm:
            return record_stack_allocation(disasm, addr, frame_size, stack_frame)
        if "mov" in disasm and ("[sp" in disasm or "[rbp" in disasm):
            record_stack_local(disasm, addr, local_vars)
        return frame_size

    def _analyze_instruction(
        self,
        addr: int,
        disasm: str,
        stack_frame: dict[str, Any],
    ) -> None:
        """Analyze a single instruction for memory accesses."""
        if not disasm:
            return

        decoded = self._decode_memory_access(disasm, stack_frame)
        if decoded is None:
            return

        location = MemoryLocation(
            address=decoded.address,
            size=decoded.size,
            name=decoded.location_name,
            location_type=("stack" if "stack" in decoded.location_name or decoded.address < 0 else "unknown"),
        )
        access = MemoryAccess(
            address=addr,
            location=location,
            access_type=decoded.access_type,
            instruction=disasm,
            registers_involved=decoded.registers,
        )

        self._accesses.setdefault(addr, []).append(access)
        self._locations[decoded.address] = location

    def _decode_memory_access(self, disasm: str, stack_frame: dict[str, Any]) -> _DecodedAccess | None:
        """Decode the memory access described by an instruction, if any."""
        if "mov" in disasm and "[" in disasm:
            return self._decode_x86_mov(disasm, stack_frame)
        if "ldr" in disasm:
            return self._decode_arm_mem(disasm, stack_frame, "ldr", MemoryAccessType.READ)
        if "str" in disasm:
            return self._decode_arm_mem(disasm, stack_frame, "str", MemoryAccessType.WRITE)
        if any(op in disasm for op in ("push", "pop")):
            return self._decode_push_pop(disasm)
        return None

    def _decode_x86_mov(self, disasm: str, stack_frame: dict[str, Any]) -> _DecodedAccess | None:
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
            return None

        address = self._extract_memory_address(operand, stack_frame)
        size = self._extract_access_size(disasm)
        location_name = self._identify_location(operand, address, stack_frame)
        return _DecodedAccess(access_type, size, address, location_name, registers)

    def _decode_arm_mem(
        self, disasm: str, stack_frame: dict[str, Any], mnemonic: str, access_type: MemoryAccessType
    ) -> _DecodedAccess:
        size = 4
        address = 0
        location_name = ""
        registers: list[str] = []

        match = re.search(rf"{mnemonic}\s+\w+,\s+\[([^\]]+)\]", disasm)
        if match:
            operand = match.group(1)
            address = self._extract_memory_address(operand, stack_frame)
            size = self._extract_arm_access_size(disasm)
            location_name = self._identify_location(operand, address, stack_frame)
            reg_match = re.search(rf"{mnemonic}\s+(\w+)", disasm)
            registers = [reg_match.group(1)] if reg_match else []

        return _DecodedAccess(access_type, size, address, location_name, registers)

    def _decode_push_pop(self, disasm: str) -> _DecodedAccess | None:
        match = re.search(r"(push|pop)\s+(\w+)", disasm)
        if not match:
            return None

        op = match.group(1)
        reg = match.group(2)
        if op == "push":
            access_type = MemoryAccessType.WRITE
            address = -8  # Stack pointer offset
        else:
            access_type = MemoryAccessType.READ
            address = 0
        return _DecodedAccess(access_type, 8, address, "stack", [reg])

    def _extract_memory_address(self, operand: str, stack_frame: dict[str, Any]) -> int:
        """Extract memory address from operand."""

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
            return "stack_base"

        for var in stack_frame.get("local_vars", []):
            if var.get("offset") == address:
                return str(var.get("name", f"stack_{abs(address)}"))

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
