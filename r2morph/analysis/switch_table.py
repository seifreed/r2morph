"""
Switch table detection and reconstruction for complex CFG handling.

This module provides:
- Jump table pattern detection
- Switch case resolution
- Table entry extraction
- Indirect jump target discovery
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


class JumpTableType(Enum):
    """Type of jump table."""

    DIRECT = "direct"
    INDIRECT = "indirect"
    COMPACT = "compact"
    EXPANDED = "expanded"
    PLT_GOT = "plt_got"


@dataclass
class JumpTableEntry:
    """Represents a single entry in a jump table."""

    index: int
    target_address: int
    case_value: int | None = None
    is_default: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class JumpTable:
    """
    Represents a complete jump table.

    Jump tables are used for switch statements and computed gotos.
    """

    table_address: int
    table_type: JumpTableType
    entries: list[JumpTableEntry] = field(default_factory=list)
    base_register: str | None = None
    scale: int = 4
    offset: int = 0
    default_case: int | None = None
    bounds_check_register: str | None = None
    bounds_check_address: int | None = None
    function_address: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def case_count(self) -> int:
        """Number of cases in the table."""
        return len([e for e in self.entries if not e.is_default])

    @property
    def unique_targets(self) -> list[int]:
        """Unique target addresses in the table."""
        return sorted(set(e.target_address for e in self.entries))

    @property
    def is_dense(self) -> bool:
        """Check if case values are dense (no gaps)."""
        case_values = sorted(e.case_value for e in self.entries if e.case_value is not None)
        if len(case_values) < 2:
            return True
        return case_values[-1] - case_values[0] + 1 == len(case_values)


@dataclass
class IndirectJump:
    """
    Represents an indirect jump instruction.

    Indirect jumps are used for:
    - Switch statements (via jump tables)
    - Tail calls
    - Virtual function dispatch
    - PLT/GOT thunks
    """

    address: int
    instruction: str
    jump_type: str
    base_register: str | None = None
    index_register: str | None = None
    scale: int = 1
    displacement: int = 0
    table_address: int | None = None
    target_candidates: list[int] = field(default_factory=list)
    function_address: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class SwitchTableAnalyzer:
    """
    Analyzes switch tables and indirect jumps in binaries.

    Provides:
    - Jump table detection
    - Switch case reconstruction
    - Indirect jump resolution
    - PLT/GOT identification
    """

    JUMP_TABLE_PATTERNS = [
        (r"jmp\s+\[([a-z]+)\s*\*\s*(\d+)\s*\+\s*(0x[0-9a-f]+)\]", "indexed_scaled_offset"),
        (r"jmp\s+\[([a-z]+)\s*\*\s*(\d+)\]", "indexed_scaled"),
        (r"jmp\s+\[([a-z]+)\s*\+\s*(0x[0-9a-f]+)\]", "indexed_offset"),
        (r"jmp\s+\[([a-z]+)\]", "indexed"),
        (r"jmp\s+([a-z]+)", "register"),
        (r"jmp\s+(0x[0-9a-f]+)", "absolute"),
    ]

    TAIL_CALL_PATTERNS = [
        (r"jmp\s+([a-z]+\.[a-zA-Z0-9_]+)", "symbolic"),
        (r"jmp\s+(0x[0-9a-f]+)", "absolute"),
    ]

    PLT_PATTERNS = [
        r"jmp\s+\[rip\s*\+\s*0x[0-9a-f]+\]",
        r"jmp\s+\[([a-z]+)\s*\+\s*0x[0-9a-f]+\].*;.*plt",
    ]

    def __init__(self, binary: Binary):
        """
        Initialize the switch table analyzer.

        Args:
            binary: Binary instance to analyze
        """
        self.binary = binary
        self._known_functions: dict[int, str] | None = None
        self._plt_entries: dict[int, dict[str, Any]] | None = None
        self._got_entries: dict[int, int] | None = None

    def analyze_indirect_jumps(self, function_address: int) -> list[IndirectJump]:
        """
        Find all indirect jumps in a function.

        Args:
            function_address: Address of the function to analyze

        Returns:
            List of IndirectJump instances found
        """
        indirect_jumps: list[IndirectJump] = []

        try:
            instructions = self.binary.get_function_disasm(function_address)
        except Exception as e:
            logger.error(f"Failed to get disassembly for 0x{function_address:x}: {e}")
            return indirect_jumps

        for insn in instructions:
            addr = insn.get("offset", 0)
            mnemonic = insn.get("type", "").lower()
            disasm = insn.get("opcode", insn.get("disasm", "")).lower()

            if mnemonic not in ("jmp", "ujmp"):
                continue

            jump = self._classify_indirect_jump(addr, disasm, function_address)
            if jump:
                indirect_jumps.append(jump)

        logger.debug(f"Found {len(indirect_jumps)} indirect jumps in 0x{function_address:x}")
        return indirect_jumps

    def _classify_indirect_jump(self, address: int, disasm: str, function_address: int) -> IndirectJump | None:
        """
        Classify an indirect jump instruction.

        Args:
            address: Address of the jump instruction
            disasm: Disassembly string
            function_address: Parent function address

        Returns:
            IndirectJump instance or None if not classified
        """
        jump_type = "unknown"
        base_register = None
        index_register = None
        scale = 1
        displacement = 0
        table_address = None

        for pattern, ptype in self.JUMP_TABLE_PATTERNS:
            match = re.search(pattern, disasm, re.IGNORECASE)
            if match:
                jump_type = "jumptable"
                groups = match.groups()

                if ptype == "indexed_scaled_offset" and len(groups) >= 3:
                    index_register = groups[0]
                    scale = int(groups[1])
                    displacement = int(groups[2], 16)
                elif ptype == "indexed_scaled" and len(groups) >= 2:
                    index_register = groups[0]
                    scale = int(groups[1])
                elif ptype == "indexed_offset" and len(groups) >= 2:
                    base_register = groups[0]
                    displacement = int(groups[1], 16)
                elif ptype == "indexed":
                    base_register = groups[0] if groups[0] else None
                    index_register = groups[0] if not base_register else None

                if base_register and displacement:
                    table_address = displacement

                break

        if jump_type == "unknown":
            for pattern, ptype in self.TAIL_CALL_PATTERNS:
                match = re.search(pattern, disasm, re.IGNORECASE)
                if match:
                    jump_type = "tailcall"
                    groups = match.groups()
                    if ptype == "absolute":
                        target = int(groups[0], 16)
                        return IndirectJump(
                            address=address,
                            instruction=disasm,
                            jump_type=jump_type,
                            target_candidates=[target],
                            function_address=function_address,
                        )
                    break

        for pattern in self.PLT_PATTERNS:
            if re.search(pattern, disasm, re.IGNORECASE):
                jump_type = "plt"
                break

        if jump_type == "unknown" and ("[" in disasm or "rip" in disasm):
            jump_type = "indirect"

        if jump_type == "unknown":
            return None

        return IndirectJump(
            address=address,
            instruction=disasm,
            jump_type=jump_type,
            base_register=base_register,
            index_register=index_register,
            scale=scale,
            displacement=displacement,
            table_address=table_address,
            function_address=function_address,
        )

    def resolve_jump_table(
        self,
        jump: IndirectJump,
        table_address: int | None = None,
        max_entries: int = 256,
    ) -> JumpTable | None:
        """
        Resolve a jump table to extract all targets.

        Args:
            jump: IndirectJump instance
            table_address: Optional known table address
            max_entries: Maximum entries to extract

        Returns:
            JumpTable instance or None if resolution fails
        """
        effective_address = table_address or jump.table_address or jump.displacement
        if effective_address is None or effective_address == 0:
            logger.debug(f"No table address for jump at 0x{jump.address:x}")
            return None

        arch_info = self.binary.get_arch_info()
        bits = arch_info.get("bits", 64)
        ptr_size = bits // 8

        entries: list[JumpTableEntry] = []
        seen_targets: set[int] = set()

        try:
            offset = 0
            case_value = 0

            while len(entries) < max_entries:
                target_bytes = self.binary.read_bytes(effective_address + offset, ptr_size)
                if not target_bytes or len(target_bytes) != ptr_size:
                    break

                if bits == 64:
                    target = int.from_bytes(target_bytes, "little", signed=False)
                    if target > 0x7FFFFFFFFFFF:
                        target = target - (1 << 64)
                else:
                    target = int.from_bytes(target_bytes, "little", signed=False)
                    if target > 0x7FFFFFFF:
                        target = target - (1 << 32)

                if target == 0 or target in seen_targets:
                    break

                normalized = self._normalize_address(target, bits)

                entry = JumpTableEntry(
                    index=len(entries),
                    target_address=normalized,
                    case_value=case_value,
                )
                entries.append(entry)
                seen_targets.add(normalized)

                offset += ptr_size
                case_value += 1

        except Exception as e:
            logger.debug(f"Failed to read jump table at 0x{effective_address:x}: {e}")
            if not entries:
                return None

        if not entries:
            return None

        table_type = JumpTableType.DIRECT
        if jump.base_register and jump.index_register:
            table_type = JumpTableType.INDIRECT
        elif jump.scale != ptr_size:
            table_type = JumpTableType.COMPACT

        return JumpTable(
            table_address=effective_address,
            table_type=table_type,
            entries=entries,
            base_register=jump.base_register,
            scale=jump.scale,
            offset=jump.displacement,
            function_address=jump.function_address,
        )

    def _normalize_address(self, addr: int, bits: int) -> int:
        """Normalize an address to valid range."""
        if bits == 64:
            if addr > 0xFFFFFFFFFFFFFFFF:
                addr = addr & 0xFFFFFFFFFFFFFFFF
            if addr > 0x7FFFFFFFFFFF:
                return 0
        else:
            addr = addr & 0xFFFFFFFF
            if addr > 0x7FFFFFFF:
                return 0
        return addr

    def detect_switch_pattern(self, function_address: int) -> tuple[list[JumpTable], list[IndirectJump]]:
        """
        Detect switch statement patterns in a function.

        Looks for:
        - Bounds check followed by jump table
        - Default case handling
        - Case dispatching

        Args:
            function_address: Address of the function

        Returns:
            Tuple of (jump_tables, other_indirect_jumps)
        """
        try:
            instructions = self.binary.get_function_disasm(function_address)
            self.binary.get_basic_blocks(function_address)
        except Exception as e:
            logger.error(f"Failed to analyze function at 0x{function_address:x}: {e}")
            return [], []

        jump_tables: list[JumpTable] = []
        other_jumps: list[IndirectJump] = []

        indirect_jumps = self.analyze_indirect_jumps(function_address)

        bounds_check_candidates: dict[int, dict[str, Any]] = {}
        for insn in instructions:
            addr = insn.get("offset", 0)
            mnemonic = insn.get("type", "").lower()
            disasm = insn.get("opcode", insn.get("disasm", "")).lower()

            if mnemonic in ("cmp", "test"):
                match = re.search(r"cmp\s+([a-z]+),\s*([a-z0-9]+)", disasm)
                if match:
                    reg, val = match.groups()
                    try:
                        bound = int(val, 0)
                        bounds_check_candidates[addr] = {"register": reg, "bound": bound, "address": addr}
                    except ValueError:
                        pass

        for jump in indirect_jumps:
            found_bounds = False
            for check_addr, check_info in bounds_check_candidates.items():
                if check_addr < jump.address:
                    if abs(check_addr - jump.address) < 32:
                        found_bounds = True
                        break

            if jump.jump_type in ("jumptable", "indirect"):
                table = self.resolve_jump_table(jump)
                if table:
                    if found_bounds:
                        table.bounds_check_address = check_addr
                        table.bounds_check_register = check_info.get("register")
                    jump_tables.append(table)
                else:
                    other_jumps.append(jump)
            else:
                other_jumps.append(jump)

        logger.debug(
            f"Function 0x{function_address:x}: {len(jump_tables)} jump tables, {len(other_jumps)} other indirect jumps"
        )
        return jump_tables, other_jumps

    def detect_tail_calls(self, function_address: int) -> list[tuple[int, int]]:
        """
        Detect tail calls in a function.

        A tail call is a jmp to another function entry point.

        Args:
            function_address: Address of the function

        Returns:
            List of (jump_address, target_address) tuples
        """
        tail_calls: list[tuple[int, int]] = []

        if self._known_functions is None:
            self._cache_functions()

        if not self._known_functions:
            return tail_calls

        try:
            instructions = self.binary.get_function_disasm(function_address)
        except Exception as e:
            logger.debug(f"Failed to get disassembly: {e}")
            return tail_calls

        for insn in instructions:
            addr = insn.get("offset", 0)
            mnemonic = insn.get("type", "").lower()
            disasm = insn.get("opcode", insn.get("disasm", ""))

            if mnemonic != "jmp":
                continue

            match = re.search(r"jmp\s+(0x[0-9a-f]+)", disasm, re.IGNORECASE)
            if not match:
                continue

            try:
                target = int(match.group(1), 16)
            except ValueError:
                continue

            if target in self._known_functions:
                tail_calls.append((addr, target))
                logger.debug(f"Tail call at 0x{addr:x} -> 0x{target:x} ({self._known_functions[target]})")

        return tail_calls

    def detect_plt_got_thunks(self) -> dict[int, dict[str, Any]]:
        """
        Detect PLT/GOT thunk entries.

        Returns:
            Dictionary mapping thunk address to thunk info
        """
        if self._plt_entries is not None:
            return self._plt_entries

        self._plt_entries = {}

        try:
            sections = self.binary.get_sections()
        except Exception:
            sections = []

        plt_sections = [
            s for s in sections if "plt" in s.get("name", "").lower() or ".plt" in s.get("name", "").lower()
        ]

        if not plt_sections:
            logger.debug("No PLT section found")
            return self._plt_entries

        for section in plt_sections:
            start = section.get("addr", section.get("virtual_address", 0))
            size = section.get("size", section.get("virtual_size", 0))

            if start == 0 or size == 0:
                continue

            try:
                data = self.binary.read_bytes(start, min(size, 0x1000))
            except Exception:
                continue

            if not data:
                continue

            offset = 0
            while offset < len(data) - 16:
                chunk = data[offset : offset + 16]

                if self._is_plt_stub_pattern(chunk):
                    thunk_addr = start + offset
                    self._plt_entries[thunk_addr] = {
                        "address": thunk_addr,
                        "section": section.get("name", ""),
                        "type": "plt_stub",
                    }
                    offset += 16
                else:
                    offset += 1

        logger.debug(f"Found {len(self._plt_entries)} PLT entries")
        return self._plt_entries

    def _is_plt_stub_pattern(self, data: bytes) -> bool:
        """Check if bytes match common PLT stub patterns."""
        if len(data) < 6:
            return False

        if data[:2] == b"\xff\x25":
            return True

        if data[:2] == b"\xff\x27":
            return True

        if len(data) >= 10 and data[:6] == b"\xff\x35" and data[6:10] == b"\x48\x8d\x3d":
            return True

        if data[:6] == b"\x48\x8b\x1d" or data[:6] == b"\x48\x8b\x05":
            return True

        return False

    def _cache_functions(self) -> None:
        """Cache function addresses for quick lookup."""
        self._known_functions = {}

        try:
            functions = self.binary.get_functions()
            for func in functions:
                addr = func.get("offset", 0)
                name = func.get("name", f"func_{addr:x}")
                if addr:
                    self._known_functions[addr] = name
        except Exception as e:
            logger.debug(f"Failed to cache functions: {e}")

    def get_jump_table_targets(self, table: JumpTable) -> dict[int, list[int]]:
        """
        Map table indices to target addresses.

        Args:
            table: JumpTable instance

        Returns:
            Dictionary mapping case values to target addresses
        """
        targets: dict[int, list[int]] = {}

        for entry in table.entries:
            if entry.case_value is None:
                continue

            case_value = entry.case_value
            target = entry.target_address

            if case_value not in targets:
                targets[case_value] = []
            targets[case_value].append(target)

        if table.default_case is not None and table.default_case not in targets:
            targets[table.default_case] = [0]

        return targets

    def reconstruct_switch_cases(self, table: JumpTable, function_address: int) -> dict[int, dict[str, Any]]:
        """
        Reconstruct switch case structure from jump table.

        Args:
            table: JumpTable instance
            function_address: Parent function address

        Returns:
            Dictionary mapping case values to case block info
        """
        try:
            blocks = self.binary.get_basic_blocks(function_address)
        except Exception:
            return {}

        block_addrs = {b.get("addr", 0) for b in blocks}

        cases: dict[int, dict[str, Any]] = {}

        for entry in table.entries:
            if entry.is_default:
                continue

            target = entry.target_address
            case_value = entry.case_value if entry.case_value is not None else entry.index

            if target not in block_addrs:
                logger.debug(f"Jump table entry {entry.index} targets 0x{target:x} which is not a basic block start")

            cases[case_value] = {
                "value": case_value,
                "target": target,
                "is_block_start": target in block_addrs,
                "table_index": entry.index,
            }

        return cases

    def analyze_function_jumps(self, function_address: int) -> dict[str, Any]:
        """
        Comprehensive analysis of all jump patterns in a function.

        Args:
            function_address: Function to analyze

        Returns:
            Dictionary with all jump analysis results
        """
        jump_tables, other_jumps = self.detect_switch_pattern(function_address)
        tail_calls = self.detect_tail_calls(function_address)

        resolved_tables: list[dict[str, Any]] = []
        for table in jump_tables:
            cases = self.reconstruct_switch_cases(table, function_address)
            resolved_tables.append(
                {
                    "table_address": table.table_address,
                    "table_type": table.table_type.value,
                    "case_count": table.case_count,
                    "unique_targets": len(table.unique_targets),
                    "is_dense": table.is_dense,
                    "bounds_register": table.bounds_check_register,
                    "bounds_address": table.bounds_check_address,
                    "cases": cases,
                }
            )

        other_jump_info: list[dict[str, Any]] = []
        for jump in other_jumps:
            other_jump_info.append(
                {
                    "address": jump.address,
                    "instruction": jump.instruction,
                    "jump_type": jump.jump_type,
                    "base_register": jump.base_register,
                    "index_register": jump.index_register,
                    "scale": jump.scale,
                    "displacement": jump.displacement,
                    "target_candidates": jump.target_candidates,
                }
            )

        tail_call_info: list[dict[str, Any]] = []
        for jump_addr, target_addr in tail_calls:
            target_name = ""
            if self._known_functions and target_addr in self._known_functions:
                target_name = self._known_functions[target_addr]
            tail_call_info.append(
                {
                    "jump_address": jump_addr,
                    "target_address": target_addr,
                    "target_name": target_name,
                }
            )

        return {
            "function_address": function_address,
            "jump_tables": resolved_tables,
            "other_indirect_jumps": other_jump_info,
            "tail_calls": tail_call_info,
            "statistics": {
                "total_jump_tables": len(jump_tables),
                "total_other_jumps": len(other_jumps),
                "total_tail_calls": len(tail_calls),
                "total_switch_cases": sum(t.case_count for t in jump_tables),
            },
        }
