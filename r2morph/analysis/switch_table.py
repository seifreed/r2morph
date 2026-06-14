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
from typing import Any

from r2morph.analysis.switch_table_detection import (
    detect_plt_got_thunks as detect_plt_got_thunks_impl,
)
from r2morph.analysis.switch_table_detection import (
    detect_tail_calls as detect_tail_calls_impl,
)
from r2morph.analysis.switch_table_detection import (
    is_plt_stub_pattern,
)
from r2morph.analysis.switch_table_models import (
    IndirectJump,
    JumpTable,
    JumpTableEntry,
    JumpTableType,  # noqa: F401
)
from r2morph.analysis.switch_table_parsing import (
    classify_indirect_jump,
    match_jumptable_operands,
)
from r2morph.analysis.switch_table_patterns import JUMP_TABLE_PATTERNS, PLT_PATTERNS, TAIL_CALL_PATTERNS
from r2morph.analysis.switch_table_resolution import (
    get_jump_table_targets,
    normalize_address,
    read_jump_table_entries,
    reconstruct_switch_cases,
    resolve_jump_table,
)
from r2morph.core.binary import Binary

logger = logging.getLogger(__name__)


class SwitchTableAnalyzer:
    """
    Analyzes switch tables and indirect jumps in binaries.

    Provides:
    - Jump table detection
    - Switch case reconstruction
    - Indirect jump resolution
    - PLT/GOT identification
    """

    JUMP_TABLE_PATTERNS = JUMP_TABLE_PATTERNS
    TAIL_CALL_PATTERNS = TAIL_CALL_PATTERNS
    PLT_PATTERNS = PLT_PATTERNS

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

    def _match_jumptable_operands(self, disasm: str) -> dict[str, Any] | None:
        """Match a jump-table addressing pattern and extract its operands.

        Returns the operand fields (base/index registers, scale, displacement
        and resolved table address) when any jump-table pattern matches -- the
        bare register/absolute forms match with empty operands -- or None when
        none does.
        """
        return match_jumptable_operands(disasm)

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
        return classify_indirect_jump(address, disasm, function_address)

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
        return resolve_jump_table(self.binary, jump, table_address=table_address, max_entries=max_entries)

    def _read_jump_table_entries(
        self,
        effective_address: int,
        ptr_size: int,
        bits: int,
        max_entries: int,
    ) -> list[JumpTableEntry]:
        return read_jump_table_entries(self.binary, effective_address, ptr_size, bits, max_entries)

    def _normalize_address(self, addr: int, bits: int) -> int:
        return normalize_address(addr, bits)

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
                        # Not a parseable numeric literal here (e.g. register/symbolic operand); expected, so this candidate is skipped.
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
        if self._known_functions is None:
            self._cache_functions()

        return detect_tail_calls_impl(self.binary, self._known_functions, function_address)

    def detect_plt_got_thunks(self) -> dict[int, dict[str, Any]]:
        if self._plt_entries is not None:
            return self._plt_entries

        self._plt_entries = detect_plt_got_thunks_impl(self.binary)
        return self._plt_entries

    def _is_plt_stub_pattern(self, data: bytes) -> bool:
        """Check if bytes match common PLT stub patterns."""
        return is_plt_stub_pattern(data)

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
        return get_jump_table_targets(table)

    def reconstruct_switch_cases(self, table: JumpTable, function_address: int) -> dict[int, dict[str, Any]]:
        return reconstruct_switch_cases(self.binary, table, function_address)

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
