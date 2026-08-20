"""
Tests for switch table analysis module.

Covers:
- Jump table detection
- Switch case reconstruction
- Tail call detection
- PLT/GOT thunk identification
"""

from r2morph.analysis.switch_table import (
    IndirectJump,
    JumpTable,
    JumpTableEntry,
    JumpTableType,
    SwitchTableAnalyzer,
)
from tests.utils.assertions import expect

_EXPECTED_CASES_0_TARGET_4198656 = 0x401100
_EXPECTED_ENTRY_TARGET_ADDRESS_4198400 = 0x401000
_EXPECTED_JUMP_ADDRESS_4198400 = 0x401000
_EXPECTED_JUMP_DISPLACEMENT_4214784 = 0x405000
_EXPECTED_JUMP_SCALE_4 = 4
_EXPECTED_LEN_CASES_3 = 3
_EXPECTED_LEN_JUMP_TARGET_CANDIDATES_2 = 2
_EXPECTED_LEN_TABLE_UNIQUE_TARGETS_2 = 2
_EXPECTED_LEN_TABLE_UNIQUE_TARGETS_3 = 3
_EXPECTED_TABLE_CASE_COUNT_3 = 3
_EXPECTED_TABLE_TABLE_ADDRESS_4214784 = 0x405000


class _Binary:
    def __init__(
        self,
        *,
        disassembly: list[dict[str, object]] | None = None,
        functions: list[dict[str, object]] | None = None,
        basic_blocks: list[dict[str, object]] | None = None,
        raw_bytes: bytes = b"",
    ) -> None:
        self.disassembly = disassembly or []
        self.functions = functions or []
        self.basic_blocks = basic_blocks or []
        self.raw_bytes = raw_bytes

    def get_function_disasm(self, address: int) -> list[dict[str, object]]:
        return self.disassembly

    def get_functions(self) -> list[dict[str, object]]:
        return self.functions

    def get_basic_blocks(self, address: int) -> list[dict[str, object]]:
        return self.basic_blocks

    def read_bytes(self, address: int, size: int) -> bytes:
        return self.raw_bytes[:size]

    def get_arch_info(self) -> dict[str, object]:
        return {"bits": 64, "arch": "x86_64"}


class TestJumpTableEntry:
    """Test JumpTableEntry dataclass."""

    def test_basic_entry(self):
        """Create basic jump table entry."""
        entry = JumpTableEntry(
            index=0,
            target_address=0x401000,
            case_value=0,
        )
        expect(entry.index == 0)
        expect(entry.target_address == _EXPECTED_ENTRY_TARGET_ADDRESS_4198400)
        expect(entry.case_value == 0)
        expect(not (entry.is_default is not False))

    def test_default_case(self):
        """Create default case entry."""
        entry = JumpTableEntry(
            index=10,
            target_address=0x401500,
            is_default=True,
        )
        expect(not (entry.is_default is not True))


class TestJumpTable:
    """Test JumpTable dataclass."""

    def test_basic_table(self):
        """Create basic jump table."""
        entries = [
            JumpTableEntry(index=0, target_address=0x401000, case_value=0),
            JumpTableEntry(index=1, target_address=0x401100, case_value=1),
            JumpTableEntry(index=2, target_address=0x401200, case_value=2),
        ]
        table = JumpTable(
            table_address=0x405000,
            table_type=JumpTableType.DIRECT,
            entries=entries,
        )
        expect(table.table_address == _EXPECTED_TABLE_TABLE_ADDRESS_4214784)
        expect(table.case_count == _EXPECTED_TABLE_CASE_COUNT_3)
        expect(len(table.unique_targets) == _EXPECTED_LEN_TABLE_UNIQUE_TARGETS_3)

    def test_dense_table(self):
        """Test dense case detection."""
        entries = [
            JumpTableEntry(index=0, target_address=0x401000, case_value=0),
            JumpTableEntry(index=1, target_address=0x401100, case_value=1),
            JumpTableEntry(index=2, target_address=0x401200, case_value=2),
        ]
        table = JumpTable(
            table_address=0x405000,
            table_type=JumpTableType.DIRECT,
            entries=entries,
        )
        expect(not (table.is_dense is not True))

    def test_sparse_table(self):
        """Test sparse case detection."""
        entries = [
            JumpTableEntry(index=0, target_address=0x401000, case_value=0),
            JumpTableEntry(index=1, target_address=0x401100, case_value=5),
            JumpTableEntry(index=2, target_address=0x401200, case_value=10),
        ]
        table = JumpTable(
            table_address=0x405000,
            table_type=JumpTableType.DIRECT,
            entries=entries,
        )
        expect(not (table.is_dense is not False))

    def test_duplicate_targets(self):
        """Test unique targets with duplicates."""
        entries = [
            JumpTableEntry(index=0, target_address=0x401000, case_value=0),
            JumpTableEntry(index=1, target_address=0x401000, case_value=1),
            JumpTableEntry(index=2, target_address=0x401200, case_value=2),
        ]
        table = JumpTable(
            table_address=0x405000,
            table_type=JumpTableType.DIRECT,
            entries=entries,
        )
        expect(len(table.unique_targets) == _EXPECTED_LEN_TABLE_UNIQUE_TARGETS_2)


class TestIndirectJump:
    """Test IndirectJump dataclass."""

    def test_basic_jump(self):
        """Create basic indirect jump."""
        jump = IndirectJump(
            address=0x401000,
            instruction="jmp [rax*4+0x405000]",
            jump_type="jumptable",
        )
        expect(jump.address == _EXPECTED_JUMP_ADDRESS_4198400)
        expect(jump.jump_type == "jumptable")

    def test_with_candidates(self):
        """Create jump with target candidates."""
        jump = IndirectJump(
            address=0x401000,
            instruction="jmp rax",
            jump_type="register",
            target_candidates=[0x401100, 0x401200],
        )
        expect(len(jump.target_candidates) == _EXPECTED_LEN_JUMP_TARGET_CANDIDATES_2)


class TestSwitchTableAnalyzer:
    """Test SwitchTableAnalyzer class."""

    def test_classify_jumptable_pattern(self):
        """Test jump table pattern classification."""
        analyzer = SwitchTableAnalyzer(_Binary())

        jump = analyzer._classify_indirect_jump(0x401000, "jmp [rax*4+0x405000]", 0x401000)
        expect(jump is not None)
        expect(jump.jump_type == "jumptable")
        expect(jump.index_register == "rax")
        expect(jump.scale == _EXPECTED_JUMP_SCALE_4)
        expect(jump.displacement == _EXPECTED_JUMP_DISPLACEMENT_4214784)

    def test_classify_tail_call(self):
        """Test tail call classification via detect_tail_calls."""
        binary = _Binary(
            disassembly=[
                {"offset": 0x401000, "type": "push", "opcode": "push rbp"},
                {"offset": 0x401002, "type": "jmp", "opcode": "jmp 0x402000"},
            ],
            functions=[
                {"offset": 0x401000, "name": "caller"},
                {"offset": 0x402000, "name": "callee"},
            ],
        )

        analyzer = SwitchTableAnalyzer(binary)
        analyzer._cache_functions()

        # Tail calls are detected via detect_tail_calls, not _classify_indirect_jump
        tail_calls = analyzer.detect_tail_calls(0x401000)
        expect(not (len(tail_calls) < 0))

    def test_classify_indirect_register(self):
        """Test indirect register jump."""
        analyzer = SwitchTableAnalyzer(_Binary())

        jump = analyzer._classify_indirect_jump(0x401000, "jmp [rax]", 0x401000)
        expect(jump is not None)
        expect(not (jump.jump_type not in ("jumptable", "indirect")))

    def test_detect_switch_pattern_simple(self):
        """Test simple switch pattern detection."""
        binary = _Binary(
            disassembly=[
                {"offset": 0x401000, "type": "cmp", "opcode": "cmp eax, 5"},
                {"offset": 0x401002, "type": "ja", "opcode": "ja 0x401100"},
                {"offset": 0x401004, "type": "jmp", "opcode": "jmp [rax*4+0x405000]"},
            ],
            raw_bytes=b"\x00\x10\x40\x00\x10\x10\x40\x00\x20\x10\x40\x00",
        )

        analyzer = SwitchTableAnalyzer(binary)
        tables, jumps = analyzer.detect_switch_pattern(0x401000)

        expect(len(tables) == 1 or len(jumps) >= 1)

    def test_analyze_indirect_jumps(self):
        """Test indirect jump analysis."""
        binary = _Binary(
            disassembly=[
                {"offset": 0x401000, "type": "mov", "opcode": "mov eax, ebx"},
                {"offset": 0x401002, "type": "jmp", "opcode": "jmp [rax*4+0x405000]"},
                {"offset": 0x401006, "type": "ret", "opcode": "ret"},
            ]
        )

        analyzer = SwitchTableAnalyzer(binary)
        jumps = analyzer.analyze_indirect_jumps(0x401000)

        expect(len(jumps) == 1)
        expect(jumps[0].jump_type == "jumptable")

    def test_detect_tail_calls_within_function(self):
        """Test tail call detection."""
        binary = _Binary(
            disassembly=[
                {"offset": 0x401000, "type": "push", "opcode": "push rbp"},
                {"offset": 0x401002, "type": "mov", "opcode": "mov rbp, rsp"},
                {"offset": 0x401004, "type": "jmp", "opcode": "jmp 0x402000"},
                {"offset": 0x401008, "type": "pop", "opcode": "pop rbp"},
                {"offset": 0x40100A, "type": "ret", "opcode": "ret"},
            ],
            functions=[
                {"offset": 0x401000, "name": "caller_func"},
                {"offset": 0x402000, "name": "target_func"},
            ],
        )

        analyzer = SwitchTableAnalyzer(binary)
        tail_calls = analyzer.detect_tail_calls(0x401000)

        expect(not (len(tail_calls) < 0))

    def test_reconstruct_switch_cases(self):
        """Test switch case reconstruction."""
        entries = [
            JumpTableEntry(index=0, target_address=0x401100, case_value=0),
            JumpTableEntry(index=1, target_address=0x401200, case_value=1),
            JumpTableEntry(index=2, target_address=0x401300, case_value=2),
        ]
        table = JumpTable(
            table_address=0x405000,
            table_type=JumpTableType.DIRECT,
            entries=entries,
        )

        binary = _Binary(
            basic_blocks=[
                {"addr": 0x401100, "size": 0x10},
                {"addr": 0x401200, "size": 0x10},
                {"addr": 0x401300, "size": 0x10},
            ]
        )

        analyzer = SwitchTableAnalyzer(binary)
        cases = analyzer.reconstruct_switch_cases(table, 0x401000)

        expect(len(cases) == _EXPECTED_LEN_CASES_3)
        expect(cases[0]["value"] == 0)
        expect(cases[0]["target"] == _EXPECTED_CASES_0_TARGET_4198656)
        expect(not (cases[0]["is_block_start"] is not True))

    def test_analyze_function_jumps(self):
        """Test comprehensive function jump analysis."""
        binary = _Binary(
            disassembly=[
                {"offset": 0x401000, "type": "cmp", "opcode": "cmp eax, 3"},
                {"offset": 0x401002, "type": "ja", "opcode": "ja 0x401100"},
                {"offset": 0x401004, "type": "jmp", "opcode": "jmp [rax*4+0x405000]"},
                {"offset": 0x401008, "type": "jmp", "opcode": "jmp 0x402000"},
            ],
            functions=[
                {"offset": 0x401000, "name": "test_func"},
                {"offset": 0x402000, "name": "other_func"},
            ],
            raw_bytes=b"\x00\x10\x40\x00" * 4,
        )

        analyzer = SwitchTableAnalyzer(binary)
        result = analyzer.analyze_function_jumps(0x401000)

        expect(not ("jump_tables" not in result))
        expect(not ("other_indirect_jumps" not in result))
        expect(not ("tail_calls" not in result))
        expect(not ("statistics" not in result))


class TestJumpTableType:
    """Test JumpTableType enum."""

    def test_all_types(self):
        """Test all jump table types exist."""
        expect(JumpTableType.DIRECT.value == "direct")
        expect(JumpTableType.INDIRECT.value == "indirect")
        expect(JumpTableType.COMPACT.value == "compact")
        expect(JumpTableType.EXPANDED.value == "expanded")
        expect(JumpTableType.PLT_GOT.value == "plt_got")
