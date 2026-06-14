"""Contract tests for switch table model exports."""

from r2morph.analysis.switch_table import IndirectJump, JumpTable, JumpTableEntry, JumpTableType
from r2morph.analysis.switch_table_models import (
    IndirectJump as ModelsIndirectJump,
)
from r2morph.analysis.switch_table_models import (
    JumpTable as ModelsJumpTable,
)
from r2morph.analysis.switch_table_models import (
    JumpTableEntry as ModelsJumpTableEntry,
)
from r2morph.analysis.switch_table_models import (
    JumpTableType as ModelsJumpTableType,
)


def test_switch_table_models_are_reexported_from_analyzer_module():
    assert JumpTableType is ModelsJumpTableType
    assert JumpTableEntry is ModelsJumpTableEntry
    assert JumpTable is ModelsJumpTable
    assert IndirectJump is ModelsIndirectJump
