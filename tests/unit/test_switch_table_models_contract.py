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
from tests.utils.assertions import expect


def test_switch_table_models_are_reexported_from_analyzer_module():
    expect(not (JumpTableType is not ModelsJumpTableType))
    expect(not (JumpTableEntry is not ModelsJumpTableEntry))
    expect(not (JumpTable is not ModelsJumpTable))
    expect(not (IndirectJump is not ModelsIndirectJump))
