from r2morph.analysis.symbolic.syntia_models import InstructionSemantics, SemanticComplexity, VMHandlerSemantics
from tests.utils.assertions import expect

_EXPECTED_HANDLER_INSTRUCTION_SEMANTICS_0_ADDRESS_4096 = 0x1000


def test_syntia_models_contract() -> None:
    sem = InstructionSemantics(address=0x1000, instruction_bytes=b"\x90", disassembly="nop")
    expect(not (sem.complexity is not SemanticComplexity.UNKNOWN))
    handler = VMHandlerSemantics(
        handler_id=1,
        entry_address=0x2000,
        handler_type="branch",
        instruction_semantics=[sem],
    )
    expect(handler.instruction_semantics[0].address == _EXPECTED_HANDLER_INSTRUCTION_SEMANTICS_0_ADDRESS_4096)
