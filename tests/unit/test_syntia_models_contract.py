from r2morph.analysis.symbolic.syntia_models import InstructionSemantics, SemanticComplexity, VMHandlerSemantics


def test_syntia_models_contract() -> None:
    sem = InstructionSemantics(address=0x1000, instruction_bytes=b"\x90", disassembly="nop")
    assert sem.complexity is SemanticComplexity.UNKNOWN
    handler = VMHandlerSemantics(
        handler_id=1,
        entry_address=0x2000,
        handler_type="branch",
        instruction_semantics=[sem],
    )
    assert handler.instruction_semantics[0].address == 0x1000
