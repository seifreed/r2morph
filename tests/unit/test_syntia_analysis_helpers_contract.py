from r2morph.analysis.symbolic.syntia_analysis_helpers import (
    assess_semantic_complexity,
    classify_handler_type,
    fallback_semantic_analysis,
    generate_equivalent_native_code,
    synthesize_handler_semantics,
)
from r2morph.analysis.symbolic.syntia_models import InstructionSemantics, SemanticComplexity, VMHandlerSemantics


def test_syntia_analysis_helpers_contract() -> None:
    fallback = fallback_semantic_analysis("mov eax, ebx")
    assert fallback["confidence"] == 0.8

    sem = InstructionSemantics(
        address=0x1000,
        instruction_bytes=b"\x90",
        disassembly="nop",
        learned_semantics="move data",
        confidence=0.9,
    )
    assert assess_semantic_complexity(sem) is SemanticComplexity.SIMPLE
    assert synthesize_handler_semantics([sem]) == "move data"
    neutral_sem = InstructionSemantics(
        address=0x1001,
        instruction_bytes=b"\x90",
        disassembly="nop",
        learned_semantics="nop",
        confidence=0.1,
    )
    assert classify_handler_type([neutral_sem]) == "unknown"

    handler = VMHandlerSemantics(
        handler_id=1,
        entry_address=0x2000,
        handler_type="branch",
        instruction_semantics=[sem],
        overall_semantic_formula="branch",
    )
    assert generate_equivalent_native_code(handler) == "cmp eax, ebx\nje target"
