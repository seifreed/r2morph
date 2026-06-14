from r2morph.analysis.symbolic.syntia_handler_analysis import analyze_vm_handler
from r2morph.analysis.symbolic.syntia_models import InstructionSemantics, VMHandlerSemantics


def test_syntia_handler_analysis_contract() -> None:
    def learn_instruction_semantics(inst_bytes: bytes, address: int, disasm: str) -> InstructionSemantics:
        return InstructionSemantics(
            address=address,
            instruction_bytes=inst_bytes,
            disassembly=disasm,
            learned_semantics=disasm,
            confidence=1.0,
        )

    handler = analyze_vm_handler(
        [(0x1000, b"\x90", "mov eax, ebx"), (0x1001, b"\x90", "add eax, 1")],
        7,
        learn_instruction_semantics,
    )

    assert isinstance(handler, VMHandlerSemantics)
    assert handler.handler_id == 7
    assert handler.handler_type in {"arithmetic", "memory", "unknown"}
    assert handler.equivalent_native_code is not None

