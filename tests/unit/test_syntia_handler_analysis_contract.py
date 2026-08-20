from r2morph.analysis.symbolic.syntia_handler_analysis import analyze_vm_handler
from r2morph.analysis.symbolic.syntia_models import InstructionSemantics, VMHandlerSemantics
from tests.utils.assertions import expect

_EXPECTED_HANDLER_HANDLER_ID_7 = 7


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

    expect(isinstance(handler, VMHandlerSemantics))
    expect(handler.handler_id == _EXPECTED_HANDLER_HANDLER_ID_7)
    expect(not (handler.handler_type not in {"arithmetic", "memory", "unknown"}))
    expect(handler.equivalent_native_code is not None)
