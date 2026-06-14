from r2morph.devirtualization.vm_handler_metrics import build_handler_statistics, calculate_handler_confidence
from r2morph.devirtualization.vm_handler_models import VMArchitecture, VMHandler, VMHandlerType


def test_vm_handler_metrics_contract() -> None:
    handler = VMHandler(
        handler_id=1,
        entry_address=0x1000,
        size=16,
        handler_type=VMHandlerType.ARITHMETIC,
        instructions=[{"disasm": "add eax, ebx"}],
        semantic_signature="arith",
        equivalent_x86="add eax, ebx",
        confidence=0.0,
    )
    arch = VMArchitecture(dispatcher_address=0x2000)
    arch.handlers[1] = handler

    assert calculate_handler_confidence(handler) == 0.8
    stats = build_handler_statistics(arch)
    assert stats["total_handlers"] == 1
    assert stats["handler_types"] == {"arithmetic": 1}
    assert stats["average_confidence"] == 0.0
    assert stats["dispatcher_address"] == 0x2000
