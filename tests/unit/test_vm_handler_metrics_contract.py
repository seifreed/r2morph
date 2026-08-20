from r2morph.devirtualization.vm_handler_metrics import build_handler_statistics, calculate_handler_confidence
from r2morph.devirtualization.vm_handler_models import VMArchitecture, VMHandler, VMHandlerType
from tests.utils.assertions import expect

_EXPECTED_CALCULATE_HANDLER_CONFIDENCE_HANDLER_0_8 = 0.8
_EXPECTED_STATS_DISPATCHER_ADDRESS_8192 = 0x2000


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

    expect(calculate_handler_confidence(handler) == _EXPECTED_CALCULATE_HANDLER_CONFIDENCE_HANDLER_0_8)
    stats = build_handler_statistics(arch)
    expect(stats["total_handlers"] == 1)
    expect(stats["handler_types"] == {"arithmetic": 1})
    expect(stats["average_confidence"] == 0.0)
    expect(stats["dispatcher_address"] == _EXPECTED_STATS_DISPATCHER_ADDRESS_8192)
