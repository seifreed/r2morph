from r2morph.devirtualization.vm_handler_analyzer import (
    VMArchitecture,
    VMHandler,
    VMHandlerAnalyzer,
    VMHandlerType,
)
from tests.utils.assertions import expect

_EXPECTED_STATS_DISPATCHER_ADDRESS_8192 = 0x2000
_EXPECTED_STATS_TOTAL_HANDLERS_2 = 2


def test_vm_handler_classification_and_equivalent_x86():
    analyzer = VMHandlerAnalyzer(binary=None)

    instructions = [
        {"disasm": "add eax, ebx"},
        {"disasm": "sub eax, 1"},
    ]
    handler_type = analyzer._classify_handler_type(instructions)
    expect(handler_type == VMHandlerType.ARITHMETIC)

    handler = VMHandler(
        handler_id=1,
        entry_address=0x1000,
        size=8,
        handler_type=handler_type,
        instructions=instructions,
        semantic_signature=analyzer._generate_semantic_signature(instructions),
    )

    handler.equivalent_x86 = analyzer._generate_equivalent_x86(handler)
    confidence = analyzer._calculate_handler_confidence(handler)

    expect(handler.equivalent_x86 is not None)
    expect(0.0 <= confidence <= 1.0)


def test_vm_handler_signature_and_statistics():
    analyzer = VMHandlerAnalyzer(binary=None)

    instructions = [
        {"disasm": "push rbp"},
        {"disasm": "mov rbp, rsp"},
        {"disasm": "pop rbp"},
    ]
    signature = analyzer._generate_semantic_signature(instructions)
    expect(signature.startswith("push"))

    arch = VMArchitecture(
        dispatcher_address=0x2000,
        handlers={
            1: VMHandler(handler_id=1, entry_address=0x3000, size=4),
            2: VMHandler(handler_id=2, entry_address=0x3010, size=4),
        },
    )
    analyzer.vm_architecture = arch

    stats = analyzer.get_handler_statistics()
    expect(stats["total_handlers"] == _EXPECTED_STATS_TOTAL_HANDLERS_2)
    expect(stats["dispatcher_address"] == _EXPECTED_STATS_DISPATCHER_ADDRESS_8192)
