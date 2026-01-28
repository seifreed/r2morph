from r2morph.devirtualization.vm_handler_analyzer import (
    VMHandlerAnalyzer,
    VMHandler,
    VMHandlerType,
    VMArchitecture,
)


def test_vm_handler_equivalent_x86_for_memory_and_stack():
    analyzer = VMHandlerAnalyzer(binary=None)

    memory_handler = VMHandler(
        handler_id=1,
        entry_address=0x1000,
        size=4,
        handler_type=VMHandlerType.MEMORY,
        instructions=[{"disasm": "mov eax, [ebx]"}],
        semantic_signature="mov",
    )
    stack_handler = VMHandler(
        handler_id=2,
        entry_address=0x2000,
        size=4,
        handler_type=VMHandlerType.STACK,
        instructions=[{"disasm": "push eax"}],
        semantic_signature="push",
    )

    assert analyzer._generate_equivalent_x86(memory_handler) == "mov eax, [ebx]"
    assert analyzer._generate_equivalent_x86(stack_handler) == "push eax"


def test_vm_handler_confidence_bounds():
    analyzer = VMHandlerAnalyzer(binary=None)

    short_handler = VMHandler(
        handler_id=1,
        entry_address=0x1000,
        size=4,
        handler_type=VMHandlerType.UNKNOWN,
        instructions=[{"disasm": "nop"}],
        semantic_signature="nop",
    )

    long_handler = VMHandler(
        handler_id=2,
        entry_address=0x2000,
        size=400,
        handler_type=VMHandlerType.ARITHMETIC,
        instructions=[{"disasm": "add eax, ebx"}] * 60,
        semantic_signature="add",
    )

    assert analyzer._calculate_handler_confidence(short_handler) >= 0.0
    assert analyzer._calculate_handler_confidence(long_handler) <= 1.0


def test_vm_handler_statistics_empty_architecture():
    analyzer = VMHandlerAnalyzer(binary=None)
    assert analyzer.get_handler_statistics() == {}

    analyzer.vm_architecture = VMArchitecture(dispatcher_address=0x1234)
    stats = analyzer.get_handler_statistics()
    assert stats["total_handlers"] == 0
    assert stats["dispatcher_address"] == 0x1234
