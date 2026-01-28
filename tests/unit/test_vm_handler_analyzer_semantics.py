from r2morph.core.binary import Binary
from r2morph.devirtualization.vm_handler_analyzer import (
    VMHandler,
    VMHandlerAnalyzer,
    VMHandlerType,
)


def test_vm_handler_classification_and_signatures():
    with Binary("dataset/elf_x86_64") as bin_obj:
        analyzer = VMHandlerAnalyzer(bin_obj)

        arithmetic = [{"disasm": "add eax, ebx"}, {"disasm": "sub eax, 1"}]
        logical = [{"disasm": "xor eax, eax"}]
        stack = [{"disasm": "push rax"}, {"disasm": "pop rax"}]
        compare = [{"disasm": "cmp eax, ebx"}, {"disasm": "test eax, eax"}]

        assert analyzer._classify_handler_type(arithmetic) == VMHandlerType.ARITHMETIC
        assert analyzer._classify_handler_type(logical) == VMHandlerType.LOGICAL
        assert analyzer._classify_handler_type(stack) == VMHandlerType.STACK
        assert analyzer._classify_handler_type(compare) == VMHandlerType.COMPARE

        signature = analyzer._generate_semantic_signature(arithmetic)
        assert "add" in signature
        assert "sub" in signature


def test_vm_handler_equivalent_x86_and_confidence():
    with Binary("dataset/elf_x86_64") as bin_obj:
        analyzer = VMHandlerAnalyzer(bin_obj)

        handler = VMHandler(
            handler_id=1,
            entry_address=0x1000,
            size=8,
            handler_type=VMHandlerType.ARITHMETIC,
            instructions=[{"disasm": "add eax, ebx"}],
            semantic_signature="add eax, ebx",
        )
        handler.equivalent_x86 = analyzer._generate_equivalent_x86(handler)
        assert handler.equivalent_x86 == "add eax, ebx"

        confidence = analyzer._calculate_handler_confidence(handler)
        assert 0.0 <= confidence <= 1.0

        long_handler = VMHandler(
            handler_id=2,
            entry_address=0x2000,
            size=400,
            handler_type=VMHandlerType.UNKNOWN,
            instructions=[{"disasm": "nop"} for _ in range(60)],
            semantic_signature="nop",
        )
        confidence_long = analyzer._calculate_handler_confidence(long_handler)
        assert confidence_long <= confidence


def test_vm_handler_equivalent_x86_memory_and_stack():
    with Binary("dataset/elf_x86_64") as bin_obj:
        analyzer = VMHandlerAnalyzer(bin_obj)

        memory_handler = VMHandler(
            handler_id=3,
            entry_address=0x3000,
            size=8,
            handler_type=VMHandlerType.MEMORY,
            instructions=[{"disasm": "mov eax, [ebx]"}],
            semantic_signature="mov eax, [ebx]",
        )
        assert analyzer._generate_equivalent_x86(memory_handler) == "mov eax, [ebx]"

        stack_handler = VMHandler(
            handler_id=4,
            entry_address=0x4000,
            size=8,
            handler_type=VMHandlerType.STACK,
            instructions=[{"disasm": "push eax"}, {"disasm": "pop eax"}],
            semantic_signature="push eax -> pop eax",
        )
        assert analyzer._generate_equivalent_x86(stack_handler) == "push eax"


def test_vm_handler_context_and_stats():
    with Binary("dataset/elf_x86_64") as bin_obj:
        analyzer = VMHandlerAnalyzer(bin_obj)
        assert analyzer.get_handler_statistics() == {}

        analyzer.vm_architecture = analyzer.analyze_vm_architecture(0x1000)
        stats = analyzer.get_handler_statistics()
        assert "handler_types" in stats
