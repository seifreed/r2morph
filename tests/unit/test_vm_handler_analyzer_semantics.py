from r2morph.core.binary import Binary
from r2morph.devirtualization.vm_handler_analyzer import (
    VMHandler,
    VMHandlerAnalyzer,
    VMHandlerType,
)
from tests.utils.assertions import expect


def test_vm_handler_classification_and_signatures():
    with Binary("fixtures/dataset/elf_x86_64") as bin_obj:
        analyzer = VMHandlerAnalyzer(bin_obj)

        arithmetic = [{"disasm": "add eax, ebx"}, {"disasm": "sub eax, 1"}]
        logical = [{"disasm": "xor eax, eax"}]
        stack = [{"disasm": "push rax"}, {"disasm": "pop rax"}]
        compare = [{"disasm": "cmp eax, ebx"}, {"disasm": "test eax, eax"}]

        expect(analyzer._classify_handler_type(arithmetic) == VMHandlerType.ARITHMETIC)
        expect(analyzer._classify_handler_type(logical) == VMHandlerType.LOGICAL)
        expect(analyzer._classify_handler_type(stack) == VMHandlerType.STACK)
        expect(analyzer._classify_handler_type(compare) == VMHandlerType.COMPARE)

        signature = analyzer._generate_semantic_signature(arithmetic)
        expect(not ("add" not in signature))
        expect(not ("sub" not in signature))


def test_vm_handler_equivalent_x86_and_confidence():
    with Binary("fixtures/dataset/elf_x86_64") as bin_obj:
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
        expect(handler.equivalent_x86 == "add eax, ebx")

        confidence = analyzer._calculate_handler_confidence(handler)
        expect(0.0 <= confidence <= 1.0)

        long_handler = VMHandler(
            handler_id=2,
            entry_address=0x2000,
            size=400,
            handler_type=VMHandlerType.UNKNOWN,
            instructions=[{"disasm": "nop"} for _ in range(60)],
            semantic_signature="nop",
        )
        confidence_long = analyzer._calculate_handler_confidence(long_handler)
        expect(not (confidence_long > confidence))


def test_vm_handler_equivalent_x86_memory_and_stack():
    with Binary("fixtures/dataset/elf_x86_64") as bin_obj:
        analyzer = VMHandlerAnalyzer(bin_obj)

        memory_handler = VMHandler(
            handler_id=3,
            entry_address=0x3000,
            size=8,
            handler_type=VMHandlerType.MEMORY,
            instructions=[{"disasm": "mov eax, [ebx]"}],
            semantic_signature="mov eax, [ebx]",
        )
        expect(analyzer._generate_equivalent_x86(memory_handler) == "mov eax, [ebx]")

        stack_handler = VMHandler(
            handler_id=4,
            entry_address=0x4000,
            size=8,
            handler_type=VMHandlerType.STACK,
            instructions=[{"disasm": "push eax"}, {"disasm": "pop eax"}],
            semantic_signature="push eax -> pop eax",
        )
        expect(analyzer._generate_equivalent_x86(stack_handler) == "push eax")


def test_vm_handler_context_and_stats():
    with Binary("fixtures/dataset/elf_x86_64") as bin_obj:
        analyzer = VMHandlerAnalyzer(bin_obj)
        expect(analyzer.get_handler_statistics() == {})

        analyzer.vm_architecture = analyzer.analyze_vm_architecture(0x1000)
        stats = analyzer.get_handler_statistics()
        expect(not ("handler_types" not in stats))
