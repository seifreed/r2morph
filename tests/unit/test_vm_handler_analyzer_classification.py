from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.devirtualization.vm_handler_analyzer import (
    VMHandlerAnalyzer,
    VMHandler,
    VMHandlerType,
)


def test_vm_handler_classification_and_semantics():
    binary_path = Path("dataset/elf_x86_64")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze()
        analyzer = VMHandlerAnalyzer(bin_obj)

        functions = bin_obj.get_functions()
        if functions:
            instrs = analyzer._get_handler_instructions(functions[0].get('offset', 0))
            assert isinstance(instrs, list)

        instructions = [
            {"disasm": "add eax, ebx"},
            {"disasm": "sub eax, ecx"},
        ]

        handler_type = analyzer._classify_handler_type(instructions)
        assert handler_type in {VMHandlerType.ARITHMETIC, VMHandlerType.UNKNOWN}

        signature = analyzer._generate_semantic_signature(instructions)
        assert "add" in signature

        handler = VMHandler(
            handler_id=1,
            entry_address=0x1000,
            size=10,
            handler_type=VMHandlerType.ARITHMETIC,
            instructions=instructions,
            semantic_signature=signature,
        )

        handler.equivalent_x86 = analyzer._generate_equivalent_x86(handler)
        confidence = analyzer._calculate_handler_confidence(handler)
        assert 0.0 <= confidence <= 1.0
