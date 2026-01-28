from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.devirtualization.vm_handler_analyzer import VMHandlerAnalyzer, VMHandler, VMHandlerType


def test_vm_handler_analyzer_internal_helpers():
    binary_path = Path("dataset/elf_x86_64")
    if not binary_path.exists():
        pytest.skip("ELF binary not available")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        analyzer = VMHandlerAnalyzer(bin_obj)

        arithmetic_instructions = [{"disasm": "add eax, ebx"}, {"disasm": "sub eax, ecx"}]
        handler_type = analyzer._classify_handler_type(arithmetic_instructions)
        assert handler_type == VMHandlerType.ARITHMETIC

        signature = analyzer._generate_semantic_signature(arithmetic_instructions)
        assert "add" in signature

        handler = VMHandler(
            handler_id=1,
            entry_address=0x1000,
            size=8,
            instructions=arithmetic_instructions,
        )
        handler.handler_type = handler_type
        handler.semantic_signature = signature

        handler.equivalent_x86 = analyzer._generate_equivalent_x86(handler)
        assert handler.equivalent_x86 == "add eax, ebx"

        confidence = analyzer._calculate_handler_confidence(handler)
        assert 0.0 <= confidence <= 1.0

        stack_instructions = [{"disasm": "push eax"}, {"disasm": "pop ebx"}]
        stack_type = analyzer._classify_handler_type(stack_instructions)
        assert stack_type == VMHandlerType.STACK
