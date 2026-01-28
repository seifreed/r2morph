from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.devirtualization.vm_handler_analyzer import VMHandlerAnalyzer, VMHandlerType


def test_vm_handler_analyzer_real_function_workflow():
    binary_path = Path("dataset/elf_x86_64")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        functions = bin_obj.get_functions()
        assert functions

        analyzer = VMHandlerAnalyzer(bin_obj)
        handler = analyzer._analyze_single_handler(0, functions[0].get("offset", 0))
        assert handler is not None
        assert handler.handler_type in set(VMHandlerType)
        assert handler.semantic_signature is not None
        assert 0.0 <= handler.confidence <= 1.0


def test_vm_handler_architecture_statistics():
    binary_path = Path("dataset/elf_x86_64")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        functions = bin_obj.get_functions()
        assert functions

        analyzer = VMHandlerAnalyzer(bin_obj)
        dispatcher_addr = functions[0].get("offset", 0)
        architecture = analyzer.analyze_vm_architecture(dispatcher_addr)

        assert architecture.dispatcher_address == dispatcher_addr
        assert architecture.vm_context_size >= 0
        assert isinstance(architecture.vm_registers, list)

        stats = analyzer.get_handler_statistics()
        assert stats.get("dispatcher_address") == dispatcher_addr
        assert "total_handlers" in stats
        assert "average_confidence" in stats
