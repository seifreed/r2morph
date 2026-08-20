from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.devirtualization.vm_handler_analyzer import VMHandlerAnalyzer, VMHandlerType
from tests.utils.assertions import expect


def test_vm_handler_analyzer_real_function_workflow():
    binary_path = Path("fixtures/dataset/elf_x86_64")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        functions = bin_obj.get_functions()
        expect(functions)

        analyzer = VMHandlerAnalyzer(bin_obj)
        handler = analyzer._analyze_single_handler(0, functions[0].get("offset", 0))
        expect(handler is not None)
        expect(not (handler.handler_type not in set(VMHandlerType)))
        expect(handler.semantic_signature is not None)
        expect(0.0 <= handler.confidence <= 1.0)


def test_vm_handler_architecture_statistics():
    binary_path = Path("fixtures/dataset/elf_x86_64")

    with Binary(binary_path) as bin_obj:
        bin_obj.analyze("aa")
        functions = bin_obj.get_functions()
        expect(functions)

        analyzer = VMHandlerAnalyzer(bin_obj)
        dispatcher_addr = functions[0].get("offset", 0)
        architecture = analyzer.analyze_vm_architecture(dispatcher_addr)

        expect(architecture.dispatcher_address == dispatcher_addr)
        expect(not (architecture.vm_context_size < 0))
        expect(isinstance(architecture.vm_registers, list))

        stats = analyzer.get_handler_statistics()
        expect(stats.get("dispatcher_address") == dispatcher_addr)
        expect(not ("total_handlers" not in stats))
        expect(not ("average_confidence" not in stats))
