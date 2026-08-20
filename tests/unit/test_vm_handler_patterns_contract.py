from r2morph.devirtualization.vm_handler_models import VMHandlerType
from r2morph.devirtualization.vm_handler_patterns import load_vm_handler_patterns
from tests.utils.assertions import expect


def test_vm_handler_pattern_catalog_contract() -> None:
    patterns = load_vm_handler_patterns()

    expect(
        set(patterns)
        == {
            VMHandlerType.ARITHMETIC,
            VMHandlerType.LOGICAL,
            VMHandlerType.MEMORY,
            VMHandlerType.STACK,
            VMHandlerType.BRANCH,
            VMHandlerType.COMPARE,
        }
    )

    for handler_type, catalog in patterns.items():
        expect(catalog, handler_type)
        for entry in catalog:
            expect(not ("pattern" not in entry))
            expect(not ("description" not in entry))
            expect(not ("confidence" not in entry))
            expect(isinstance(entry["pattern"], list))
