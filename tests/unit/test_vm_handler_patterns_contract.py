from r2morph.devirtualization.vm_handler_models import VMHandlerType
from r2morph.devirtualization.vm_handler_patterns import load_vm_handler_patterns


def test_vm_handler_pattern_catalog_contract() -> None:
    patterns = load_vm_handler_patterns()

    assert set(patterns) == {
        VMHandlerType.ARITHMETIC,
        VMHandlerType.LOGICAL,
        VMHandlerType.MEMORY,
        VMHandlerType.STACK,
        VMHandlerType.BRANCH,
        VMHandlerType.COMPARE,
    }

    for handler_type, catalog in patterns.items():
        assert catalog, handler_type
        for entry in catalog:
            assert "pattern" in entry
            assert "description" in entry
            assert "confidence" in entry
            assert isinstance(entry["pattern"], list)
