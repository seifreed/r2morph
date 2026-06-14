from types import SimpleNamespace

from r2morph.platform.pe_handler_projection import project_exports, project_imports, project_relocations


def test_pe_handler_projection_contract() -> None:
    binary = SimpleNamespace(
        imports=[SimpleNamespace(name="KERNEL32.dll", entries=[SimpleNamespace(name="CreateFileA", ordinal=1)])],
        exported_functions=[SimpleNamespace(name="Foo", address=0x1000, ordinal=7)],
        relocations=[SimpleNamespace(address=0x2000, size=4, type="HIGHLOW")],
    )

    imports = project_imports(binary)
    exports = project_exports(binary)
    relocations = project_relocations(binary)

    assert imports == [{"library": "KERNEL32.dll", "entries": ["CreateFileA"]}]
    assert exports == [{"name": "Foo", "address": 0x1000, "ordinal": 7}]
    assert relocations == [{"address": 0x2000, "size": 4, "type": "HIGHLOW"}]
