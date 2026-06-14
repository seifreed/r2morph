from r2morph.devirtualization.binary_rewriter_models import (
    BinaryFormat,
    CodePatch,
    RelocationEntry,
    RewriteOperation,
    RewriteResult,
)


def test_binary_rewriter_models_expose_expected_contract() -> None:
    patch = CodePatch(
        address=0x1000,
        operation=RewriteOperation.INSTRUCTION_INSERT,
        original_bytes=b"\x90",
        new_bytes=b"\x90\x90",
    )
    reloc = RelocationEntry(address=0x2000, target=0x3000, reloc_type="ABS")
    result = RewriteResult(success=True, output_path="out.bin")

    assert BinaryFormat.PE.value == "pe"
    assert patch.size_change == 0
    assert reloc.addend == 0
    assert result.patches_applied == 0
