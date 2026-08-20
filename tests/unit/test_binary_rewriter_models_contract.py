from r2morph.devirtualization.binary_rewriter_models import (
    BinaryFormat,
    CodePatch,
    RelocationEntry,
    RewriteOperation,
    RewriteResult,
)
from tests.utils.assertions import expect


def test_binary_rewriter_models_expose_expected_contract() -> None:
    patch = CodePatch(
        address=0x1000,
        operation=RewriteOperation.INSTRUCTION_INSERT,
        original_bytes=b"\x90",
        new_bytes=b"\x90\x90",
    )
    reloc = RelocationEntry(address=0x2000, target=0x3000, reloc_type="ABS")
    result = RewriteResult(success=True, output_path="out.bin")

    expect(BinaryFormat.PE.value == "pe")
    expect(patch.size_change == 0)
    expect(reloc.addend == 0)
    expect(result.patches_applied == 0)
