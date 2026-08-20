from r2morph.devirtualization.binary_rewriter import BinaryRewriter, CodePatch, RewriteOperation
from tests.utils.assertions import expect


def test_binary_rewriter_validate_patches_overlap_and_warnings():
    rewriter = BinaryRewriter()
    rewriter.sections = {".text": {"vaddr": 0x1000, "vsize": 0x100}}

    rewriter.patches = [
        CodePatch(
            address=0x2000,
            operation=RewriteOperation.INSTRUCTION_INSERT,
            original_bytes=b"",
            new_bytes=b"\x90" * 5,
            size_change=5,
            new_instructions=["invalid"],
        ),
        CodePatch(
            address=0x2000,
            operation=RewriteOperation.INSTRUCTION_DELETE,
            original_bytes=b"\x90" * 2000,
            new_bytes=b"",
            size_change=-2000,
        ),
    ]

    result = rewriter._validate_patches()
    expect(not (result["valid"] is not False))
    expect(any("Overlapping" in err for err in result["errors"]))
    expect(any("Invalid address" in warning for warning in result["warnings"]))
    expect(any("Large size change" in warning for warning in result["warnings"]))
