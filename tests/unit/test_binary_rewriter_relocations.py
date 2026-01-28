from r2morph.devirtualization.binary_rewriter import BinaryRewriter, CodePatch, RewriteOperation, RelocationEntry


def test_binary_rewriter_updates_relocations_with_shifts():
    rewriter = BinaryRewriter()
    rewriter.patches = [
        CodePatch(
            address=0x1000,
            operation=RewriteOperation.INSTRUCTION_INSERT,
            original_bytes=b"",
            new_bytes=b"\x90" * 4,
            size_change=4,
        ),
        CodePatch(
            address=0x2000,
            operation=RewriteOperation.INSTRUCTION_DELETE,
            original_bytes=b"\x90" * 2,
            new_bytes=b"",
            size_change=-2,
        ),
    ]

    rewriter.relocations = [
        RelocationEntry(address=0x1000, target=0x3000, reloc_type="ABS"),
        RelocationEntry(address=0x2000, target=0x4000, reloc_type="ABS"),
    ]

    stats = rewriter._update_relocations()
    assert stats["updated"] == 2
    assert rewriter.relocations[0].target == 0x3000
    assert rewriter.relocations[1].target == 0x4004
