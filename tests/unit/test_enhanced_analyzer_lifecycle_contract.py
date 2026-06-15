from pathlib import Path

from r2morph.analysis.enhanced_analyzer_lifecycle import cleanup_binary, load_binary


def test_enhanced_analyzer_lifecycle_helpers_cover_basic_flow():
    binary = load_binary(Path("dataset/elf_x86_64"))
    try:
        assert binary is not None
        assert hasattr(binary, "analyze")
    finally:
        cleanup_binary(binary)

    class _BrokenBinary:
        def __exit__(self, exc_type, exc, tb):
            raise RuntimeError("cleanup failed")

    cleanup_binary(_BrokenBinary())
    cleanup_binary(None)
