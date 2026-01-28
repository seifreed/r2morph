"""Adapters for external tool integration.

This package provides abstraction layers for external tools like disassemblers,
enabling dependency injection and easier testing.

The adapter pattern is used to:
1. Decouple the codebase from specific tool implementations
2. Enable mock implementations for testing
3. Allow swapping implementations without changing client code

Example usage:
    from r2morph.adapters import DisassemblerInterface, R2PipeAdapter, MockDisassembler

    # Production code
    def analyze(disasm: DisassemblerInterface, path: Path) -> dict:
        disasm.open(path)
        try:
            return disasm.cmdj("ij")
        finally:
            disasm.close()

    # In production
    adapter = R2PipeAdapter()
    result = analyze(adapter, binary_path)

    # In tests
    mock = MockDisassembler(responses={"ij": {"bin": {"arch": "x86"}}})
    result = analyze(mock, Path("/fake/path"))
"""

from .disassembler import DisassemblerInterface
from .r2pipe_adapter import R2PipeAdapter
from .mock_disassembler import MockDisassembler

__all__ = [
    "DisassemblerInterface",
    "R2PipeAdapter",
    "MockDisassembler",
]
