"""Regression: CodeVirtualizationPass must not fabricate original/mutated
bytes when read_bytes fails.

Pre-fix, the mutation record used
``original_bytes if original_bytes else bytecode`` (and the mutated
twin), so a failed read recorded the *mutated* VM bytecode as the
"original" — a zero-diff record and an unsound rollback target (same
class as the constant_unfolding iter-1 bug and the
binary_rewriter._get_bytes_at_address fix). The fix skips the block
when the original is unreadable and rolls back when the post-write
read-back fails, never fabricating. Real in-memory double, no mocks.
"""

from __future__ import annotations

from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests._doubles.in_memory_virtualization_binary import InMemoryVirtualizationBinary

INSNS = [
    {"mnemonic": "mov", "disasm": "mov eax, ebx", "size": 2, "type": "mov"},
    {"mnemonic": "add", "disasm": "add eax, 1", "size": 3, "type": "add"},
]
BASE = 0x1000
CONTENTS = bytes(range(256))  # distinct, non-zero original block
CONFIG = {"probability": 1.0, "include_dispatcher": False, "max_functions": 5}


def test_read_failure_does_not_fabricate_or_record() -> None:
    binary = InMemoryVirtualizationBinary(base_addr=BASE, contents=CONTENTS, insns=INSNS, reads_fail=True)
    p = CodeVirtualizationPass(CONFIG)

    result = p.apply(binary)

    assert result["functions_virtualized"] == 0
    assert p.get_records() == []


def test_readable_original_is_recorded_verbatim() -> None:
    binary = InMemoryVirtualizationBinary(base_addr=BASE, contents=CONTENTS, insns=INSNS, reads_fail=False)
    p = CodeVirtualizationPass(CONFIG)

    result = p.apply(binary)

    assert result["functions_virtualized"] == 1
    rec = p.get_records()[-1]
    assert rec.original_bytes == CONTENTS.hex()
    assert rec.original_bytes != rec.mutated_bytes
