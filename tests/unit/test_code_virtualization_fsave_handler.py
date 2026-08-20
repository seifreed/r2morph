"""
The fsave/frestore runtime handlers: virtual RFLAGS saved across VM dispatch.

The region keeps an operation's readable flags in a dedicated frame slot (the ``[rsp+128]``
literal a per-build pass relocates), never in native RFLAGS. A native ``pushfq`` is therefore
modelled as ``fsave`` - a copy of that slot onto the virtual operand stack - and the matching
``popfq`` as ``frestore`` - a pop back into the slot. Both survive the ``vm_dispatch`` re-entry
the computed jump performs, so flag state crosses the dispatch inside the VM's own frame.

These pin the structural contract: each handler reads/writes the flags slot, advances the vIP
by a single opcode byte, and returns to the shared dispatch; and a region carrying the items
assembles to real machine code. Runtime semantic parity (an interpreter that brackets its
dispatch with pushfq/popfq keeps its exit code) is covered by the integration suite.
"""

from __future__ import annotations

from r2morph.core import randomness
from r2morph.mutations.code_virtualization_region import build_region_scheme
from r2morph.mutations.code_virtualization_region_codegen import build_region_blob
from r2morph.mutations.code_virtualization_region_microops import _frestore_handler_asm, _fsave_handler_asm
from r2morph.mutations.code_virtualization_region_models import Region
from tests.utils.assertions import expect

_CAVE_VADDR = 0x500000


def test_fsave_handler_reads_the_flags_slot_and_returns_to_dispatch() -> None:
    """fsave copies the flags slot onto the vstack and advances one opcode byte."""
    asm = _fsave_handler_asm()
    expect(not ("mov rax, qword ptr [rsp+128]" not in asm))
    expect(not ("add rsi, 1" not in asm))
    expect(asm.rstrip().endswith("jmp vm_dispatch"))


def test_frestore_handler_writes_the_flags_slot_and_returns_to_dispatch() -> None:
    """frestore pops the vstack top back into the flags slot and advances one byte."""
    asm = _frestore_handler_asm()
    expect(not ("mov qword ptr [rsp+128], rax" not in asm))
    expect(not ("add rsi, 1" not in asm))
    expect(asm.rstrip().endswith("jmp vm_dispatch"))


def test_region_with_flag_transfer_items_assembles() -> None:
    """A region carrying fsave/frestore assembles cleanly - the handlers are wired."""
    region = Region(
        instructions=[("fsave",), ("frestore",), ("exit", 0x2000)],
        exit_vaddr=0x2000,
        entry_vaddr=0x1000,
        op_keys={"fsave", "frestore", "exit_8192"},
        body_ranges=[(0x1000, 1), (0x1001, 1)],
    )
    scheme = build_region_scheme(region, randomness.Random(1234))
    expect(build_region_blob(region, _CAVE_VADDR, scheme) is not None)
