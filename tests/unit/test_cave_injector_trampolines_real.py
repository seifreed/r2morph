"""Characterization: CodeCaveInjector.inject_with_trampolines.

This public method had no callers and no tests, and its loop body
contained a discarded ``allocation.address + i * jmp_size`` expression
statement (dead code ruff B018 cannot flag because it embeds a method
call) plus an orphaned ``_get_jmp_size`` helper. Per its docstring the
trampoline jumps go straight from each site to the matching
``original_destinations`` entry, so removing the vestigial layout code
is behaviour-preserving. This test pins that observable contract with a
real in-memory Binary double (CLAUDE.md SS4: no mocks) and gives the
previously-untested API real coverage.
"""

from r2morph.relocations.cave_injector import CodeCaveInjector
from tests._doubles.in_memory_cave_binary import InMemoryCaveBinary


def test_inject_with_trampolines_writes_direct_site_to_destination_jumps() -> None:
    binary = InMemoryCaveBinary()
    injector = CodeCaveInjector(binary)

    code = b"\x90" * 16
    sites = [0x4000, 0x5000]
    destinations = [0x9000, 0xA000]

    allocation = injector.inject_with_trampolines(code, sites, destinations)

    assert allocation is not None
    assert allocation.address == 0x1000
    assert allocation.size == len(code)
    assert allocation.metadata["trampolines_written"] == 2

    # The injected code is written into the cave.
    assert (0x1000, code) in binary.writes

    # Each site receives a 5-byte E9 rel32 near jump to its destination.
    trampolines = {addr: data for addr, data in binary.writes if addr in sites}
    assert set(trampolines) == set(sites)
    for site, dest in zip(sites, destinations):
        jmp = trampolines[site]
        assert len(jmp) == 5
        assert jmp[0] == 0xE9
        rel = int.from_bytes(jmp[1:5], "little", signed=True)
        assert site + 5 + rel == dest
