"""Regression: APIHashingPass must record the real cave bytes and the
patched call sites, never fabricate.

Pre-fix the mutation record used ``original_bytes=b"\\x00"*stub_size``
(the real pre-write cave bytes were never read) and omitted the patched
call sites entirely, so a record-based diff/restore was wrong and
incomplete (same family as the constant_unfolding / code_virtualization
"never fabricate the original" fixes). The fix reads the real cave
bytes (skipping the import if unreadable) and records every patched
call site in metadata. Real in-memory double, no mocks.

The cave here is a NOP (0x90) run, so a faithful original is
b"\\x90"*10 — distinguishable from the pre-fix fabricated b"\\x00"*10.
"""

from __future__ import annotations

from r2morph.mutations.api_hashing import APIHashingPass
from tests._doubles.in_memory_api_hashing_binary import InMemoryAPIHashingBinary

BASE = 0x1000
STUB_SIZE = 10
CALL_SITE = 0x1000
PLT = 0x2000

# [0x1000..0x1005) call e8 00000000 ; [0x1005..0x1040) 0xCC filler (non-cave)
# [0x1040..0x1080) 0x90 NOP run -> the cave CaveFinder will pick
_BUF = bytearray(128)
_BUF[0:5] = b"\xe8\x00\x00\x00\x00"
_BUF[5:0x40] = b"\xcc" * (0x40 - 5)
_BUF[0x40:0x80] = b"\x90" * 0x40

SECTION = {"name": ".text", "vaddr": BASE, "vsize": 128, "perm": "r-x"}
IMPORTS = [{"name": "MyApi", "plt": PLT, "type": "FUNC", "libname": "lib"}]
XREFS = [{"from": CALL_SITE}]


def _run() -> APIHashingPass:
    binary = InMemoryAPIHashingBinary(
        base_addr=BASE,
        contents=bytes(_BUF),
        section=SECTION,
        imports=IMPORTS,
        xrefs=XREFS,
    )
    p = APIHashingPass({"api_list": ["MyApi"]})
    p.apply(binary)
    return p


def test_records_real_cave_bytes_not_fabricated_zeros() -> None:
    recs = _run().get_records()
    assert len(recs) == 1
    rec = recs[0]
    assert rec.original_bytes == ("90" * STUB_SIZE)
    assert rec.original_bytes != ("00" * STUB_SIZE)


def test_records_patched_call_sites_in_metadata() -> None:
    rec = _run().get_records()[0]
    sites = rec.metadata.get("patched_call_sites")
    assert sites and len(sites) == 1
    assert sites[0]["address"] == hex(CALL_SITE)
    assert sites[0]["original_bytes"] == "e800000000"
    assert sites[0]["patched_bytes"].startswith("e8")
