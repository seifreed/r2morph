"""Regression: PEHandler's manual struct.unpack paths must match their
destructurings in BOTH field count and byte length.

Two related bugs in ``r2morph/platform/pe_handler.py`` -- both swallowed by
broad ``except Exception`` blocks that logged at debug level and returned
``None``/``[]``:

1. ``_read_pe_header`` -- the optional-header ``struct.unpack`` format
   string described 20 (PE32) / 24 (PE32+) fields but the LHS
   destructuring demanded 29 variables, AND for PE32+ the data slice was
   ``[:120]`` while the format only consumed 96 bytes. ``struct.unpack``
   raised ``unpack requires a buffer of N bytes`` on every real PE binary
   (verified against ``dataset/pe_x86_64.exe``, a PE32+ x86_64 file).

2. ``get_sections``' lief-free fallback -- the per-section format was
   ``"<IIIIIIII"`` (8 fields, 32 bytes) but the destructuring expected 9
   variables. ``NumberOfRelocations`` and ``NumberOfLineNumbers`` are 2-byte
   fields per the PE spec, not 4. The destructure raised ``ValueError:
   not enough values to unpack`` on every section.

Both used to fail silently:

* ``_read_pe_header`` returned ``None`` even for valid PE binaries.
* ``get_sections`` returned ``[]`` when lief was unavailable.

No-mocks regression (CLAUDE.md sec.4): exercises the real PE32+ x86_64
binary tracked in ``dataset/``. For ``get_sections`` the lief-free
fallback path is reached via a hand-written ``PEHandler`` subclass that
overrides ``_parse_lief`` to return ``None`` (a fake, not a mock).
"""

from __future__ import annotations

from pathlib import Path

from r2morph.platform.pe_handler import PEHandler

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_PE_BINARY = _REPO_ROOT / "dataset" / "pe_x86_64.exe"


def test_read_pe_header_returns_dict_for_real_pe32_plus() -> None:
    """Pre-fix this returned ``None`` for every real PE binary because
    ``struct.unpack``'s buffer-size check fired before the destructure
    even got a chance."""
    handler = PEHandler(_PE_BINARY)

    header = handler._read_pe_header()

    assert header is not None, "_read_pe_header must succeed on a real PE binary"
    assert header["is_pe32_plus"] is True, "dataset/pe_x86_64.exe is PE32+"
    assert header["num_sections"] >= 1, f"got num_sections={header['num_sections']!r}"
    assert header["entry_point"] > 0, f"got entry_point={header['entry_point']!r}"
    # Microsoft's PE spec puts CheckSum at offset 64 from the start of
    # the optional header. The handler exposes that as an absolute file
    # offset; sanity-check the relative-offset invariant.
    assert (
        header["checksum_offset"] == header["optional_header_offset"] + 64
    ), f"checksum_offset must equal optional_header_offset+64; got {header!r}"


def test_get_sections_fallback_parses_real_pe_without_lief() -> None:
    """The lief-free fallback in ``get_sections`` had a section-header
    struct format that produced 8 values where the destructuring needed
    9, so it raised ``ValueError`` on every section. Drive the fallback
    via a real ``PEHandler`` subclass (a hand-written fake, not a mock)
    that disables lief, and check that real section bytes are parsed."""

    class _LiefLessHandler(PEHandler):
        """Forces the lief-free struct fallback by reporting "no lief"."""

        def _parse_lief(self) -> None:
            return None

    handler = _LiefLessHandler(_PE_BINARY)
    sections = handler.get_sections()

    assert isinstance(sections, list)
    assert len(sections) >= 1, f"expected at least one section, got {sections!r}"
    first = sections[0]
    # Every section dict must carry the keys the rest of r2morph uses.
    for required_key in ("name", "virtual_address", "size", "offset", "characteristics"):
        assert required_key in first, f"missing {required_key!r} in section dict {first!r}"
    # And at least one section must be non-empty (size > 0).
    assert any(s["size"] > 0 for s in sections), f"all sections have size 0: {sections!r}"
