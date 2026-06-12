"""Regression: ``format_as_sarif`` must accept hex-string ``original_bytes``
and ``mutated_bytes`` -- the form the CLI ``report --format sarif`` path
always feeds it.

``MutationRecord.to_dict`` stores ``original_bytes`` and ``mutated_bytes``
as hex strings (``MutationRecord.original_bytes`` is typed as ``str`` and
``to_dict`` does ``asdict(self)`` so the str passes through unchanged).
That hex string then lands in the JSON report. When ``cli.py report
--format sarif`` runs it does:

    with open(report_file) as handle:
        payload = json.load(handle)
    ...
    format_as_sarif(payload["mutations"], ...)

``format_as_sarif`` mapped each mutation dict's ``original_bytes`` straight
into ``MutationResult.original_bytes`` (typed as ``bytes`` but with no
runtime conversion), then ``_mutation_to_result`` did
``mutation.original_bytes.hex()`` -- and ``str`` has no ``.hex()`` method.
The whole SARIF output path therefore crashed with::

    AttributeError: 'str' object has no attribute 'hex'

The existing ``test_format_as_sarif_basic`` masks this because it passes
literal ``bytes`` objects (``b"\\x90\\x90"``) which never round-trip
through JSON; only the production flow that loads the report from disk
hits the bug.

No-mocks regression (CLAUDE.md sec.4): replays the exact dict shape
``MutationRecord.to_dict`` produces -- hex-string bytes -- and asserts
``format_as_sarif`` returns a valid SARIF report.
"""

from __future__ import annotations

import json

from r2morph.mutations.base import MutationRecord
from r2morph.reporting.sarif_formatter import format_as_sarif


def _make_record() -> MutationRecord:
    return MutationRecord(
        pass_name="NopInsertion",
        function_address=0x1000,
        start_address=0x1000,
        end_address=0x1003,
        original_bytes="48894424f0",  # real hex-string form, as produced by mutation passes
        mutated_bytes="9090909090",
        original_disasm="mov [rsp-0x10], rax",
        mutated_disasm="nop; nop; nop; nop; nop",
        mutation_kind="nop_insertion",
    )


def test_format_as_sarif_accepts_hex_string_original_bytes() -> None:
    """The CLI loads a report via ``json.load`` and passes the resulting
    list-of-dicts straight to ``format_as_sarif``. Each dict's
    ``original_bytes`` is the hex string stored by ``MutationRecord.to_dict``;
    pre-fix the formatter called ``.hex()`` on that string and crashed."""
    record = _make_record()
    payload = record.to_dict()

    # The CLI does exactly this -- writes the report to JSON and reloads it.
    # Mimic the same round-trip to make sure we're feeding the formatter
    # what production actually feeds it.
    round_tripped = json.loads(json.dumps(payload))
    assert isinstance(round_tripped["original_bytes"], str), (
        "MutationRecord.to_dict must keep original_bytes as a hex string -- "
        f"got {type(round_tripped['original_bytes']).__name__}"
    )

    report = format_as_sarif(
        mutations=[round_tripped],
        validations=[],
        binary_path="binary.elf",
    )

    assert len(report.runs[0].results) == 1, f"expected 1 mutation result; got {len(report.runs[0].results)}"


def test_format_as_sarif_byte_length_matches_real_byte_count() -> None:
    """The hex string ``"deadbeef"`` is 8 characters but only 4 real
    bytes. Pre-fix the formatter did ``len(mutation.original_bytes)`` on
    the str, so SARIFRegion.byte_length was double the real count."""
    payload = {
        "address": 0x2000,
        "original_bytes": "deadbeef",
        "mutated_bytes": "cafef00d",
        "pass_name": "Substitution",
    }

    report = format_as_sarif([payload], [], "binary.elf")
    result = report.runs[0].results[0]
    region = result.locations[0].physical_location.region

    assert region.byte_length == 4, f"original_bytes='deadbeef' is 4 bytes, not 8; got byte_length={region.byte_length}"


def test_format_as_sarif_round_trips_bytes_input_too() -> None:
    """The existing pre-bytes-aware shape (literal ``bytes``) must keep
    working too -- it's still how unit tests construct mutations."""
    payload = {
        "address": 0x3000,
        "original_bytes": b"\x90\x90\x90",
        "mutated_bytes": b"\x48\x31\xc0",
        "pass_name": "Substitution",
    }

    report = format_as_sarif([payload], [], "binary.elf")
    assert len(report.runs[0].results) == 1
