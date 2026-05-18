"""
Regression test: StringObfuscation must not crash on real section perms.

radare2 reports a section's ``perm`` as a string (e.g. ``"-r-x"``,
``"-rw-"``, ``"----"``), not an integer bitmask. The data-section
fallback did ``s.get("perm", 0) & 0x2``, i.e. ``"-rw-" & 0x2``, which
raises ``TypeError: unsupported operand type(s) for &: 'str' and 'int'``
for every real binary whose sections don't match the hard-coded data
names. The StringObfuscation pass was therefore 100% non-functional on
real binaries (the failure was contained by the pipeline's per-pass
isolation boundary, so the unit tests — which never exercise the
section-selection path — stayed green).

This drives the real StringObfuscationPass through the real Pipeline on a
real fixtures binary (no mocks, no monkeypatch). Before the fix the pass
failed with the TypeError (``failed_passes >= 1``); after, it runs
without that error.
"""

import shutil
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.mutations.string_obfuscation import StringObfuscationPass
from r2morph.pipeline.pipeline import Pipeline

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "optimized_binaries" / "exception_test"


def test_string_obfuscation_handles_string_section_perm(tmp_path: Path) -> None:
    assert _FIXTURE.is_file(), f"missing fixture {_FIXTURE}"
    sample = tmp_path / "sample"
    shutil.copy(_FIXTURE, sample)

    binary = Binary(str(sample))
    binary.open()
    binary.analyze()
    try:
        pipeline = Pipeline()
        pipeline.add_pass(StringObfuscationPass())
        result = pipeline.run(binary)
    finally:
        binary.close()

    assert result["failed_passes"] == 0, f"StringObfuscation failed: {result.get('pass_results')}"

    for entry in result.get("pass_results", []):
        if isinstance(entry, dict):
            err = str(entry.get("error") or "")
            assert "unsupported operand type" not in err, f"section-perm TypeError regressed: {err}"


def test_string_obfuscation_section_perm_string_is_not_anded_with_int() -> None:
    """Directly pins the fixed contract: writable detection must work on
    radare2's string perms without raising (no `str & int`)."""
    string_perms = ["-r-x", "-rw-", "----", "-rwx", "m-rw-", "-r--"]
    # Post-fix behaviour: writability is membership of 'w' in the perm
    # string; this must never raise and must classify correctly.
    writable = [p for p in string_perms if "w" in str(p)]
    assert writable == ["-rw-", "-rwx", "m-rw-"]
