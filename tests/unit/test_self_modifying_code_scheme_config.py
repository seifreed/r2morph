"""
Regression test: SelfModifyingCode must accept a string encryption_scheme.

The pass documents ``encryption_scheme`` as a string config option
(default ``"xor_key"``), but ``__init__`` stored ``self.config.get(...)``
verbatim and ``apply`` later did ``self.encryption_scheme.value``. When
the scheme was supplied the documented way -- a string, e.g. via a JSON
config -- ``"rc4".value`` raised ``AttributeError: 'str' object has no
attribute 'value'`` and the pass failed for every function (contained by
the pipeline's per-pass isolation boundary, so the suite -- which only
used the enum default -- stayed green).

These exercise the real pass: a direct constructor contract check and an
end-to-end run through the real Pipeline on the arm64 Mach-O fixture (no
mocks, no monkeypatch).
"""

import shutil
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.mutations.self_modifying_code import EncryptionScheme, SelfModifyingCodePass
from r2morph.pipeline.pipeline import Pipeline

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "optimized_binaries" / "exception_test"


def test_string_scheme_is_coerced_to_enum() -> None:
    assert SelfModifyingCodePass({"encryption_scheme": "rc4"}).encryption_scheme is EncryptionScheme.RC4
    assert SelfModifyingCodePass({"encryption_scheme": "xor_rolling"}).encryption_scheme is EncryptionScheme.XOR_ROLLING


def test_enum_scheme_passes_through() -> None:
    p = SelfModifyingCodePass({"encryption_scheme": EncryptionScheme.ADD_SUB})
    assert p.encryption_scheme is EncryptionScheme.ADD_SUB


def test_invalid_scheme_falls_back_to_default() -> None:
    p = SelfModifyingCodePass({"encryption_scheme": "totally-not-a-scheme"})
    assert p.encryption_scheme is EncryptionScheme.XOR_KEY


def test_default_scheme_is_enum() -> None:
    assert SelfModifyingCodePass().encryption_scheme is EncryptionScheme.XOR_KEY


def test_string_scheme_runs_in_pipeline(tmp_path: Path) -> None:
    sample = tmp_path / "sample"
    shutil.copy(_FIXTURE, sample)

    binary = Binary(str(sample))
    binary.open()
    binary.analyze()
    try:
        pipeline = Pipeline()
        pipeline.add_pass(SelfModifyingCodePass({"encryption_scheme": "rc4"}))
        result = pipeline.run(binary)
    finally:
        binary.close()

    assert result["failed_passes"] == 0, f"SMC failed: {result.get('pass_results')}"
    for entry in result.get("pass_results", []):
        if isinstance(entry, dict):
            err = str(entry.get("error") or "")
            assert "has no attribute 'value'" not in err, f"scheme-config regressed: {err}"
