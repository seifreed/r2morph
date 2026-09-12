"""Real target support checks for code virtualization."""

from __future__ import annotations

import hashlib
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.utils.assertions import expect


def _run_code_virtualization(path: Path) -> dict[str, object]:
    with Binary(path, writable=True) as binary:
        return CodeVirtualizationPass(config={"probability": 1.0, "max_functions": 1}).run(binary)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_code_virtualization_pe_x86_64_target_is_rejected_before_mutation(deterministic_pe_sample: Path) -> None:
    before = _sha256(deterministic_pe_sample)

    result = _run_code_virtualization(deterministic_pe_sample)

    expect(
        result["target_diagnostic"]
        == {
            "format": "PE",
            "architecture": "x86_64",
            "bits": 64,
            "supported_formats": ["ELF"],
            "supported_architectures": ["x86_64"],
            "reason": "target is outside the code virtualization support envelope",
        }
        and result["functions_virtualized"] == 0
        and before == _sha256(deterministic_pe_sample)
    )


def test_code_virtualization_macho_arm64_target_is_rejected_before_mutation(deterministic_macho_sample: Path) -> None:
    before = _sha256(deterministic_macho_sample)

    result = _run_code_virtualization(deterministic_macho_sample)

    expect(
        result["target_diagnostic"]
        == {
            "format": "Mach-O",
            "architecture": "arm64",
            "bits": 64,
            "supported_formats": ["ELF"],
            "supported_architectures": ["x86_64"],
            "reason": "target is outside the code virtualization support envelope",
        }
        and result["functions_virtualized"] == 0
        and before == _sha256(deterministic_macho_sample)
    )
