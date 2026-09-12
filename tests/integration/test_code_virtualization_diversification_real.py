"""Real regression contracts for diversified VM builds."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.integration.elf_emulator import emulate_exit_code
from tests.utils.assertions import expect

_DATASET = Path(__file__).resolve().parents[2] / "fixtures" / "dataset"
_FIXTURE = _DATASET / "elf_vm_shift_x86_64"
_SEEDS = (20260913, 20260914, 20260915, 20260916)


def _virtualized_builds(tmp_path: Path) -> tuple[Path, ...]:
    builds: list[Path] = []
    for seed in _SEEDS:
        output = tmp_path / f"seed-{seed}"
        shutil.copyfile(_FIXTURE, output)
        binary = Binary(output, writable=True)
        binary.open()
        try:
            stats = CodeVirtualizationPass(config={"probability": 1.0, "seed": seed}).apply(binary)
            binary.save()
        finally:
            binary.close()
        if stats["functions_virtualized"] < 1:
            raise RuntimeError(f"seed {seed} did not virtualize the fixture")
        builds.append(output)
    return tuple(builds)


def _sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def test_diversified_vm_builds_preserve_fixture_exit_code(tmp_path: Path) -> None:
    baseline = emulate_exit_code(_FIXTURE)
    observed = tuple(emulate_exit_code(path) for path in _virtualized_builds(tmp_path))

    expect(observed == (baseline,) * len(_SEEDS))


def test_diversified_vm_builds_have_distinct_artifacts(tmp_path: Path) -> None:
    digests = {_sha256(path) for path in _virtualized_builds(tmp_path)}

    expect(len(digests) == len(_SEEDS))
