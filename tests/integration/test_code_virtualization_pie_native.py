"""
Native execution proof that a virtualized PIE image is load-base independent.

The default suite proves PIE virtualization under emulation at one synthetic load
bias. That is a weaker claim than it looks: a synthetic bias is a constant chosen by
the test, so a blob that accidentally baked an absolute address in would still line
up. This module makes the complementary, stronger claim - it executes the mutated
file for real on Linux/x86-64, where the loader picks the ET_DYN load base itself and
picks a different one on every exec. Any base-dependent artifact left in the injected
VM blob (an absolute vIP, an unbiased target-map entry, a trampoline resolved against
the on-disk vaddr) surfaces here as a wrong exit status or a crash, because the base
the blob was built against is not the base it is running at.

For that reason the evidence lives in *repeated* runs: one green run says little, the
same run repeated against a freshly randomized base each time is the actual proof.

Both fixtures are static-PIE and ``-nostdlib``, so they need no dynamic loader and run
in any minimal image. Each is executed twice per invocation - once unmutated as the
reference exit status, once virtualized - so a container, image or toolchain problem
(both red) is distinguishable from a mutation defect (only the mutated one red).

Opt in with ``R2MORPH_NATIVE_TESTS=1``::

    R2MORPH_NATIVE_TESTS=1 python -m pytest tests/integration/test_code_virtualization_pie_native.py

The module skips unless all three of these hold: the variable is set, a container
daemon is reachable, and that daemon is itself x86-64. The last condition is what
keeps the claim honest. On a non-x86-64 daemon ``--platform linux/amd64`` is served by
a translation layer rather than by the kernel's ELF loader, and such a layer maps the
image at a constant address (0x555555554000, observed identical across execs) instead
of a randomized one - so the binary would run, the assertions would pass, and none of
it would say anything about base independence. A green run against a pinned base is
worse than no run, because it looks like evidence.

Those three conditions are an *infrastructure* gate, not an ``xfail`` covering a known
defect: without a native Linux/x86-64 runtime there is no randomized base to observe,
so there is no verdict to be had, and a failure would report the absence of the right
machine rather than the presence of a bug. Once the gate is open the assertions are
unconditional - nothing here tolerates a wrong exit status.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

if os.environ.get("R2MORPH_NATIVE_TESTS") != "1":
    pytest.skip(
        "native execution is opt-in: set R2MORPH_NATIVE_TESTS=1 to run it",
        allow_module_level=True,
    )
else:
    try:
        _daemon = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Arch}}"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pytest.skip(
            "no reachable container daemon to execute a Linux/x86-64 ELF in",
            allow_module_level=True,
        )
    if _daemon.returncode != 0:
        pytest.skip(
            "no reachable container daemon to execute a Linux/x86-64 ELF in",
            allow_module_level=True,
        )
    if _daemon.stdout.strip() != "amd64":
        pytest.skip(
            f"container daemon is {_daemon.stdout.strip() or 'of unknown architecture'}, not x86-64: "
            "linux/amd64 would run under a translation layer that pins the ET_DYN load base, "
            "leaving no randomized base to prove independence against",
            allow_module_level=True,
        )

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass

# A minimal image suffices: the fixtures are static and -nostdlib, so nothing from the
# image's userland is linked in. Pulling it the first time dominates the time budget.
_CONTAINER_IMAGE = "alpine:3"
_CONTAINER_TIMEOUT_SECONDS = 900
_EXECUTABLE_MODE = 0o755

_DATASET = Path(__file__).resolve().parents[2] / "dataset"
# Plain arithmetic over a straight-line region, virtualized whole.
_ARITH_FIXTURE = _DATASET / "elf_vm_pie_x86_64"
_ARITH_EXIT_CODE = 73
# rip-relative offset-table switch: table base, sign-extending offset load and computed
# jump are all reconstructed from the run-time load base rather than a link-time one.
_SWITCH_FIXTURE = _DATASET / "elf_switch_pie_x86_64"
_SWITCH_EXIT_CODE = 30


def _native_exit_code(executable: Path) -> int:
    """Exit status of ``executable`` run in a Linux/x86-64 container.

    The mount is read-only and the network is off. The container's kernel picks the
    ET_DYN load base, which is what makes the resulting status meaningful.
    """
    executable.chmod(_EXECUTABLE_MODE)
    run = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--platform",
            "linux/amd64",
            "--volume",
            f"{executable.parent}:/subject:ro",
            _CONTAINER_IMAGE,
            f"/subject/{executable.name}",
        ],
        capture_output=True,
        timeout=_CONTAINER_TIMEOUT_SECONDS,
        check=False,
    )
    return run.returncode


def _staged_copy(fixture: Path, destination: Path) -> Path:
    """The fixture copied out of ``dataset/`` so nothing shared is ever mutated."""
    if not fixture.exists():
        pytest.skip(f"fixture missing: {fixture}")
    staged = destination / fixture.name
    shutil.copy(fixture, staged)
    return staged


def _virtualized_copy(fixture: Path, destination: Path) -> Path:
    """A copy of ``fixture`` with its functions lifted into the region VM."""
    mutated = destination / f"{fixture.name}.virtualized"
    shutil.copy(_staged_copy(fixture, destination), mutated)

    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()

    if stats["functions_virtualized"] < 1:
        pytest.fail(f"nothing was virtualized in {fixture.name}; running it would prove nothing")
    return mutated


def test_pie_arith_fixture_native_reference_exit_status_is_the_documented_code(tmp_path: Path) -> None:
    """Reference: the unmutated PIE arithmetic fixture runs natively as documented."""
    assert _native_exit_code(_staged_copy(_ARITH_FIXTURE, tmp_path)) == _ARITH_EXIT_CODE


def test_pie_arith_fixture_virtualized_native_exit_status_is_unchanged(tmp_path: Path) -> None:
    """The virtualized PIE arithmetic image keeps its exit status at a kernel-chosen base."""
    assert _native_exit_code(_virtualized_copy(_ARITH_FIXTURE, tmp_path)) == _ARITH_EXIT_CODE


def test_pie_switch_fixture_native_reference_exit_status_is_the_documented_code(tmp_path: Path) -> None:
    """Reference: the unmutated PIE offset-table switch fixture runs natively as documented."""
    assert _native_exit_code(_staged_copy(_SWITCH_FIXTURE, tmp_path)) == _SWITCH_EXIT_CODE


def test_pie_switch_fixture_virtualized_native_exit_status_is_unchanged(tmp_path: Path) -> None:
    """The virtualized PIE switch keeps its exit status at a kernel-chosen base."""
    assert _native_exit_code(_virtualized_copy(_SWITCH_FIXTURE, tmp_path)) == _SWITCH_EXIT_CODE
