"""
Native execution proof that a real, strict ELF loader accepts a virtualized image.

Everything else that runs the produced file runs it under something permissive. The
emulator maps the segments the tests ask it to map; the Linux kernel's own loader is
famously tolerant of program headers no toolchain would ever emit. Both will happily
execute a structurally invalid image, so a green emulation is not evidence that the
file is well formed - only that its instruction stream is right.

This module supplies the missing half: it hands the mutated file to a real userland
loader on Linux/x86-64 and takes the process exit status as the verdict. That loader
validates the image before it transfers control, and it refuses images the emulator
accepted - an injection that lengthened the ELF-header-plus-table prefix without
growing the segment that maps it was rejected here ("first load segment does not span
the elf header size", exit 133) while emulating perfectly. Nothing short of running
the file under a strict loader had caught it.

What this module does NOT establish is load-base independence. Under a translation
layer ``--platform linux/amd64`` maps the ET_DYN image at a constant address
(0x555555554000, observed identical across execs) rather than a randomized one, so a
green run here says nothing about a blob that baked an absolute address in - a green
run against a pinned base is worse than no run, because it looks like evidence. That
claim is made instead by the sibling module ``test_code_virtualization_pie_real``,
which emulates the image at a nonzero bias: a link-time absolute cannot cancel out at
a bias the image was not built for, so a wrong exit status there is exactly the
base-dependence signal that is unavailable here.

Both fixtures are static-PIE and ``-nostdlib``, so they need no dynamic loader and run
in any minimal image. Each is executed twice per invocation - once unmutated as the
reference exit status, once virtualized - so a container, image or toolchain problem
(both red) is distinguishable from a mutation defect (only the mutated one red).

Opt in with ``R2MORPH_NATIVE_TESTS=1``::

    R2MORPH_NATIVE_TESTS=1 python -m pytest tests/integration/test_code_virtualization_pie_native.py

The module skips unless the variable is set and a container daemon is reachable. That
is an *infrastructure* gate, not an ``xfail`` covering a known defect: with no Linux
runtime to hand the file to there is no loader verdict to be had, and a failure would
report the absence of a runtime rather than the presence of a bug. The daemon's own
architecture is not part of the gate - a translation layer still runs the image
through a strict loader, which is the whole claim being made. Once the gate is open
the assertions are unconditional - nothing here tolerates a wrong exit status.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.utils.assertions import expect
from tests.utils.process import run_command

if os.environ.get("R2MORPH_NATIVE_TESTS") != "1":
    pytest.skip(
        "native execution is opt-in: set R2MORPH_NATIVE_TESTS=1 to run it",
        allow_module_level=True,
    )
else:
    try:
        _daemon = run_command(
            ["docker", "version", "--format", "{{.Server.Version}}"],
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

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass

# A minimal image suffices: the fixtures are static and -nostdlib, so nothing from the
# image's userland is linked in. Pulling it the first time dominates the time budget.
_CONTAINER_IMAGE = "alpine:3"
_CONTAINER_TIMEOUT_SECONDS = 900
_EXECUTABLE_MODE = 0o755

_DATASET = Path(__file__).resolve().parents[2] / "fixtures" / "dataset"
# Plain arithmetic over a straight-line region, virtualized whole.
_ARITH_FIXTURE = _DATASET / "elf_vm_pie_x86_64"
_ARITH_EXIT_CODE = 73
# rip-relative offset-table switch: table base, sign-extending offset load and computed
# jump are all reconstructed from the run-time load base rather than a link-time one.
_SWITCH_FIXTURE = _DATASET / "elf_switch_pie_x86_64"
_SWITCH_EXIT_CODE = 30


def _native_exit_code(executable: Path) -> int:
    """Exit status of ``executable`` run in a Linux/x86-64 container.

    The mount is read-only and the network is off. A structurally invalid image is
    refused before its entry point runs, so the status also reports loadability.
    """
    executable.chmod(_EXECUTABLE_MODE)
    run = run_command(
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
    """The fixture copied out of ``fixtures/dataset/`` so nothing shared is ever mutated."""
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
    expect(_native_exit_code(_staged_copy(_ARITH_FIXTURE, tmp_path)) == _ARITH_EXIT_CODE)


def test_pie_arith_fixture_virtualized_native_exit_status_is_unchanged(tmp_path: Path) -> None:
    """A strict loader accepts the virtualized PIE arithmetic image and it exits as before."""
    expect(_native_exit_code(_virtualized_copy(_ARITH_FIXTURE, tmp_path)) == _ARITH_EXIT_CODE)


def test_pie_switch_fixture_native_reference_exit_status_is_the_documented_code(tmp_path: Path) -> None:
    """Reference: the unmutated PIE offset-table switch fixture runs natively as documented."""
    expect(_native_exit_code(_staged_copy(_SWITCH_FIXTURE, tmp_path)) == _SWITCH_EXIT_CODE)


def test_pie_switch_fixture_virtualized_native_exit_status_is_unchanged(tmp_path: Path) -> None:
    """A strict loader accepts the virtualized PIE switch image and it exits as before."""
    expect(_native_exit_code(_virtualized_copy(_SWITCH_FIXTURE, tmp_path)) == _SWITCH_EXIT_CODE)
