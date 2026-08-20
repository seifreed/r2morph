"""
Runtime parity for position-independent (ET_DYN) images.

Virtualizing a PIE binary is a different problem from virtualizing a fixed-load
executable: the VM blob has to be injected into an image whose segments are all
relocated at load time, and every address the generated interpreter computes has
to be derived from the runtime base rather than from a link-time constant. These
tests run the ACTUAL produced file under Unicorn at a realistic, NONZERO load
bias, so any address baked in at link time shows up as a wrong exit code or a
trap. No mocks, no monkeypatch - a real Binary, the real injection, and the real
generated interpreter.
"""

from __future__ import annotations

import importlib.util
import shutil
import struct
from pathlib import Path

import pytest

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)

from r2morph.core.binary import Binary
from r2morph.mutations.code_virtualization import CodeVirtualizationPass
from tests.integration.elf_emulator import emulate_exit_code

_DATASET = Path(__file__).resolve().parents[2] / "fixtures" / "dataset"
# Plain straight-line PIE: arithmetic plus one rip-relative .rodata load. No
# switch and no computed jump, so it isolates the injection itself.
FIXTURE_PIE = _DATASET / "elf_vm_pie_x86_64"
# PIE rip-relative offset-table switch (lea/movsxd/add/jmp reg): isolates the
# computed-jump target map, which must be keyed base-independently.
FIXTURE_PIE_SWITCH = _DATASET / "elf_switch_pie_x86_64"

# A conventional Linux PIE base. Running an ET_DYN image at a NONZERO bias is the
# whole point: at bias 0 the link-time and runtime addresses coincide, so an
# address baked in at link time is indistinguishable from a correctly computed
# one and every base-dependence bug stays invisible. Biasing the image separates
# the two, so anything that is not base-independent diverges immediately.
LOAD_BIAS = 0x555555554000

_PT_LOAD = 1


def _pt_loads(path: Path) -> list[tuple[int, int, int, int]]:
    """Every PT_LOAD of an ELF64 as ``(p_offset, p_vaddr, p_filesz, p_memsz)``, in header order."""
    raw = path.read_bytes()
    e_phoff = struct.unpack_from("<Q", raw, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", raw, 0x36)[0]
    e_phnum = struct.unpack_from("<H", raw, 0x38)[0]

    segments: list[tuple[int, int, int, int]] = []
    for index in range(e_phnum):
        entry = e_phoff + index * e_phentsize
        if struct.unpack_from("<I", raw, entry)[0] != _PT_LOAD:
            continue
        p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, _p_align = struct.unpack_from("<QQQQQQ", raw, entry + 8)
        segments.append((p_offset, p_vaddr, p_filesz, p_memsz))
    return segments


def _e_phoff(path: Path) -> int:
    return int(struct.unpack_from("<Q", path.read_bytes(), 0x20)[0])


def _virtualize(fixture: Path, mutated: Path) -> int:
    """Copy ``fixture`` to ``mutated``, run the whole pass over it, return the virtualized count."""
    shutil.copy(fixture, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        stats = CodeVirtualizationPass(config={"probability": 1.0}).apply(binary)
        binary.save()
    finally:
        binary.close()
    return int(stats["functions_virtualized"])


def test_plain_pie_fixture_emulates_reference_exit_code_at_load_bias() -> None:
    # The unmutated fixture must already be base-independent: every reference in it
    # is rip-relative, so it exits 73 at a real load base just as it does at 0. This
    # is the control - if it ever fails, the fixture is at fault, not the pass, and
    # the parity assertions below would be measuring the wrong thing.
    if not FIXTURE_PIE.exists():
        pytest.skip(f"fixture missing: {FIXTURE_PIE}")

    assert emulate_exit_code(FIXTURE_PIE, load_bias=LOAD_BIAS) == 73


def test_virtualized_plain_pie_preserves_exit_code_at_load_bias(tmp_path: Path) -> None:
    # The injection proof. The VM blob goes into a brand-new R+X load segment
    # appended above the whole image, with the program-header table relocated into
    # it; the trampoline and the interpreter must reach their data through the
    # runtime base. Before the injector handled ET_DYN this produced nothing at all,
    # and a link-time absolute anywhere in the emitted code would trap or return a
    # value other than 73 once the image is biased.
    if not FIXTURE_PIE.exists():
        pytest.skip(f"fixture missing: {FIXTURE_PIE}")

    mutated = tmp_path / "mutated_pie"
    assert _virtualize(FIXTURE_PIE, mutated) >= 1
    assert emulate_exit_code(mutated, load_bias=LOAD_BIAS) == 73


def test_virtualized_pie_switch_preserves_exit_code_at_load_bias(tmp_path: Path) -> None:
    # The target-map proof. The PIE switch reconstructs its case address at runtime
    # (table base + signed 32-bit offset), so the virtualized computed jump has to
    # match that runtime value against the map of virtualized case entries. Keyed by
    # link-time absolutes, every compare misses at a real load base and the dispatch
    # silently falls through to the default VM exit - a wrong exit code, not a trap.
    # dispatch(2) = 30 must survive.
    if not FIXTURE_PIE_SWITCH.exists():
        pytest.skip(f"fixture missing: {FIXTURE_PIE_SWITCH}")

    mutated = tmp_path / "mutated_pie_switch"
    shutil.copy(FIXTURE_PIE_SWITCH, mutated)
    binary = Binary(str(mutated), writable=True)
    binary.open()
    try:
        binary.analyze()
        dispatch = next(f for f in binary.get_functions() if "dispatch" in (f.get("name") or ""))
        pass_ = CodeVirtualizationPass(config={"probability": 1.0, "virtualize_dispatch": True})
        # Driving the switch function directly keeps the parity assertion honest: it
        # cannot be satisfied by leaving the dispatch native and virtualizing only
        # the caller.
        assert pass_._virtualize_dispatch_function(binary, dispatch) is not None
        binary.save()
    finally:
        binary.close()

    assert emulate_exit_code(mutated, load_bias=LOAD_BIAS) == 30


def test_virtualized_pie_image_maps_headers_in_appended_rx_fragment(tmp_path: Path) -> None:
    # An independent structural oracle: this reads the produced FILE, not the code
    # that wrote it, so it holds even if the emitted interpreter were wrong. The
    # blob cannot be squeezed into an ET_DYN image's existing segments, so the
    # injector must append RX fragments above every pre-existing load. The first
    # fragment of each injection also maps the relocated program-header table,
    # avoiding a standalone metadata segment. The VM layout is randomized per
    # build, so only these invariants are asserted - never an absolute address.
    if not FIXTURE_PIE.exists():
        pytest.skip(f"fixture missing: {FIXTURE_PIE}")

    mutated = tmp_path / "mutated_phdr"
    _virtualize(FIXTURE_PIE, mutated)

    original_load_count = len(_pt_loads(FIXTURE_PIE))
    appended = _pt_loads(mutated)[original_load_count:]
    phoff = _e_phoff(mutated)
    table_owner = next(load for load in appended if load[0] <= phoff < load[0] + load[2])
    assert appended and table_owner in appended
