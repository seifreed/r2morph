"""Regression test: DataFlowMutation must be reproducible across processes.

Bug (same class as register_substitution): in
``_find_safe_substitution_candidates`` both ``caller_saved`` and
``dead_regs`` (= ``all_regs - live``) are ``set`` objects that were
iterated directly. ``set`` iteration order is randomized per process by
``PYTHONHASHSEED``; the inner ``for dead_reg in dead_regs: ...; break``
therefore picked a non-deterministic substitute register, and the
candidate list order varied, so the downstream *seeded*
``random.sample`` produced different mutations across processes with the
same ``seed=`` -- breaking r2morph's reproducibility guarantee.

Runs real subprocesses (CLAUDE.md s.4: no mocks) with different
``PYTHONHASHSEED`` values; the candidate list must be byte-for-byte
identical. Fails before the ``sorted()`` fix, passes after.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

_PROBE = """
import json
from r2morph.mutations.data_flow_mutation import DataFlowMutationPass

pass_obj = DataFlowMutationPass()
instructions = [
    {"addr": 0x1000, "disasm": "mov rax, rcx"},
    {"addr": 0x1004, "disasm": "add rdx, rsi"},
    {"addr": 0x1008, "disasm": "xor rdi, r8"},
]
live_in = {
    0x1000: {"rax", "rcx"},
    0x1004: {"rdx", "rsi"},
    0x1008: {"rdi", "r8"},
}
candidates = pass_obj._find_safe_substitution_candidates(instructions, live_in, "x86_64")
print(json.dumps([(orig, subst) for _insn, orig, subst in candidates]))
"""


def _run_with_hash_seed(hash_seed: str) -> str:
    result = subprocess.run(
        [sys.executable, "-c", _PROBE],
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "PYTHONHASHSEED": hash_seed},
    )
    assert result.returncode == 0, (
        f"probe failed (PYTHONHASHSEED={hash_seed})\n" f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    return result.stdout.strip()


def test_candidate_selection_is_reproducible_across_hash_seeds() -> None:
    outputs = {hs: _run_with_hash_seed(hs) for hs in ("0", "1", "42", "12345")}

    first = next(iter(outputs.values()))
    assert json.loads(first), f"probe produced no candidates: {first!r}"

    distinct = set(outputs.values())
    assert len(distinct) == 1, (
        "DataFlowMutation candidate selection is not reproducible across " f"PYTHONHASHSEED values: {outputs}"
    )
