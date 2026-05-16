"""Regression test: RegisterSubstitution must be reproducible across processes.

Bug: ``_find_substitution_candidates`` built ``unused`` via
``list(caller_saved - used_registers)`` and iterated
``used_registers & caller_saved`` directly. Both are ``set`` objects, so
their iteration order is randomized per process by ``PYTHONHASHSEED``.
The subsequent *seeded* ``random.shuffle`` / ``random.sample`` therefore
produced different substitutions across processes **even with the same
``seed=``**, defeating r2morph's core reproducibility guarantee and
making symbolic-scope detection flaky in the test suite.

This runs real subprocesses (CLAUDE.md s.4: no mocks) with different
``PYTHONHASHSEED`` values; with a fixed RNG seed the candidate list must
be byte-for-byte identical. It fails before the ``sorted()`` fix and
passes after.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

_PROBE = """
import json, random
from r2morph.mutations.register_substitution import RegisterSubstitutionPass

pass_obj = RegisterSubstitutionPass()
instructions = [
    {"disasm": "mov rax, 1"},
    {"disasm": "add rcx, 2"},
    {"disasm": "xor rdx, rdx"},
    {"disasm": "inc rsi"},
]
random.seed(1337)
print(json.dumps(pass_obj._find_substitution_candidates(instructions, "x64")))
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

    # Must be non-trivial (the inputs do yield candidates) so the test
    # actually exercises the ordering path rather than passing vacuously.
    first = next(iter(outputs.values()))
    assert json.loads(first), f"probe produced no candidates: {first!r}"

    distinct = set(outputs.values())
    assert len(distinct) == 1, (
        "RegisterSubstitution candidate selection is not reproducible " f"across PYTHONHASHSEED values: {outputs}"
    )
