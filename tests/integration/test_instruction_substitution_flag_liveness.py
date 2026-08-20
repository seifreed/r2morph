"""Flag-liveness regression for instruction substitution.

``fixtures/dataset/elf_flag_live_x86_64`` zeroes ``rsi`` with the flag-neutral ``mov rsi, 0``
between a ``cmp`` (which sets ZF) and a ``jz`` (which reads it). Every equivalent in
that register's group is flag-setting (``xor``/``sub``), so substituting would change
ZF and flip the branch. The pass must refuse the substitution while the flags are
live, leaving the instruction unchanged.
"""

import shutil
from pathlib import Path

import pytest

from r2morph.core.binary import Binary
from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from tests.utils.assertions import expect

_FIXTURE = Path("fixtures/dataset/elf_flag_live_x86_64")
_CANDIDATE_ADDR = 0x1008  # `mov rsi, 0`
_FLAG_SETTING_SECOND_BYTES = {0x31, 0x29}  # xor / sub opcodes


def _candidate_is_flag_live(binary: Binary) -> bool:
    pass_obj = InstructionSubstitutionPass()
    pass_obj._init_substitution_rules()
    arch_family, _ = binary.get_arch_family()
    for _func, candidates in pass_obj._select_candidates(binary, binary.get_functions(), arch_family):
        for insn in candidates:
            if insn.get("addr") == _CANDIDATE_ADDR:
                return bool(insn.get("flags_live_after"))
    return False


def test_flag_live_zeroing_is_marked_live(tmp_path: Path):
    if not _FIXTURE.exists():
        pytest.skip("flag-liveness fixture not available")
    temp = tmp_path / "flag_live"
    shutil.copy(_FIXTURE, temp)
    with Binary(temp, writable=True) as binary:
        binary.analyze()
        expect(not (_candidate_is_flag_live(binary) is not True))


def test_flag_live_zeroing_is_never_substituted_to_a_flag_setter(tmp_path: Path):
    if not _FIXTURE.exists():
        pytest.skip("flag-liveness fixture not available")
    for seed in range(1, 16):
        temp = tmp_path / f"flag_live_{seed}"
        shutil.copy(_FIXTURE, temp)
        with Binary(temp, writable=True) as binary:
            binary.analyze()
            pass_obj = InstructionSubstitutionPass(config={"probability": 1.0, "seed": seed})
            pass_obj.force_different = True
            pass_obj.apply(binary)
            second_byte = binary.read_bytes(_CANDIDATE_ADDR + 1, 1)[0]
        expect(second_byte not in _FLAG_SETTING_SECOND_BYTES, f"flag-setting substitution applied at seed {seed}")
