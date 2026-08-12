"""Regression: the region VM conditional branch carries no native jcc.

The handler must decide taken/not-taken arithmetically from the captured RFLAGS
and select the next virtual IP branch-free, so a devirtualizer cannot read the
condition or the CFG edge off a native ``jcc``. These tests assert the generated
handler assembly for every supported condition contains no conditional-jump
mnemonic, and that every condition the lifter can emit is handled.
"""

from __future__ import annotations

from r2morph.mutations.code_virtualization_region_classification import _CONDITION
from r2morph.mutations.code_virtualization_region_control_handlers import (
    _JCC_CONDITION_BASE,
    _jcc_handler_asm,
)

# Every x86 conditional-jump mnemonic (and synonym). ``jmp`` is unconditional and
# intentionally excluded; jcxz/jecxz/jrcxz are register-count branches the lifter
# never emits but are listed for completeness of the guard.
_NATIVE_CONDITIONAL_JUMPS = frozenset(
    {
        "je",
        "jz",
        "jne",
        "jnz",
        "jl",
        "jnge",
        "jge",
        "jnl",
        "jg",
        "jnle",
        "jle",
        "jng",
        "jb",
        "jc",
        "jnae",
        "jae",
        "jnc",
        "jnb",
        "jbe",
        "jna",
        "ja",
        "jnbe",
        "js",
        "jns",
        "jo",
        "jno",
        "jp",
        "jpe",
        "jnp",
        "jpo",
        "jcxz",
        "jecxz",
        "jrcxz",
    }
)

# A stand-in for the taken-target decode the real caller passes; its content is
# irrelevant to the branch-free property under test (it holds no jcc either).
_RETARGET_TARGET_STUB = "  mov eax, dword ptr [rsi+1]\n  lea r9, [rip+bytecode]\n  add r9, rax\n"


def _mnemonics(asm: str) -> list[str]:
    out = []
    for line in asm.splitlines():
        stripped = line.strip()
        if stripped and not stripped.endswith(":"):
            out.append(stripped.split()[0].lower())
    return out


def test_every_lifted_condition_has_a_branchless_handler() -> None:
    # A jcc condition the lifter can produce but the handler does not map would
    # KeyError at build time; guard the coverage explicitly.
    assert set(_CONDITION.values()) == set(_JCC_CONDITION_BASE)


def test_jcc_handler_emits_no_native_conditional_jump() -> None:
    for condition in _JCC_CONDITION_BASE:
        asm = _jcc_handler_asm(condition, _RETARGET_TARGET_STUB)
        offending = _NATIVE_CONDITIONAL_JUMPS.intersection(_mnemonics(asm))
        assert not offending, f"{condition}: native conditional jump(s) {offending}"


def test_jcc_handler_selects_branch_free_from_captured_flags() -> None:
    # The handler must load the captured flags and build a 0/-1 select mask - the
    # markers that prove it is the arithmetic path, not a native compare-and-jump.
    asm = _jcc_handler_asm("jg", _RETARGET_TARGET_STUB)
    mnemonics = _mnemonics(asm)
    assert "neg" in mnemonics  # 0/-1 mask
    assert "cmov" not in "".join(mnemonics)  # no conditional move either
    assert "vm_dispatch" in asm  # tail-dispatches like every handler
