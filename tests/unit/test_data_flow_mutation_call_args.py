"""Regression test: SysV AMD64 ``call`` reads arg regs (rdi/rsi/rdx/rcx/r8/r9).

``DataFlowMutationPass._analyze_function_liveness`` previously hardcoded the
call's ``used`` set as ``["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"]`` -- the
caller-saved set, NOT the SysV argument set. ``rdi`` and ``rsi`` (the most
common argument registers) were missing from ``used`` and the
caller-saved kill set on ``defined`` only contained ``rax``.

Effect: a register loaded for a call argument was treated as dead at the
instruction immediately preceding the call. The substitute search in
``_find_safe_substitution_candidates`` then picked it as a ``dead_reg``
target and rewrote a neighbouring instruction to write into it, clobbering
the argument value before the call read it.

No-mocks regression (CLAUDE.md sec.4): real ``DataFlowMutationPass``, real
helper methods, hand-built instruction stream that mirrors what the caller
gets from radare2's ``pdj``.
"""

from __future__ import annotations

from r2morph.mutations.data_flow_mutation import DataFlowMutationPass


def _arg_load_call_stream() -> list[dict[str, object]]:
    """Three instructions: load rdi (the SysV first arg), do scratch work in
    rcx, then call. The ``next_addr`` linkage is required so the simplified
    backward liveness propagates from the call back over the body."""
    return [
        {"addr": 0x1000, "next_addr": 0x1007, "disasm": "mov rdi, 5"},
        {"addr": 0x1007, "next_addr": 0x100A, "disasm": "xor rcx, rcx"},
        {"addr": 0x100A, "next_addr": 0, "disasm": "call func"},
    ]


def test_call_marks_sysv_argument_registers_as_used() -> None:
    """At the call site, rdi/rsi/rdx/rcx/r8/r9 must be in live_in -- they are
    the SysV AMD64 integer-argument registers the callee will read."""
    pass_obj = DataFlowMutationPass()

    live_in = pass_obj._analyze_function_liveness(_arg_load_call_stream())

    call_live = live_in[0x100A]
    for arg_reg in ("rdi", "rsi", "rdx", "rcx", "r8", "r9"):
        assert arg_reg in call_live, (
            f"SysV arg register {arg_reg!r} must be live at the call site; " f"got {sorted(call_live)!r}"
        )


def test_loaded_argument_register_stays_live_until_call() -> None:
    """``mov rdi, 5; xor rcx, rcx; call func`` -- rdi must be in live_in at
    the xor (the instruction between the arg-load and the call), otherwise
    the candidate search treats rdi as a dead substitute target."""
    pass_obj = DataFlowMutationPass()

    live_in = pass_obj._analyze_function_liveness(_arg_load_call_stream())

    xor_live = live_in[0x1007]
    assert "rdi" in xor_live, (
        "rdi was loaded for the upcoming call argument and must remain live " f"at 0x1007; got {sorted(xor_live)!r}"
    )


def test_call_argument_register_never_used_as_substitute_target() -> None:
    """End-to-end: the candidate list emitted by ``_find_safe_substitution_candidates``
    must not propose substituting any operand with rdi at a point where rdi
    holds an upcoming-call argument. Pre-fix it produced (xor-insn, rcx, rdi)
    because rdi was wrongly considered dead between the load and the call."""
    pass_obj = DataFlowMutationPass()
    instructions = _arg_load_call_stream()

    live_in = pass_obj._analyze_function_liveness(instructions)
    candidates = pass_obj._find_safe_substitution_candidates(instructions, live_in, "x86_64")

    rdi_targets = [(orig, subst) for _insn, orig, subst in candidates if subst == "rdi"]
    assert not rdi_targets, (
        "rdi holds the upcoming call argument; the candidate search must not "
        f"propose it as a substitute: {rdi_targets!r}"
    )
