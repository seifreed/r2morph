"""Exact characterization of ControlFlowFlatteningPass._analyze_jump_target.

This method had zero test coverage. It is pinned here with exact-output
assertions *before* the clean-arch decomposition moves it verbatim into
a JumpObfuscator collaborator (CFF slice 5/6), so any divergence in the
extracted code or its delegation wiring is caught.

No mocks / monkeypatch (CLAUDE.md §4): a real ControlFlowFlatteningPass
instance is used. The `binary` argument is genuinely unused by the
method body (only `jump_insn` is inspected), so passing None is valid
and exercises the real code path.
"""

from __future__ import annotations

from r2morph.mutations.control_flow_flattening import ControlFlowFlatteningPass


def _analyze(jump_insn: dict) -> dict | None:
    return ControlFlowFlatteningPass()._analyze_jump_target(None, jump_insn, 0x1000, "x86", 64)


def test_valid_jmp_with_hex_target_returns_target_and_size() -> None:
    assert _analyze({"disasm": "jmp 0x1234abcd", "size": 5}) == {
        "target": 0x1234ABCD,
        "size": 5,
    }


def test_uppercase_jmp_and_uppercase_hex_are_case_insensitive() -> None:
    assert _analyze({"disasm": "JMP 0xABCDEF", "size": 7}) == {
        "target": 0xABCDEF,
        "size": 7,
    }


def test_first_hex_token_wins_when_multiple_present() -> None:
    assert _analyze({"disasm": "jmp 0x10 ; was 0x20", "size": 3}) == {
        "target": 0x10,
        "size": 3,
    }


def test_empty_disasm_returns_none() -> None:
    assert _analyze({"disasm": "", "size": 5}) is None


def test_disasm_without_hex_returns_none() -> None:
    assert _analyze({"disasm": "jmp sym.target", "size": 5}) is None


def test_zero_size_returns_none() -> None:
    assert _analyze({"disasm": "jmp 0xdeadbeef", "size": 0}) is None


def test_missing_size_key_defaults_to_zero_and_returns_none() -> None:
    assert _analyze({"disasm": "jmp 0xbeef"}) is None


def test_non_jmp_mnemonic_returns_none() -> None:
    assert _analyze({"disasm": "call 0xdeadbeef", "size": 5}) is None
