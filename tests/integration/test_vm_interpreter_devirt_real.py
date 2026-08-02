"""
Devirtualization recovery oracle against a hand-built VM-interpreter fixture.

``dataset/elf_vm_interp_x86_64`` is a minimal, generic bytecode interpreter shaped
like a code-virtualization VM: a computed-goto dispatch loop that fetches an opcode,
indexes a handler table, and jumps through it, with each handler mutating a virtual
accumulator and jumping back to the dispatcher. It is the oracle the literal-recursion
spike needs - recovering it must yield the handler table, the bytecode region, and the
VM context.

These tests drive the real :class:`VMHandlerAnalyzer` on the real binary (no mocks).
The Unicorn emulation harness is reused from the sibling code-virtualization suite;
importing that module skips this one too when Unicorn is unavailable.

The per-capability recovery tests below start as characterization of the pre-oracle
state (nothing recovered) and are tightened to positive assertions as each recovery
function lands (D2 handler table, D3 bytecode, D4 context).
"""

from __future__ import annotations

from r2morph.core.binary import Binary
from r2morph.devirtualization.vm_handler_analyzer import VMHandlerAnalyzer
from r2morph.devirtualization.vm_handler_models import VMArchitecture
from tests.integration import test_code_virtualization_real as vm_real

FIXTURE = vm_real._DATASET / "elf_vm_interp_x86_64"

# The interpreter's bytecode computes LOADI 30; ADDI 20; SUBI 5; HALT -> exit(45).
_EXPECTED_EXIT_CODE = 45


def _recover() -> VMArchitecture:
    """Analyze the fixture's dispatcher and return the recovered VM architecture."""
    binary = Binary(str(FIXTURE))
    binary.open()
    try:
        binary.analyze("aa")
        assert binary.r2 is not None
        dispatcher = int(binary.r2.cmd("?v entry0").strip(), 16)
        return VMHandlerAnalyzer(binary).analyze_vm_architecture(dispatcher)
    finally:
        binary.close()


def test_vm_interpreter_fixture_emulates_to_expected_exit_code() -> None:
    """The fixture is a valid VM: its bytecode program exits with code 45."""
    assert vm_real._emulate_exit_code(FIXTURE) == _EXPECTED_EXIT_CODE


def test_vm_interpreter_handler_table_recovered() -> None:
    """The dispatcher's handler table is recovered at its true address (0x2000)."""
    assert _recover().handler_table_address == 0x2000


def test_vm_interpreter_handlers_recovered() -> None:
    """Recovering the table yields the four live handler entries."""
    assert len(_recover().handlers) == 4


def test_vm_interpreter_bytecode_region_located() -> None:
    """The bytecode region the vpc fetches from is located at its true address."""
    assert _recover().bytecode_address == 0x2028


def test_vm_interpreter_context_registers_inferred() -> None:
    """The dispatcher's vpc (rbx) and opcode (rax) registers are inferred as VM state."""
    assert _recover().vm_registers == ["rax", "rbx"]
