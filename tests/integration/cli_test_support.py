"""Shared real-binary fixtures for CLI integration tests."""

import importlib.util
from pathlib import Path

import pytest

from r2morph.mutations.base import MutationPass
from tests.utils.assertions import expect


class CLIIntegrationBase:
    """Provide the installed CLI prerequisites and ELF test fixture."""

    @pytest.fixture(autouse=True)
    def _require_r2pipe(self):
        if importlib.util.find_spec("r2pipe") is None:
            pytest.skip("r2pipe not installed")
        if importlib.util.find_spec("yaml") is None:
            pytest.skip("pyyaml not installed")

    @pytest.fixture
    def ls_elf(self):
        return Path(__file__).parent.parent.parent / "fixtures" / "dataset" / "elf_x86_64"


class _ReportFixturePass(MutationPass):
    """Record one real binary region for report integration tests."""

    def __init__(self):
        super().__init__("ReportFixture")

    def apply(self, binary):
        functions = binary.get_functions()
        expect(functions)
        func_addr = functions[0].get("offset", functions[0].get("addr", 0))
        instructions = binary.get_function_disasm(func_addr)
        expect(instructions)
        insn = instructions[0]
        address = insn.get("addr", 0)
        size = insn.get("size", 1)
        original = binary.read_bytes(address, size)
        expect(binary.write_bytes(address, original))
        self._record_mutation(
            function_address=func_addr,
            start_address=address,
            end_address=address + size - 1,
            original_bytes=original,
            mutated_bytes=original,
            original_disasm=insn.get("disasm", ""),
            mutated_disasm=insn.get("disasm", ""),
            mutation_kind="report_fixture",
            metadata={"integration": True},
        )
        return {"mutations_applied": 1}
