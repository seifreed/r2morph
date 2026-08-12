"""Deterministic symbolic backend doubles."""

from types import SimpleNamespace
from typing import Any

from r2morph.validation.shellcode_equivalence import ShellcodeEquivalenceChecker


class _Factory:
    @staticmethod
    def successors(state: Any, num_inst: int = 1) -> SimpleNamespace:
        return SimpleNamespace(
            flat_successors=[SimpleNamespace(addr=state.addr + num_inst)],
            unsat_successors=[],
        )


class _Bridge:
    def __init__(self, binary: Any) -> None:
        self.angr_project = SimpleNamespace(factory=_Factory())

    @staticmethod
    def create_symbolic_state(address: int) -> SimpleNamespace:
        return SimpleNamespace(addr=address)


class SymbolicBridgeModule:
    ANGR_AVAILABLE = True
    AngrBridge = _Bridge
    angr = None


def load_symbolic_bridge(module_name: str) -> type[SymbolicBridgeModule]:
    return SymbolicBridgeModule


class ObservableMatchShellcodeChecker(ShellcodeEquivalenceChecker):
    def _compare_instruction_substitution_observables(
        self,
        binary: Any,
        pass_result: dict[str, Any],
        bridge_module: Any,
    ) -> dict[str, Any]:
        return {
            "symbolic_observable_check_performed": True,
            "symbolic_observable_equivalent": True,
            "symbolic_observable_reason": "observable register/flag effects matched",
            "symbolic_observable_regions": [
                {
                    "start_address": 0x401010,
                    "end_address": 0x401011,
                    "observables_checked": ["eax", "eflags"],
                    "original_successors": 1,
                    "mutated_successors": 1,
                    "mismatches": [],
                }
            ],
            "symbolic_observable_mismatches": [],
        }

    def _compare_instruction_substitution_transition(
        self,
        binary: Any,
        pass_result: dict[str, Any],
        bridge_module: Any,
    ) -> dict[str, Any]:
        return {}
