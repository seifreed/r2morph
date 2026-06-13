from types import SimpleNamespace
from unittest.mock import patch

from r2morph.validation.symbolic_precheck_flow import run_symbolic_precheck


class _StubBridge:
    def __init__(self, _binary: object) -> None:
        self.angr_project = SimpleNamespace(factory=SimpleNamespace(successors=self._successors))

    def create_symbolic_state(self, start: int) -> object | None:
        return {"addr": start}

    @staticmethod
    def _successors(state: object, num_inst: int) -> SimpleNamespace:
        return SimpleNamespace(flat_successors=[SimpleNamespace(addr=0x2000)], unsat_successors=[])


def test_run_symbolic_precheck_supports_scope_and_records_steps() -> None:
    bridge_module = SimpleNamespace(ANGR_AVAILABLE=True, AngrBridge=_StubBridge)
    with patch("importlib.import_module", return_value=bridge_module):
        payload = run_symbolic_precheck(
            SimpleNamespace(get_arch_info=lambda: {"arch": "x86_64", "bits": 64}),
            {
                "pass_name": "InstructionSubstitution",
                "mutations": [
                    {
                        "start_address": 0x1000,
                        "end_address": 0x1004,
                        "metadata": {
                            "equivalence_group_index": 1,
                            "equivalence_members": ["a", "b"],
                            "equivalence_original_pattern": "a",
                            "equivalence_replacement_pattern": "b",
                        },
                    }
                ],
            },
            supports_scope=lambda _binary, _pass_result: (True, "supported", {}),
            estimate_steps=lambda _pass_name, _mutation: 1,
            build_hint=lambda _pass_result: {"symbolic_semantic_hint_supported": True},
            compare_observables=lambda *_args: {"symbolic_observable_check_performed": False},
            compare_transition=lambda *_args: {"symbolic_transition_check_performed": False},
        )

    assert payload["symbolic_status"] == "bounded-step-known-equivalence"
    assert payload["symbolic_step_count"] == 1
