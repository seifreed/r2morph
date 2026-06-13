from importlib import import_module

from r2morph.validation.shellcode_observables import compare_instruction_substitution_observables


class _ObservableCheckBinary:
    def get_arch_info(self):
        return {"arch": "x86", "bits": 32, "format": "ELF"}


def test_shellcode_observables_match_for_known_zeroing_pair() -> None:
    bridge_module = import_module("r2morph.analysis.symbolic.angr_bridge")
    result = compare_instruction_substitution_observables(
        _ObservableCheckBinary(),
        {
            "pass_name": "InstructionSubstitution",
            "mutations": [
                {
                    "start_address": 0x401000,
                    "end_address": 0x401001,
                    "original_bytes": "31c0",
                    "mutated_bytes": "29c0",
                    "metadata": {
                        "equivalence_group_index": 7,
                        "equivalence_original_pattern": "xor eax, eax",
                        "equivalence_replacement_pattern": "sub eax, eax",
                        "equivalence_members": ["xor eax, eax", "sub eax, eax"],
                    },
                }
            ],
        },
        bridge_module,
    )

    assert result["symbolic_observable_check_performed"] is True
    assert result["symbolic_observable_equivalent"] is True
    assert result["symbolic_observable_mismatches"] == []
    assert result["symbolic_observable_regions"][0]["mismatches"] == []
