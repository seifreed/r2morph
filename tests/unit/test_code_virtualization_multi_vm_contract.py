"""Contract tests for the multi-VM virtualization helpers."""

from r2morph.mutations.code_virtualization import MultiVMVirtualizationPass
from r2morph.mutations.code_virtualization_multi_vm import (
    resolve_multi_vm_profiles,
    select_multi_vm_profile,
)
from tests._doubles.in_memory_virtualization_binary import InMemoryVirtualizationBinary

INSNS = [
    {"mnemonic": "mov", "disasm": "mov eax, ebx", "size": 2, "type": "mov"},
    {"mnemonic": "add", "disasm": "add eax, 1", "size": 3, "type": "add"},
]
BASE = 0x2000
CONTENTS = bytes(range(64))


def test_multi_vm_profile_resolution_and_selection() -> None:
    active = resolve_multi_vm_profiles(["simple", "missing", "obfuscated"], 3)
    assert [profile.name for profile in active] == ["simple", "simple", "obfuscated"]

    selected = select_multi_vm_profile(active, randomize_selection=False, func_addr=BASE)
    assert selected.name == active[BASE % len(active)].name


def test_multi_vm_apply_uses_real_binary_surface() -> None:
    binary = InMemoryVirtualizationBinary(base_addr=BASE, contents=CONTENTS, insns=INSNS, reads_fail=False)
    p = MultiVMVirtualizationPass(
        {
            "probability": 1.0,
            "include_dispatcher": True,
            "max_functions": 2,
            "profiles": ["simple", "obfuscated"],
            "num_vms": 2,
            "randomize_selection": False,
        }
    )

    result = p.apply(binary)

    assert result["functions_virtualized"] == 1
    assert result["profiles_used"]["simple"] == 1
    assert result["dispatchers_generated"] == 2
    assert result["active_profiles"] == ["simple", "obfuscated"]
    assert result["architecture"] == "x64"
