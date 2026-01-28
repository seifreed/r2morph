import random
import shutil

from r2morph.core.binary import Binary
from r2morph.mutations.dead_code_injection import DeadCodeInjectionPass
from r2morph.mutations.instruction_expansion import InstructionExpansionPass
from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.mutations.opaque_predicates import OpaquePredicatePass
from r2morph.mutations.register_substitution import RegisterSubstitutionPass


def test_multiple_mutation_passes_on_x86_binary(tmp_path):
    random.seed(1234)
    src = "dataset/pe_x86_64.exe"
    target = tmp_path / "pe_x86_64_mut.exe"
    shutil.copy2(src, target)

    with Binary(target, writable=True) as bin_obj:
        bin_obj.analyze("aa")

        passes = [
            DeadCodeInjectionPass({"probability": 1.0}),
            InstructionExpansionPass({"probability": 1.0}),
            InstructionSubstitutionPass({"probability": 1.0}),
            NopInsertionPass({"probability": 1.0}),
            RegisterSubstitutionPass({"probability": 1.0}),
            OpaquePredicatePass({"probability": 1.0, "max_predicates_per_function": 1}),
        ]

        for mutation in passes:
            stats = mutation.apply(bin_obj)
            assert isinstance(stats, dict)
            assert "mutations_applied" in stats
