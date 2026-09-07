import shutil
from pathlib import Path

from r2morph.core import randomness
from r2morph.core.binary import Binary
from r2morph.mutations.dead_code_injection import DeadCodeInjectionPass
from r2morph.mutations.instruction_expansion import InstructionExpansionPass
from r2morph.mutations.instruction_substitution import InstructionSubstitutionPass
from r2morph.mutations.nop_insertion import NopInsertionPass
from r2morph.mutations.opaque_predicates import OpaquePredicatePass
from r2morph.mutations.register_substitution import RegisterSubstitutionPass
from r2morph.platform.pe_handler import PEHandler
from tests.utils.assertions import expect


def test_multiple_mutation_passes_on_x86_binary(tmp_path):
    randomness.seed(1234)
    src = "fixtures/dataset/pe_x86_64.exe"
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
            expect(isinstance(stats, dict))
            expect(not ("mutations_applied" not in stats))


def test_instruction_substitution_pe_x86_64_preserves_real_integrity(tmp_path: Path) -> None:
    source = Path("fixtures/dataset/pe_x86_64.exe")
    target = tmp_path / "pe_x86_64_substitute.exe"
    shutil.copy2(source, target)
    handler = PEHandler(target)

    with Binary(target, writable=True) as binary:
        binary.analyze("aa")
        pass_obj = InstructionSubstitutionPass({"probability": 1.0, "force_different": True})
        result = pass_obj.apply(binary)

    expect(result["mutations_applied"] > 0)
    expect(all(record.original_bytes != record.mutated_bytes for record in pass_obj._records))
    expect(handler.fix_checksum())
    expect(handler.validate_integrity()[0])
