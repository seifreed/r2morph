from r2morph.mutations.nop_insertion import NopInsertionPass
from tests.utils.assertions import expect


def test_mutation_record_catalogues_original_and_mutated_mnemonics() -> None:
    mutation_pass = NopInsertionPass(config={})
    record = mutation_pass._record_mutation(
        function_address=0x1000,
        start_address=0x1000,
        end_address=0x1005,
        original_bytes=b"\x89\xd8",
        mutated_bytes=b"\x8d\x04\x03",
        original_disasm="0x1000 mov eax, ebx",
        mutated_disasm="0x1000 lea eax, [rbx]",
        mutation_kind="instruction-substitution",
    )

    expect(record.metadata["affected_instruction_mnemonics"] == ["lea", "mov"])
