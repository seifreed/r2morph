from pathlib import Path

from r2morph.analysis.symbolic.syntia_models import InstructionSemantics, SemanticComplexity
from r2morph.analysis.symbolic.syntia_reporting import (
    build_learned_semantics_export,
    write_learned_semantics_export,
)


def test_syntia_reporting_contract(tmp_path: Path) -> None:
    semantics = InstructionSemantics(
        address=0x1000,
        instruction_bytes=b"\x90",
        disassembly="nop",
        learned_semantics="noop",
        confidence=0.8,
        complexity=SemanticComplexity.SIMPLE,
    )
    export_data = build_learned_semantics_export(
        {b"\x90": semantics},
        {
            "instructions_analyzed": 1,
            "semantics_learned": 2,
            "synthesis_failures": 3,
            "cache_hits": 4,
            "cache_size": 5,
        },
    )
    assert export_data["semantics"]["90"]["address"] == 0x1000

    output_path = tmp_path / "syntia.json"
    write_learned_semantics_export(output_path, export_data)
    assert output_path.exists()
