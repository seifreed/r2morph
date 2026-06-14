"""Reporting helpers for Syntia integration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from r2morph.analysis.symbolic.syntia_models import InstructionSemantics


def build_learned_semantics_export(
    semantics_cache: dict[bytes, InstructionSemantics],
    statistics: dict[str, Any],
) -> dict[str, Any]:
    """Build the export payload for learned semantics."""
    export_data = {"statistics": statistics, "semantics": {}}
    for inst_bytes, semantics in semantics_cache.items():
        export_data["semantics"][inst_bytes.hex()] = {
            "address": semantics.address,
            "disassembly": semantics.disassembly,
            "learned_semantics": semantics.learned_semantics,
            "semantic_formula": semantics.semantic_formula,
            "confidence": semantics.confidence,
            "complexity": semantics.complexity.value,
        }
    return export_data


def write_learned_semantics_export(output_path: Path, export_data: dict[str, Any]) -> None:
    """Persist the learned-semantics export to disk."""
    with open(output_path, "w") as f:
        json.dump(export_data, f, indent=2)
