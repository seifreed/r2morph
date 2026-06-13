"""Output helpers extracted from MorphEngine."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def build_report(engine: Any, result: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build a stable machine-readable engine report."""
    return engine._report_builder.assemble_report(
        result,
        pipeline_passes=engine.pipeline.passes,
        last_result=engine._last_result,
    )


def save_binary(engine: Any, output_path: str | Path) -> None:
    """Save the transformed binary through the engine state."""
    if not engine.binary:
        raise RuntimeError("No binary loaded.")

    output = Path(output_path)
    logger.info(f"Saving transformed binary to: {output}")

    if engine._session is not None:
        engine._session.finalize(output)
    else:
        assert engine.binary is not None
        from shutil import copy2

        copy2(engine.binary.path, output)
        logger.info(f"Binary successfully saved to: {output}")

    engine._binary_signer.sign_output(output, engine.config)


def save_report(engine: Any, output_path: str | Path, result: dict[str, Any] | None = None) -> Path:
    """Save a JSON report for the last engine run."""
    output = Path(output_path)
    report = build_report(engine, result)
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
    logger.info(f"Saved engine report to: {output}")
    return output
