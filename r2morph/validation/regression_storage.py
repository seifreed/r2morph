"""Persistence helpers for regression baselines."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict
from pathlib import Path

from r2morph.validation.regression_models import BaselineResult, RegressionTestType

logger = logging.getLogger(__name__)


def load_baselines(baseline_dir: Path) -> dict[str, BaselineResult]:
    """Load existing baselines from disk."""
    baselines: dict[str, BaselineResult] = {}

    for baseline_file in baseline_dir.glob("*.json"):
        try:
            with open(baseline_file) as f:
                data = json.load(f)
                test_type = data.get("test_type")
                if isinstance(test_type, str):
                    if test_type.startswith("RegressionTestType."):
                        test_type = test_type.split(".", 1)[1]
                    try:
                        data["test_type"] = RegressionTestType(test_type)
                    except ValueError:
                        data["test_type"] = RegressionTestType.DETECTION_ACCURACY
                baseline = BaselineResult(**data)
                baselines[baseline.test_id] = baseline
                logger.debug("Loaded baseline: %s", baseline.test_id)
        except Exception as exc:
            logger.warning("Failed to load baseline %s: %s", baseline_file, exc)

    return baselines


def save_baseline(baseline_dir: Path, baseline: BaselineResult) -> None:
    """Persist a baseline to disk."""
    baseline_file = baseline_dir / f"{baseline.test_id}.json"

    try:
        with open(baseline_file, "w") as f:
            payload = asdict(baseline)
            if isinstance(payload.get("test_type"), RegressionTestType):
                payload["test_type"] = payload["test_type"].value
            json.dump(payload, f, indent=2, default=str)

        logger.info("Saved baseline: %s", baseline.test_id)
    except Exception as exc:
        logger.error("Failed to save baseline %s: %s", baseline.test_id, exc)
        raise
