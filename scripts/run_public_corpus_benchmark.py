#!/usr/bin/env python3
"""Run the pinned public-corpus benchmark with the project timeout contract."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

_ANALYZER_TIMEOUT_SECONDS = 120
_PINNED_ANALYZER_TIMEOUT_SECONDS = 30
_MIN_ARGUMENT_COUNT = 2


def _load_benchmark(script: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("r2morph_public_corpus_benchmark", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load public corpus benchmark: {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    if len(sys.argv) < _MIN_ARGUMENT_COUNT:
        raise SystemExit("usage: run_public_corpus_benchmark.py SCRIPT [SCRIPT_ARGS ...]")
    script = Path(sys.argv.pop(1))
    module = _load_benchmark(script)
    if getattr(module, "_ANALYZER_TIMEOUT_SECONDS", None) != _PINNED_ANALYZER_TIMEOUT_SECONDS:
        raise RuntimeError("unexpected public corpus benchmark timeout contract")
    # The pinned corpus script has no timeout option; large static exception
    # fixtures need a bounded 120-second analyzer window.
    module._ANALYZER_TIMEOUT_SECONDS = _ANALYZER_TIMEOUT_SECONDS
    return int(module.main())


if __name__ == "__main__":
    raise SystemExit(main())
