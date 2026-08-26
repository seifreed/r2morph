"""Regression tests for optional symbolic-analysis dependencies."""

import sys

from tests.utils.assertions import expect
from tests.utils.process import run_command


def test_symbolic_modules_import_with_warnings_as_errors() -> None:
    """Optional backend incompatibility must not break test collection."""
    modules = (
        "r2morph.analysis.symbolic.angr_bridge",
        "r2morph.analysis.symbolic.constraint_solver",
        "r2morph.analysis.symbolic.path_explorer",
        "r2morph.analysis.symbolic.path_explorer_techniques",
        "r2morph.analysis.symbolic.state_manager",
        "r2morph.validation.constraint_cache",
        "r2morph.validation.semantic_symbolic",
        "r2morph.validation.state_merging",
    )
    command = [
        sys.executable,
        "-W",
        "error",
        "-c",
        "\n".join(f"import {module}" for module in modules),
    ]
    result = run_command(command, capture_output=True, text=True)

    expect(result.returncode == 0, result.stderr)
