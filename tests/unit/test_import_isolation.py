"""Regression tests for import isolation and pytest-collection hygiene.

These guard two bugs that made the mandated ``pytest -W error`` run
(CLAUDE.md section 3) fail before it could execute a single test:

1. Importing ``r2morph`` eagerly pulled in ``angr`` (a heavy optional
   C-extension) through ``r2morph.analysis.__init__``. Besides violating
   adapter isolation (CLAUDE.md section 7), ``angr`` transitively imports
   ``cle``, which emits a third-party ``DeprecationWarning`` at import
   time -- fatal under ``-W error`` for the whole suite.

2. The domain classes ``TestSample`` / ``TestSeverity`` collide with
   pytest's default ``python_classes = ["Test*"]`` pattern, so pytest
   tried to collect them and emitted a ``PytestCollectionWarning`` that
   ``-W error`` turned into a fatal collection error in every test
   module importing them.

The first test runs in a *fresh* interpreter (real subprocess, no
mocks -- CLAUDE.md section 4) because by the time the pytest process
reaches this module, other collected modules may already have imported
``angr`` into ``sys.modules``.
"""

from __future__ import annotations

import subprocess
import sys

from r2morph.validation.benchmark_types import TestSample, TestSeverity


def test_importing_r2morph_does_not_eagerly_import_angr() -> None:
    """``import r2morph`` must not transitively import ``angr``.

    angr is an optional, heavy dependency that must stay isolated behind
    lazy access (``r2morph.analysis`` PEP 562 ``__getattr__``).
    """
    probe = (
        "import sys\n"
        "import r2morph\n"
        "leaked = sorted(m for m in sys.modules if m == 'angr' or m.startswith('angr.'))\n"
        "assert not leaked, f'angr imported eagerly: {leaked}'\n"
        "assert 'r2morph.analysis.symbolic' not in sys.modules, "
        "'symbolic subpackage imported eagerly'\n"
    )
    result = subprocess.run(
        [sys.executable, "-W", "error", "-c", probe],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, (
        f"fresh-interpreter import probe failed\n" f"stdout:\n{result.stdout}\n" f"stderr:\n{result.stderr}"
    )


def test_symbolic_names_are_part_of_the_lazy_public_api() -> None:
    """The PEP 562 boundary must still advertise the symbolic API.

    The names must stay reachable via ``__all__`` / ``dir()`` and an
    unknown attribute must still raise ``AttributeError``. This proves
    the lazy ``__getattr__`` wiring without forcing the deferred
    ``angr`` import (which would emit the unavoidable third-party
    ``cle`` ``DeprecationWarning``).
    """
    import r2morph.analysis as analysis

    for name in (
        "AngrBridge",
        "ConstraintSolver",
        "PathExplorer",
        "StateManager",
        "SyntiaFramework",
        "SYMBOLIC_AVAILABLE",
        "SYNTIA_AVAILABLE",
    ):
        assert name in analysis.__all__
        assert name in dir(analysis)

    try:
        analysis.__getattr__("definitely_not_an_attribute")
    except AttributeError:
        pass
    else:
        raise AssertionError("lazy __getattr__ must reject unknown names")


def test_benchmark_domain_classes_are_not_collected_by_pytest() -> None:
    """``TestSample`` / ``TestSeverity`` are domain types, not test classes.

    ``__test__ = False`` is pytest's documented opt-out; without it the
    ``Test*`` name collision breaks collection under ``-W error``.
    """
    assert TestSample.__test__ is False
    assert TestSeverity.__test__ is False
