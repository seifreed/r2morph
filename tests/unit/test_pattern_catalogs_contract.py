"""Contract tests for detection pattern catalogs."""

from __future__ import annotations

from r2morph.detection import pattern_catalogs
from tests.utils.assertions import expect


def test_pattern_catalogs_expose_expected_values() -> None:
    expect(not ("IsDebuggerPresent" not in pattern_catalogs.ANTI_DEBUG_APIS))
    expect(not ("vmware" not in pattern_catalogs.VM_ARTIFACTS))
    expect(not ("OLLYDBG" not in pattern_catalogs.DEBUGGER_WINDOWS))
    expect(not ("Oracle VM VirtualBox" not in pattern_catalogs.ANTI_ANALYSIS_REGISTRY[0]))
