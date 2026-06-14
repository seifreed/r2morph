"""Contract tests for detection pattern catalogs."""

from __future__ import annotations

from r2morph.detection import pattern_catalogs


def test_pattern_catalogs_expose_expected_values() -> None:
    assert "IsDebuggerPresent" in pattern_catalogs.ANTI_DEBUG_APIS
    assert "vmware" in pattern_catalogs.VM_ARTIFACTS
    assert "OLLYDBG" in pattern_catalogs.DEBUGGER_WINDOWS
    assert "Oracle VM VirtualBox" in pattern_catalogs.ANTI_ANALYSIS_REGISTRY[0]
