from __future__ import annotations

import os

from r2morph.detection.anti_analysis_bypass_methods import (
    apply_bypass,
    backup_environment,
    get_bypass_methods,
    get_bypass_status,
    get_environment_state,
    restore_environment,
)
from r2morph.detection.anti_analysis_bypass_models import AntiAnalysisType, BypassTechnique
from tests.utils.assertions import expect


def test_get_bypass_methods_maps_known_techniques() -> None:
    methods = get_bypass_methods(AntiAnalysisType.DEBUGGER_DETECTION)

    expect(not (BypassTechnique.API_REDIRECTION not in methods))
    expect(not (BypassTechnique.PROCESS_HIDING not in methods))
    expect(get_bypass_methods(AntiAnalysisType.HARDWARE_FINGERPRINTING) == [])


def test_apply_bypass_updates_tracking_state() -> None:
    active_bypasses: dict[str, object] = {}
    environment_backup: dict[str, str] = {}
    timing_baseline: dict[str, float] = {}

    expect(
        not (
            apply_bypass(
                BypassTechnique.API_REDIRECTION,
                0.5,
                active_bypasses,
                environment_backup,
                timing_baseline,
            )
            is not True
        )
    )
    expect(not (active_bypasses["api_redirection"] is not True))


def test_environment_helpers_backup_restore_and_status() -> None:
    active_bypasses: dict[str, object] = {"api_redirection": True}
    environment_backup: dict[str, str] = {}
    timing_baseline: dict[str, float] = {"start_time": 1.0}
    original = dict(os.environ)

    try:
        backup_environment(environment_backup)
        expect(environment_backup)

        state = get_environment_state(active_bypasses, timing_baseline)
        expect(state["active_bypasses"] == ["api_redirection"])
        expect(state["timing_baseline"] == {"start_time": 1.0})

        status = get_bypass_status(active_bypasses, environment_backup, timing_baseline)
        expect(status["bypass_count"] == 1)
        expect(not (status["environment_modified"] is not True))

        expect(not (restore_environment(environment_backup, active_bypasses, timing_baseline) is not True))
        expect(active_bypasses == {})
        expect(timing_baseline == {})
    finally:
        os.environ.clear()
        os.environ.update(original)
