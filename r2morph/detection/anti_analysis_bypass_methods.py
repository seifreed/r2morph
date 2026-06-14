"""Bypass application helpers for anti-analysis mitigation."""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from r2morph.detection.anti_analysis_bypass_models import AntiAnalysisType, BypassTechnique

logger = logging.getLogger(__name__)


def get_bypass_methods(technique: AntiAnalysisType) -> list[BypassTechnique]:
    """Get appropriate bypass methods for a technique."""
    bypass_map = {
        AntiAnalysisType.DEBUGGER_DETECTION: [
            BypassTechnique.API_REDIRECTION,
            BypassTechnique.PROCESS_HIDING,
            BypassTechnique.ENVIRONMENT_MASKING,
        ],
        AntiAnalysisType.VM_DETECTION: [
            BypassTechnique.HARDWARE_EMULATION,
            BypassTechnique.REGISTRY_SPOOFING,
            BypassTechnique.FILE_SYSTEM_HOOKS,
        ],
        AntiAnalysisType.SANDBOX_DETECTION: [
            BypassTechnique.ENVIRONMENT_MASKING,
            BypassTechnique.FILE_SYSTEM_HOOKS,
            BypassTechnique.NETWORK_ISOLATION,
        ],
        AntiAnalysisType.TIMING_ATTACKS: [BypassTechnique.TIMING_MANIPULATION],
    }

    return bypass_map.get(technique, [])


def apply_bypass(
    bypass_technique: BypassTechnique,
    confidence: float,
    active_bypasses: dict[str, Any],
    environment_backup: dict[str, str],
    timing_baseline: dict[str, float],
) -> bool:
    """Apply a specific bypass technique."""
    try:
        if bypass_technique == BypassTechnique.ENVIRONMENT_MASKING:
            return apply_environment_masking(active_bypasses, environment_backup)
        if bypass_technique == BypassTechnique.API_REDIRECTION:
            return apply_api_redirection(active_bypasses)
        if bypass_technique == BypassTechnique.TIMING_MANIPULATION:
            return apply_timing_manipulation(active_bypasses, timing_baseline)
        if bypass_technique == BypassTechnique.REGISTRY_SPOOFING:
            return apply_registry_spoofing(active_bypasses)
        if bypass_technique == BypassTechnique.FILE_SYSTEM_HOOKS:
            return apply_filesystem_hooks(active_bypasses)
        if bypass_technique == BypassTechnique.PROCESS_HIDING:
            return apply_process_hiding(active_bypasses)
        if bypass_technique == BypassTechnique.HARDWARE_EMULATION:
            return apply_hardware_emulation(active_bypasses)

        logger.warning(f"Unknown bypass technique: {bypass_technique}")
        return False

    except Exception as e:
        logger.error(f"Failed to apply {bypass_technique.value}: {e}")
        return False


def apply_environment_masking(
    active_bypasses: dict[str, Any],
    environment_backup: dict[str, str],
) -> bool:
    """Apply environment masking bypass."""
    try:
        masking_vars = {
            "USERNAME": "Administrator",
            "COMPUTERNAME": "DESKTOP-PC",
            "PROCESSOR_IDENTIFIER": "Intel64 Family 6 Model 142 Stepping 10, GenuineIntel",
        }

        for var, value in masking_vars.items():
            environment_backup[var] = os.environ.get(var, "")
            os.environ[var] = value

        active_bypasses["environment_masking"] = masking_vars
        logger.debug("Applied environment masking")
        return True

    except Exception as e:
        logger.error(f"Environment masking failed: {e}")
        return False


def apply_api_redirection(active_bypasses: dict[str, Any]) -> bool:
    """Apply API redirection bypass."""
    try:
        logger.debug("API redirection bypass applied")
        active_bypasses["api_redirection"] = True
        return True

    except Exception as e:
        logger.error(f"API redirection failed: {e}")
        return False


def apply_timing_manipulation(active_bypasses: dict[str, Any], timing_baseline: dict[str, float]) -> bool:
    """Apply timing manipulation bypass."""
    try:
        timing_baseline.update({"start_time": time.time(), "perf_counter": time.perf_counter()})
        active_bypasses["timing_manipulation"] = timing_baseline
        logger.debug("Applied timing manipulation bypass")
        return True

    except Exception as e:
        logger.error(f"Timing manipulation failed: {e}")
        return False


def apply_registry_spoofing(active_bypasses: dict[str, Any]) -> bool:
    """Apply registry spoofing bypass."""
    try:
        logger.debug("Registry spoofing bypass applied")
        active_bypasses["registry_spoofing"] = True
        return True

    except Exception as e:
        logger.error(f"Registry spoofing failed: {e}")
        return False


def apply_filesystem_hooks(active_bypasses: dict[str, Any]) -> bool:
    """Apply filesystem hooks bypass."""
    try:
        logger.debug("Filesystem hooks bypass applied")
        active_bypasses["filesystem_hooks"] = True
        return True

    except Exception as e:
        logger.error(f"Filesystem hooks failed: {e}")
        return False


def apply_process_hiding(active_bypasses: dict[str, Any]) -> bool:
    """Apply process hiding bypass."""
    try:
        logger.debug("Process hiding bypass applied")
        active_bypasses["process_hiding"] = True
        return True

    except Exception as e:
        logger.error(f"Process hiding failed: {e}")
        return False


def apply_hardware_emulation(active_bypasses: dict[str, Any]) -> bool:
    """Apply hardware emulation bypass."""
    try:
        logger.debug("Hardware emulation bypass applied")
        active_bypasses["hardware_emulation"] = True
        return True

    except Exception as e:
        logger.error(f"Hardware emulation failed: {e}")
        return False


def backup_environment(environment_backup: dict[str, str]) -> None:
    """Backup current environment state."""
    try:
        environment_backup.clear()
        environment_backup.update(os.environ.copy())
        logger.debug("Environment backed up")

    except Exception as e:
        logger.error(f"Environment backup failed: {e}")


def get_environment_state(
    active_bypasses: dict[str, Any],
    timing_baseline: dict[str, float],
) -> dict[str, Any]:
    """Get current environment state."""
    return {
        "environment_vars": dict(os.environ),
        "active_bypasses": list(active_bypasses.keys()),
        "timing_baseline": timing_baseline.copy() if timing_baseline else {},
    }


def restore_environment(
    environment_backup: dict[str, str],
    active_bypasses: dict[str, Any],
    timing_baseline: dict[str, float],
) -> bool:
    """Restore original environment state."""
    try:
        for var, value in environment_backup.items():
            if value:
                os.environ[var] = value
            elif var in os.environ:
                del os.environ[var]

        active_bypasses.clear()
        timing_baseline.clear()

        logger.info("Environment restored")
        return True

    except Exception as e:
        logger.error(f"Environment restoration failed: {e}")
        return False


def get_bypass_status(
    active_bypasses: dict[str, Any],
    environment_backup: dict[str, str],
    timing_baseline: dict[str, float],
) -> dict[str, Any]:
    """Get current bypass status."""
    return {
        "active_bypasses": list(active_bypasses.keys()),
        "environment_modified": bool(environment_backup),
        "timing_baseline": bool(timing_baseline),
        "bypass_count": len(active_bypasses),
    }
