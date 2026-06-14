"""
Detection helpers for anti-analysis techniques.

This module owns the pattern catalog and the detection-only logic used by
``AntiAnalysisBypass``. The bypass class keeps its public API, but the
matching and runtime checks live here so detection can evolve separately
from bypass application.
"""

from __future__ import annotations

import logging
import os
import time
from typing import TYPE_CHECKING, Any

from r2morph.detection.anti_analysis_bypass_models import AntiAnalysisPattern, AntiAnalysisType

if TYPE_CHECKING:
    import psutil
else:
    try:
        import psutil
    except ImportError:
        psutil = None

PSUTIL_AVAILABLE = psutil is not None

logger = logging.getLogger(__name__)


def load_anti_analysis_patterns() -> list[AntiAnalysisPattern]:
    """Load known anti-analysis patterns."""
    patterns = []

    patterns.append(
        AntiAnalysisPattern(
            name="IsDebuggerPresent",
            technique_type=AntiAnalysisType.DEBUGGER_DETECTION,
            api_calls=["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"],
            string_patterns=["debugger", "ollydbg", "x64dbg", "windbg"],
        )
    )

    patterns.append(
        AntiAnalysisPattern(
            name="PEB Debugger Check",
            technique_type=AntiAnalysisType.DEBUGGER_DETECTION,
            api_calls=["NtQueryInformationProcess", "GetThreadContext"],
            string_patterns=["BeingDebugged", "NtGlobalFlag"],
        )
    )

    patterns.append(
        AntiAnalysisPattern(
            name="VMware Detection",
            technique_type=AntiAnalysisType.VM_DETECTION,
            registry_keys=[
                r"SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_15AD",
                r"SOFTWARE\\VMware, Inc.\\VMware Tools",
            ],
            file_paths=["C:\\Program Files\\VMware\\VMware Tools\\", "C:\\Windows\\System32\\drivers\\vmmouse.sys"],
            process_names=["vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe"],
            string_patterns=["vmware", "VMXh"],
        )
    )

    patterns.append(
        AntiAnalysisPattern(
            name="VirtualBox Detection",
            technique_type=AntiAnalysisType.VM_DETECTION,
            registry_keys=[
                r"SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_80EE",
                r"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
            ],
            file_paths=[
                "C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\",
                "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
            ],
            process_names=["VBoxService.exe", "VBoxTray.exe"],
            string_patterns=["vbox", "virtualbox", "oracle"],
        )
    )

    patterns.append(
        AntiAnalysisPattern(
            name="Cuckoo Sandbox",
            technique_type=AntiAnalysisType.SANDBOX_DETECTION,
            file_paths=["C:\\analysis\\", "C:\\sample\\", "C:\\cuckoo\\"],
            process_names=["analyzer.py", "agent.py"],
            string_patterns=["cuckoo", "sandbox", "analysis"],
        )
    )

    patterns.append(
        AntiAnalysisPattern(
            name="Joe Sandbox",
            technique_type=AntiAnalysisType.SANDBOX_DETECTION,
            file_paths=["C:\\joesandbox\\"],
            registry_keys=[r"SOFTWARE\\Joe Security"],
            string_patterns=["joe", "joeboxserver", "joesandbox"],
        )
    )

    patterns.append(
        AntiAnalysisPattern(
            name="Sleep/Delay Evasion",
            technique_type=AntiAnalysisType.TIMING_ATTACKS,
            api_calls=["Sleep", "GetTickCount", "QueryPerformanceCounter", "timeGetTime"],
            timing_patterns=["sleep", "delay", "wait"],
        )
    )

    patterns.append(
        AntiAnalysisPattern(
            name="Process Enumeration",
            technique_type=AntiAnalysisType.PROCESS_INSPECTION,
            api_calls=["CreateToolhelp32Snapshot", "Process32First", "Process32Next", "EnumProcesses"],
            string_patterns=["process", "enum", "toolhelp"],
        )
    )

    patterns.append(
        AntiAnalysisPattern(
            name="API Hook Detection",
            technique_type=AntiAnalysisType.API_HOOKING_DETECTION,
            api_calls=["GetProcAddress", "LoadLibrary", "SetWindowsHookEx", "GetModuleHandle"],
            string_patterns=["hook", "detour", "patch"],
        )
    )

    return patterns


def detect_anti_analysis_techniques(
    binary: Any,
    patterns: list[AntiAnalysisPattern],
) -> dict[AntiAnalysisType, float]:
    """Detect anti-analysis techniques in a binary."""
    results: dict[AntiAnalysisType, float] = {}

    try:
        logger.info("Detecting anti-analysis techniques")

        for pattern in patterns:
            confidence = check_pattern_match(pattern, binary)

            if confidence >= pattern.confidence_threshold:
                results[pattern.technique_type] = max(results.get(pattern.technique_type, 0.0), confidence)
                logger.debug(f"Detected {pattern.name} with confidence {confidence:.2f}")

        runtime_results = detect_runtime_anti_analysis()
        for technique, confidence in runtime_results.items():
            results[technique] = max(results.get(technique, 0.0), confidence)

    except Exception as e:
        logger.error(f"Anti-analysis detection failed: {e}")

    return results


def check_pattern_match(pattern: AntiAnalysisPattern, binary: Any) -> float:
    """Check if a pattern matches the binary."""
    confidence = 0.0
    total_checks = 0
    matches = 0

    try:
        if pattern.api_calls:
            imports = binary.get_imports()
            import_names = [imp.get("name", "") for imp in imports]

            for api_call in pattern.api_calls:
                total_checks += 1
                if any(api_call.lower() in name.lower() for name in import_names):
                    matches += 1

        if pattern.string_patterns:
            strings_output = binary.r2.cmd("izz")

            for string_pattern in pattern.string_patterns:
                total_checks += 1
                if string_pattern.lower() in strings_output.lower():
                    matches += 1

        if total_checks > 0:
            confidence = matches / total_checks

    except Exception as e:
        logger.debug(f"Pattern check failed for {pattern.name}: {e}")

    return confidence


def detect_runtime_anti_analysis() -> dict[AntiAnalysisType, float]:
    """Detect anti-analysis techniques at runtime."""
    results = {}

    try:
        if PSUTIL_AVAILABLE:
            debugger_processes = [
                "ollydbg.exe",
                "x64dbg.exe",
                "windbg.exe",
                "ida.exe",
                "ida64.exe",
                "idaq.exe",
                "idaq64.exe",
                "devenv.exe",
                "ghidra.exe",
            ]

            running_processes = [p.name().lower() for p in psutil.process_iter(["name"])]
            debugger_count = sum(1 for proc in debugger_processes if proc in running_processes)

            if debugger_count > 0:
                results[AntiAnalysisType.DEBUGGER_DETECTION] = min(1.0, debugger_count / len(debugger_processes) * 3)

        vm_confidence = check_vm_environment()
        if vm_confidence > 0:
            results[AntiAnalysisType.VM_DETECTION] = vm_confidence

        timing_confidence = check_timing_manipulation()
        if timing_confidence > 0:
            results[AntiAnalysisType.TIMING_ATTACKS] = timing_confidence

    except Exception as e:
        logger.debug(f"Runtime detection failed: {e}")

    return results


def check_vm_environment() -> float:
    """Check for VM environment indicators."""
    confidence = 0.0

    try:
        vm_indicators = []

        if PSUTIL_AVAILABLE:
            cpu_count = psutil.cpu_count()
            if cpu_count is not None and cpu_count <= 2:
                vm_indicators.append("low_cpu_count")

            memory = psutil.virtual_memory().total
            if memory < 2 * 1024 * 1024 * 1024:  # Less than 2GB
                vm_indicators.append("low_memory")

        vm_files = [
            "C:\\Windows\\System32\\drivers\\vmmouse.sys",
            "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
            "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
            "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
        ]

        for vm_file in vm_files:
            if os.path.exists(vm_file):
                vm_indicators.append(f"vm_file:{vm_file}")

        if vm_indicators:
            confidence = min(1.0, len(vm_indicators) / 5.0)

    except Exception as e:
        logger.debug(f"VM environment check failed: {e}")

    return confidence


def check_timing_manipulation() -> float:
    """Check for timing manipulation."""
    try:
        start_time = time.perf_counter()
        time.sleep(0.001)  # 1ms sleep
        end_time = time.perf_counter()

        actual_delay = end_time - start_time
        expected_delay = 0.001

        deviation = abs(actual_delay - expected_delay) / expected_delay
        return min(1.0, deviation)

    except Exception:
        return 0.0
