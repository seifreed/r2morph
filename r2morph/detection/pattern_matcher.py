"""
Pattern matching for anti-analysis detection.

This module provides detection of anti-debugging, anti-VM,
and other anti-analysis techniques through string and pattern matching.
"""

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PatternMatchResult:
    """Result of pattern matching analysis."""

    anti_debug_detected: bool = False
    anti_debug_confidence: float = 0.0
    anti_debug_apis: list[str] = field(default_factory=list)
    anti_vm_detected: bool = False
    anti_vm_confidence: float = 0.0
    anti_vm_artifacts: list[str] = field(default_factory=list)
    string_encryption_detected: bool = False
    import_hiding_detected: bool = False


class PatternMatcher:
    """
    Pattern-based detection for anti-analysis techniques.

    Scans binaries for known anti-debugging APIs, VM detection
    artifacts, and other suspicious patterns.
    """

    # Anti-debug API patterns
    ANTI_DEBUG_APIS = [
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "OutputDebugString",
        "GetTickCount",
        "QueryPerformanceCounter",
        "NtSetInformationThread",
        "CloseHandle",
        "UnhandledExceptionFilter",
        "SetUnhandledExceptionFilter",
        "RaiseException",
        "NtQuerySystemInformation",
        "FindWindow",
        "EnumWindows",
        "GetForegroundWindow",
        "NtClose",
        "CreateToolhelp32Snapshot",
        "Process32First",
        "Process32Next",
    ]

    # VM/Sandbox detection artifacts
    VM_ARTIFACTS = [
        "vmware",
        "virtualbox",
        "vbox",
        "qemu",
        "xen",
        "sandboxie",
        "wine",
        "bochs",
        "parallels",
        "vboxservice",
        "vmtools",
        "vmmouse",
        "vmhgfs",
        "vboxguest",
        "sbiedll",
        "dbghelp",
        "api_log",
        "dir_watch",
        "pstorec",
        "vmguestnativeprocessor",
        "hyper-v",
        "virtual hd",
        "qemuvga",
    ]

    # Debugger window class names
    DEBUGGER_WINDOWS = [
        "OLLYDBG",
        "WinDbgFrameClass",
        "ID",  # IDA
        "Zeta Debugger",
        "Rock Debugger",
        "ObsidianGUI",
        "x64dbg",
        "x32dbg",
    ]

    # Anti-analysis registry keys
    ANTI_ANALYSIS_REGISTRY = [
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Oracle VM VirtualBox",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        "SYSTEM\\ControlSet001\\Services\\Disk\\Enum",
        "HARDWARE\\DESCRIPTION\\System",
    ]

    def __init__(self, binary: "Binary"):
        """
        Initialize pattern matcher.

        Args:
            binary: Binary to analyze
        """
        self.binary = binary

    def scan(self) -> PatternMatchResult:
        """
        Perform comprehensive pattern matching scan.

        Returns:
            PatternMatchResult with all findings
        """
        result = PatternMatchResult()

        # Detect anti-debug techniques
        anti_debug_result = self._detect_anti_debug()
        result.anti_debug_detected = anti_debug_result["detected"]
        result.anti_debug_confidence = anti_debug_result["confidence"]
        result.anti_debug_apis = anti_debug_result["apis_found"]

        # Detect anti-VM techniques
        anti_vm_result = self._detect_anti_vm()
        result.anti_vm_detected = anti_vm_result["detected"]
        result.anti_vm_confidence = anti_vm_result["confidence"]
        result.anti_vm_artifacts = anti_vm_result["artifacts_found"]

        # Detect string encryption
        result.string_encryption_detected = self._detect_string_encryption()

        # Detect import hiding
        result.import_hiding_detected = self._detect_import_hiding()

        return result

    def _detect_anti_debug(self) -> dict[str, Any]:
        """
        Detect anti-debugging techniques.

        Returns:
            Detection result with confidence and found APIs
        """
        result: dict[str, Any] = {
            "detected": False,
            "confidence": 0.0,
            "apis_found": [],
        }

        try:
            # Check for anti-debug API calls
            strings_output = self.binary.r2.cmd("izz")

            found_apis = []
            for api in self.ANTI_DEBUG_APIS:
                if api in strings_output:
                    found_apis.append(api)

            result["apis_found"] = found_apis
            result["confidence"] = min(1.0, len(found_apis) / len(self.ANTI_DEBUG_APIS))
            result["detected"] = result["confidence"] > 0.1  # At least one API found

            # Check for debugger window names
            for window in self.DEBUGGER_WINDOWS:
                if window in strings_output:
                    result["apis_found"].append(f"Window: {window}")
                    result["confidence"] = min(1.0, result["confidence"] + 0.1)
                    result["detected"] = True

        except Exception as e:
            logger.debug(f"Error detecting anti-debug: {e}")

        return result

    def _detect_anti_vm(self) -> dict[str, Any]:
        """
        Detect anti-VM techniques.

        Returns:
            Detection result with confidence and found artifacts
        """
        result: dict[str, Any] = {
            "detected": False,
            "confidence": 0.0,
            "artifacts_found": [],
        }

        try:
            strings_output = self.binary.r2.cmd("izz")

            found_artifacts = []
            for artifact in self.VM_ARTIFACTS:
                if artifact.lower() in strings_output.lower():
                    found_artifacts.append(artifact)

            result["artifacts_found"] = found_artifacts
            result["confidence"] = min(1.0, len(found_artifacts) / len(self.VM_ARTIFACTS) * 2)  # Scale up
            result["detected"] = result["confidence"] > 0.1

            # Check for registry key patterns
            for key in self.ANTI_ANALYSIS_REGISTRY:
                if key.lower() in strings_output.lower():
                    result["artifacts_found"].append(f"Registry: {key}")
                    result["confidence"] = min(1.0, result["confidence"] + 0.1)
                    result["detected"] = True

            # Check for hardware-based detection patterns
            hardware_patterns = [
                "CPUID",
                "rdtsc",
                "int 2d",
                "icebp",
                "popf",
                "pushf",
            ]

            for pattern in hardware_patterns:
                if pattern.lower() in strings_output.lower():
                    result["artifacts_found"].append(f"Hardware: {pattern}")
                    result["confidence"] = min(1.0, result["confidence"] + 0.05)

        except Exception as e:
            logger.debug(f"Error detecting anti-VM: {e}")

        return result

    def _detect_string_encryption(self) -> bool:
        """
        Detect potential string encryption.

        Returns:
            True if string encryption is likely
        """
        try:
            # Get strings from the binary
            strings_output = self.binary.r2.cmd("iz")

            if not strings_output:
                return False

            # Count readable vs non-readable strings
            lines = strings_output.strip().split("\n")
            total_strings = len(lines)

            if total_strings < 10:
                return False

            # Low string count relative to binary size might indicate encryption
            binary_size = self.binary.info.get("bin", {}).get("size", 0)
            if binary_size > 0:
                strings_per_kb = (total_strings * 1024) / binary_size
                if strings_per_kb < 0.5:  # Very few strings
                    return True

            return False

        except Exception as e:
            logger.debug(f"Error detecting string encryption: {e}")
            return False

    def _detect_import_hiding(self) -> bool:
        """
        Detect potential import hiding/obfuscation.

        Returns:
            True if import hiding is likely
        """
        try:
            # Get imports
            imports = self.binary.r2.cmd("ii")

            if not imports:
                return True  # No imports at all is suspicious

            # Check for dynamic loading patterns
            dynamic_load_apis = [
                "GetProcAddress",
                "LoadLibrary",
                "LoadLibraryA",
                "LoadLibraryW",
                "LdrLoadDll",
                "LdrGetProcedureAddress",
            ]

            has_dynamic_loading = any(api in imports for api in dynamic_load_apis)

            # Few imports + dynamic loading = likely import hiding
            import_count = len(imports.strip().split("\n"))
            if import_count < 20 and has_dynamic_loading:
                return True

            return False

        except Exception as e:
            logger.debug(f"Error detecting import hiding: {e}")
            return False

    def find_patterns(self, patterns: list[bytes]) -> dict[bytes, list[int]]:
        """
        Search for arbitrary byte patterns in the binary.

        Args:
            patterns: List of byte patterns to search for

        Returns:
            Dictionary mapping patterns to list of addresses found
        """
        results: dict[bytes, list[int]] = {}

        try:
            for pattern in patterns:
                cmd = f"/x {pattern.hex()}"
                matches = self.binary.r2.cmd(cmd)

                if matches and matches.strip():
                    addresses = []
                    for line in matches.strip().split("\n"):
                        # Parse address from radare2 output
                        parts = line.split()
                        if parts:
                            try:
                                addr = int(parts[0], 16)
                                addresses.append(addr)
                            except (ValueError, IndexError):
                                continue

                    if addresses:
                        results[pattern] = addresses

        except Exception as e:
            logger.error(f"Pattern search failed: {e}")

        return results

    def search_strings(self, search_terms: list[str], case_sensitive: bool = False) -> dict[str, bool]:
        """
        Search for specific strings in the binary.

        Args:
            search_terms: List of strings to search for
            case_sensitive: Whether search should be case-sensitive

        Returns:
            Dictionary mapping search terms to whether they were found
        """
        results: dict[str, bool] = {}

        try:
            strings_output = self.binary.r2.cmd("izz")

            if not case_sensitive:
                strings_output = strings_output.lower()

            for term in search_terms:
                search_term = term if case_sensitive else term.lower()
                results[term] = search_term in strings_output

        except Exception as e:
            logger.error(f"String search failed: {e}")
            # Mark all as not found on error
            for term in search_terms:
                results[term] = False

        return results
