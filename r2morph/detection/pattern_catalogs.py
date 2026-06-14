"""Static anti-analysis pattern catalogs."""

from __future__ import annotations

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

ANTI_ANALYSIS_REGISTRY = [
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Oracle VM VirtualBox",
    "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
    "SOFTWARE\\VMware, Inc.\\VMware Tools",
    "SYSTEM\\ControlSet001\\Services\\Disk\\Enum",
    "HARDWARE\\DESCRIPTION\\System",
]

__all__ = [
    "ANTI_ANALYSIS_REGISTRY",
    "ANTI_DEBUG_APIS",
    "DEBUGGER_WINDOWS",
    "VM_ARTIFACTS",
]
