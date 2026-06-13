"""Pure API hashing primitives and known API lists."""

from __future__ import annotations

import binascii

COMMON_WINDOWS_APIS = [
    "CreateFileA",
    "CreateFileW",
    "VirtualAlloc",
    "VirtualFree",
    "VirtualProtect",
    "ReadFile",
    "WriteFile",
    "LoadLibraryA",
    "LoadLibraryW",
    "GetProcAddress",
    "GetModuleHandleA",
    "GetModuleHandleW",
    "NtQueryInformationProcess",
    "NtReadVirtualMemory",
    "NtWriteVirtualMemory",
    "VirtualQuery",
    "CreateProcessA",
    "CreateProcessW",
    "CreateRemoteThread",
    "OpenProcess",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "TerminateProcess",
    "WaitForSingleObject",
    "CloseHandle",
    "HeapCreate",
    "HeapAlloc",
    "HeapFree",
    "GetProcessHeap",
    "RegOpenKeyExA",
    "RegOpenKeyExW",
    "RegQueryValueExA",
    "RegSetValueExA",
    "RegCloseKey",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "InternetOpenA",
    "InternetOpenW",
    "InternetConnectA",
    "InternetConnectW",
    "HttpOpenRequestA",
    "HttpOpenRequestW",
    "HttpSendRequestA",
    "HttpSendRequestW",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "SetFileAttributesA",
    "SetFileAttributesW",
    "DeleteFileA",
    "DeleteFileW",
    "MoveFileA",
    "MoveFileW",
    "CopyFileA",
    "CopyFileW",
    "CreateDirectoryA",
    "CreateDirectoryW",
    "RemoveDirectoryA",
    "RemoveDirectoryW",
    "FindFirstFileA",
    "FindFirstFileW",
    "FindNextFileA",
    "FindNextFileW",
    "FindClose",
    "GetSystemDirectoryA",
    "GetSystemDirectoryW",
    "GetWindowsDirectoryA",
    "GetWindowsDirectoryW",
    "GetCurrentDirectoryA",
    "GetCurrentDirectoryW",
    "SetCurrentDirectoryA",
    "SetCurrentDirectoryW",
    "GetFileSize",
    "SetFilePointer",
    "GetTickCount",
    "QueryPerformanceCounter",
    "Sleep",
    "ExitProcess",
    "ExitThread",
    "malloc",
    "free",
]

COMMON_LINUX_APIS = [
    "open",
    "read",
    "write",
    "close",
    "mmap",
    "munmap",
    "mprotect",
    "execve",
    "fork",
    "clone",
    "socket",
    "connect",
    "bind",
    "listen",
    "accept",
    "send",
    "recv",
    "dlopen",
    "dlsym",
    "dlclose",
    "malloc",
    "free",
    "realloc",
    "calloc",
    "pthread_create",
    "pthread_join",
    "pthread_mutex_lock",
    "pthread_mutex_unlock",
]


def ror32(value: int, count: int) -> int:
    """Rotate right a 32-bit value."""
    count = count % 32
    return ((value >> count) | (value << (32 - count))) & 0xFFFFFFFF


def rol32(value: int, count: int) -> int:
    """Rotate left a 32-bit value."""
    count = count % 32
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def hash_ror13(name: str) -> int:
    """Calculate the common ROR13 API hash."""
    h = 0
    for c in name.lower():
        h = ror32(h, 13)
        h = (h + ord(c)) & 0xFFFFFFFF
    return h


def hash_ror7(name: str) -> int:
    """Calculate the ROR7 API hash variant."""
    h = 0
    for c in name.lower():
        h = ror32(h, 7)
        h = (h + ord(c)) & 0xFFFFFFFF
    return h


def hash_djb2(name: str) -> int:
    """Calculate the DJB2 hash."""
    h = 5381
    for c in name:
        h = ((h << 5) + h + ord(c)) & 0xFFFFFFFF
    return h


def hash_fnv1a(name: str) -> int:
    """Calculate the FNV-1a hash."""
    h = 2166136261
    for c in name.lower():
        h ^= ord(c)
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def hash_crc32(name: str) -> int:
    """Calculate CRC32 hash of a string."""
    return binascii.crc32(name.lower().encode()) & 0xFFFFFFFF


HASH_ALGORITHMS = {
    "ror13": hash_ror13,
    "ror7": hash_ror7,
    "djb2": hash_djb2,
    "fnv1a": hash_fnv1a,
    "crc32": hash_crc32,
}


__all__ = [
    "COMMON_LINUX_APIS",
    "COMMON_WINDOWS_APIS",
    "HASH_ALGORITHMS",
    "hash_crc32",
    "hash_djb2",
    "hash_fnv1a",
    "hash_ror13",
    "hash_ror7",
    "rol32",
    "ror32",
]
