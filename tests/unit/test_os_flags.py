"""
Unit tests for os_flags module.
"""

import importlib

from r2morph.analysis.os_flags import (
    LINFLAGS,
    WINFLAGS,
    OSFlags,
    get_flags,
)
from tests.utils.assertions import expect

_EXPECTED_0_255 = 0xFF
_EXPECTED_0_4294967295 = 0xFFFFFFFF
_EXPECTED_0_65535 = 0xFFFF
_EXPECTED_F_255 = 0xFF
_EXPECTED_F_4294967295 = 0xFFFFFFFF
_EXPECTED_F_65535 = 0xFFFF


class TestOSFlagsInit:
    def test_init_linux(self):
        flags = OSFlags("linux")
        expect(flags.os_type == "linux")
        expect(not (len(flags.flags) <= 0))

    def test_init_windows(self):
        flags = OSFlags("windows")
        expect(flags.os_type == "windows")
        expect(not (len(flags.flags) <= 0))

    def test_default_is_linux(self):
        flags = OSFlags()
        expect(flags.os_type == "linux")


class TestOSFlagsMethods:
    def test_get_random_flag(self):
        flags = OSFlags("linux")
        flag = flags.get_random_flag()
        expect(isinstance(flag, int))
        expect(not (flag not in flags.flags))

    def test_get_flags_count(self):
        flags = OSFlags("linux")
        count = flags.get_flags_count()
        expect(count == len(flags.flags))
        expect(not (count <= 0))

    def test_get_flag_by_index(self):
        flags = OSFlags("linux")
        flag = flags.get_flag_by_index(0)
        expect(flag == flags.flags[0])

    def test_get_flag_by_index_wrap(self):
        flags = OSFlags("linux")
        flag0 = flags.get_flag_by_index(0)
        flag_mod = flags.get_flag_by_index(len(flags.flags))
        expect(flag0 == flag_mod)

    def test_get_flags_for_size_32(self):
        flags = OSFlags("linux")
        flags_32 = flags.get_flags_for_size(32)
        expect(all(f <= _EXPECTED_F_4294967295 for f in flags_32))

    def test_get_flags_for_size_16(self):
        flags = OSFlags("linux")
        flags_16 = flags.get_flags_for_size(16)
        expect(all(f <= _EXPECTED_F_65535 for f in flags_16))

    def test_get_flags_for_size_8(self):
        flags = OSFlags("linux")
        flags_8 = flags.get_flags_for_size(8)
        expect(all(f <= _EXPECTED_F_255 for f in flags_8))

    def test_get_safe_imm32(self):
        flags = OSFlags("linux")
        imm = flags.get_safe_imm32()
        expect(isinstance(imm, int))
        expect(0 <= imm <= _EXPECTED_0_4294967295)

    def test_get_safe_imm16(self):
        flags = OSFlags("linux")
        imm = flags.get_safe_imm16()
        expect(isinstance(imm, int))
        expect(0 <= imm <= _EXPECTED_0_65535)

    def test_get_safe_imm8(self):
        flags = OSFlags("linux")
        imm = flags.get_safe_imm8()
        expect(isinstance(imm, int))
        expect(0 <= imm <= _EXPECTED_0_255)


class TestGlobalFlags:
    def test_winflags_not_empty(self):
        expect(not (len(WINFLAGS) <= 0))
        expect(all(isinstance(f, int) for f in WINFLAGS))

    def test_linflags_not_empty(self):
        expect(not (len(LINFLAGS) <= 0))
        expect(all(isinstance(f, int) for f in LINFLAGS))

    def test_windows_flags_global(self):
        os_flags = importlib.import_module("r2morph.analysis").os_flags

        expect(os_flags.WINDOWS_FLAGS.os_type == "windows")

    def test_linux_flags_global(self):
        os_flags = importlib.import_module("r2morph.analysis").os_flags

        expect(os_flags.LINUX_FLAGS.os_type == "linux")


class TestGetFlags:
    def test_get_flags_linux(self):
        flags = get_flags("linux")
        expect(flags.os_type == "linux")

    def test_get_flags_windows(self):
        flags = get_flags("windows")
        expect(flags.os_type == "windows")

    def test_get_flags_default(self):
        flags = get_flags()
        expect(flags.os_type == "linux")


class TestFlagConsistency:
    def test_linux_windows_different_instances(self):
        flags1 = OSFlags("linux")
        flags2 = OSFlags("linux")
        expect(flags1.flags == flags2.flags)

    def test_flag_values_valid(self):
        flags = OSFlags("linux")
        for flag in flags.flags:
            expect(isinstance(flag, int))
            expect(not (flag < 0))

    def test_windows_flag_values_valid(self):
        flags = OSFlags("windows")
        for flag in flags.flags:
            expect(isinstance(flag, int))
            expect(not (flag < 0))
