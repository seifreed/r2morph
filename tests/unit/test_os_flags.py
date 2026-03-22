"""
Unit tests for os_flags module.
"""

from r2morph.analysis.os_flags import (
    WINFLAGS,
    LINFLAGS,
    OSFlags,
    get_flags,
)


class TestOSFlagsInit:
    def test_init_linux(self):
        flags = OSFlags("linux")
        assert flags.os_type == "linux"
        assert len(flags.flags) > 0

    def test_init_windows(self):
        flags = OSFlags("windows")
        assert flags.os_type == "windows"
        assert len(flags.flags) > 0

    def test_default_is_linux(self):
        flags = OSFlags()
        assert flags.os_type == "linux"


class TestOSFlagsMethods:
    def test_get_random_flag(self):
        flags = OSFlags("linux")
        flag = flags.get_random_flag()
        assert isinstance(flag, int)
        assert flag in flags.flags

    def test_get_flags_count(self):
        flags = OSFlags("linux")
        count = flags.get_flags_count()
        assert count == len(flags.flags)
        assert count > 0

    def test_get_flag_by_index(self):
        flags = OSFlags("linux")
        flag = flags.get_flag_by_index(0)
        assert flag == flags.flags[0]

    def test_get_flag_by_index_wrap(self):
        flags = OSFlags("linux")
        flag0 = flags.get_flag_by_index(0)
        flag_mod = flags.get_flag_by_index(len(flags.flags))
        assert flag0 == flag_mod

    def test_get_flags_for_size_32(self):
        flags = OSFlags("linux")
        flags_32 = flags.get_flags_for_size(32)
        assert all(f <= 0xFFFFFFFF for f in flags_32)

    def test_get_flags_for_size_16(self):
        flags = OSFlags("linux")
        flags_16 = flags.get_flags_for_size(16)
        assert all(f <= 0xFFFF for f in flags_16)

    def test_get_flags_for_size_8(self):
        flags = OSFlags("linux")
        flags_8 = flags.get_flags_for_size(8)
        assert all(f <= 0xFF for f in flags_8)

    def test_get_safe_imm32(self):
        flags = OSFlags("linux")
        imm = flags.get_safe_imm32()
        assert isinstance(imm, int)
        assert 0 <= imm <= 0xFFFFFFFF

    def test_get_safe_imm16(self):
        flags = OSFlags("linux")
        imm = flags.get_safe_imm16()
        assert isinstance(imm, int)
        assert 0 <= imm <= 0xFFFF

    def test_get_safe_imm8(self):
        flags = OSFlags("linux")
        imm = flags.get_safe_imm8()
        assert isinstance(imm, int)
        assert 0 <= imm <= 0xFF


class TestGlobalFlags:
    def test_winflags_not_empty(self):
        assert len(WINFLAGS) > 0
        assert all(isinstance(f, int) for f in WINFLAGS)

    def test_linflags_not_empty(self):
        assert len(LINFLAGS) > 0
        assert all(isinstance(f, int) for f in LINFLAGS)

    def test_windows_flags_global(self):
        from r2morph.analysis import os_flags

        assert os_flags.WINDOWS_FLAGS.os_type == "windows"

    def test_linux_flags_global(self):
        from r2morph.analysis import os_flags

        assert os_flags.LINUX_FLAGS.os_type == "linux"


class TestGetFlags:
    def test_get_flags_linux(self):
        flags = get_flags("linux")
        assert flags.os_type == "linux"

    def test_get_flags_windows(self):
        flags = get_flags("windows")
        assert flags.os_type == "windows"

    def test_get_flags_default(self):
        flags = get_flags()
        assert flags.os_type == "linux"


class TestFlagConsistency:
    def test_linux_windows_different_instances(self):
        flags1 = OSFlags("linux")
        flags2 = OSFlags("linux")
        assert flags1.flags == flags2.flags

    def test_flag_values_valid(self):
        flags = OSFlags("linux")
        for flag in flags.flags:
            assert isinstance(flag, int)
            assert flag >= 0

    def test_windows_flag_values_valid(self):
        flags = OSFlags("windows")
        for flag in flags.flags:
            assert isinstance(flag, int)
            assert flag >= 0
