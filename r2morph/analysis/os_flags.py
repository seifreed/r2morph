"""
OS-specific constants for semantic-preserving mutations.

Provides Windows and Linux flags/constants that can be used
in junk code generation while preserving program semantics.
"""

from typing import Final


WINFLAGS: Final[list[int]] = [
    0x00000001,
    0x00000002,
    0x00000004,
    0x00000008,
    0x00000010,
    0x00000020,
    0x00000040,
    0x00000080,
    0x00000100,
    0x00000200,
    0x00000400,
    0x00000800,
    0x00001000,
    0x00002000,
    0x00004000,
    0x00008000,
    0x00010000,
    0x00020000,
    0x00040000,
    0x00080000,
    0x00100000,
    0x00200000,
    0x00400000,
    0x00800000,
    0x01000000,
    0x02000000,
    0x04000000,
    0x08000000,
    0x10000000,
    0x20000000,
    0x40000000,
    0x80000000,
    0xFFFFFFFF,
    0xFFFFFFFE,
    0x7FFFFFFF,
    0x3FFFFFFF,
    0x1FFFFFFF,
    0x0FFFFFFF,
    0x07FFFFFF,
    0x03FFFFFF,
    0x01FFFFFF,
    0x00FFFFFF,
    0x007FFFFF,
    0x003FFFFF,
    0x001FFFFF,
    0x000FFFFF,
    0x0007FFFF,
    0x0003FFFF,
    0x0001FFFF,
    0x0000FFFF,
    0x00007FFF,
    0x00003FFF,
    0x00001FFF,
    0x00000FFF,
    0x000007FF,
    0x000003FF,
    0x000001FF,
    0x000000FF,
    0x0000007F,
    0x0000003F,
    0x0000001F,
    0x0000000F,
    0x00000007,
    0x00000003,
    0x00000001,
]

LINFLAGS: Final[list[int]] = [
    0x00000001,
    0x00000002,
    0x00000004,
    0x00000008,
    0x00000010,
    0x00000020,
    0x00000040,
    0x00000080,
    0x00000100,
    0x00000200,
    0x00000400,
    0x00000800,
    0x00001000,
    0x00002000,
    0x00004000,
    0x00008000,
    0x00010000,
    0x00020000,
    0x00040000,
    0x00080000,
    0x00100000,
    0x00200000,
    0x00400000,
    0x00800000,
    0x01000000,
    0x02000000,
    0x04000000,
    0x08000000,
    0x10000000,
    0x20000000,
    0x40000000,
    0x80000000,
    0xFFFFFFFF,
    0xFFFFFFFE,
    0x7FFFFFFF,
    0x3FFFFFFF,
    0x1FFFFFFF,
    0x0FFFFFFF,
    0x07FFFFFF,
    0x03FFFFFF,
    0x01FFFFFF,
    0x00FFFFFF,
    0x007FFFFF,
    0x003FFFFF,
    0x001FFFFF,
    0x000FFFFF,
    0x0007FFFF,
    0x0003FFFF,
    0x0001FFFF,
    0x0000FFFF,
    0x00007FFF,
    0x00003FFF,
    0x00001FFF,
    0x00000FFF,
    0x000007FF,
    0x000003FF,
    0x000001FF,
    0x000000FF,
    0x0000007F,
    0x0000003F,
    0x0000001F,
    0x0000000F,
    0x00000007,
    0x00000003,
    0x00000001,
]


class OSFlags:
    def __init__(self, os_type: str = "linux"):
        if os_type == "windows":
            self.flags = WINFLAGS.copy()
        else:
            self.flags = LINFLAGS.copy()
        self._os_type = os_type

    @property
    def os_type(self) -> str:
        return self._os_type

    def get_random_flag(self) -> int:
        import random

        return random.choice(self.flags)

    def get_flags_count(self) -> int:
        return len(self.flags)

    def get_flag_by_index(self, index: int) -> int:
        return self.flags[index % len(self.flags)]

    def get_flags_for_size(self, size_bits: int = 32) -> list[int]:
        max_val = (1 << size_bits) - 1
        return [f for f in self.flags if f <= max_val]

    def get_safe_imm32(self) -> int:
        import random

        return random.choice(self.flags)

    def get_safe_imm16(self) -> int:
        import random

        flags_16 = [f for f in self.flags if f <= 0xFFFF]
        return random.choice(flags_16) if flags_16 else 0

    def get_safe_imm8(self) -> int:
        import random

        flags_8 = [f for f in self.flags if f <= 0xFF]
        return random.choice(flags_8) if flags_8 else 0


WINDOWS_FLAGS = OSFlags("windows")
LINUX_FLAGS = OSFlags("linux")


def get_flags(os_type: str = "linux") -> OSFlags:
    if os_type == "windows":
        return WINDOWS_FLAGS
    return LINUX_FLAGS
