"""Regression tests for host capability classification used by integration tests."""

from tests.utils.assertions import expect
from tests.utils.platform_binaries import supports_native_elf_x86_64


def test_native_elf_x86_64_requires_linux_amd64() -> None:
    expect(supports_native_elf_x86_64("Linux", "x86_64"))


def test_native_elf_x86_64_rejects_macos_arm64() -> None:
    expect(not supports_native_elf_x86_64("Darwin", "arm64"))
