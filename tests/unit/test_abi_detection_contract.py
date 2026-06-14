from __future__ import annotations

from r2morph.analysis.abi_detection import detect_abi
from r2morph.analysis.abi_models import ABIType


class MockBinary:
    def __init__(self, arch_info):
        self._arch_info = arch_info

    def get_arch_info(self):
        return self._arch_info


def test_detect_abi_routes_common_arches() -> None:
    assert detect_abi(MockBinary({"arch": "x86", "bits": 64, "platform": "linux"})).abi_type == ABIType.X86_64_SYSTEM_V
    assert detect_abi(MockBinary({"arch": "x86", "bits": 64, "platform": "windows"})).abi_type == ABIType.X86_64_WINDOWS
    assert detect_abi(MockBinary({"arch": "aarch64", "bits": 64, "platform": "linux"})).abi_type == ABIType.ARM64_AAPCS
    assert detect_abi(MockBinary({"arch": "arm", "bits": 32, "platform": "linux"})).abi_type == ABIType.ARM32_AAPCS
