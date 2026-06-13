"""Default benchmark sample catalog."""

from __future__ import annotations

from r2morph.validation.benchmark_types import TestSeverity

DEFAULT_TEST_SAMPLES: list[dict[str, object]] = [
    {
        "file_path": "dataset/vmprotect_sample.exe",
        "sample_hash": "abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234",
        "expected_packer": "VMProtect",
        "expected_vm_protection": True,
        "expected_anti_analysis": True,
        "expected_cfo": True,
        "expected_mba": True,
        "severity": TestSeverity.CRITICAL,
        "description": "VMProtect 3.x protected binary with full virtualization",
        "source": "research_collection",
    },
    {
        "file_path": "dataset/themida_sample.exe",
        "sample_hash": "efgh5678901234efgh5678901234efgh5678901234efgh5678901234efgh5678",
        "expected_packer": "Themida",
        "expected_vm_protection": True,
        "expected_anti_analysis": True,
        "expected_cfo": True,
        "expected_mba": False,
        "severity": TestSeverity.CRITICAL,
        "description": "Themida protected binary with anti-debugging",
        "source": "malware_zoo",
    },
    {
        "file_path": "dataset/upx_sample.exe",
        "sample_hash": "ijkl9012345678ijkl9012345678ijkl9012345678ijkl9012345678ijkl9012",
        "expected_packer": "UPX",
        "expected_vm_protection": False,
        "expected_anti_analysis": False,
        "expected_cfo": False,
        "expected_mba": False,
        "severity": TestSeverity.LOW,
        "description": "Simple UPX compressed binary",
        "source": "test_samples",
    },
    {
        "file_path": "dataset/custom_vm_sample.exe",
        "sample_hash": "mnop3456789012mnop3456789012mnop3456789012mnop3456789012mnop3456",
        "expected_packer": "Custom",
        "expected_vm_protection": True,
        "expected_anti_analysis": True,
        "expected_cfo": True,
        "expected_mba": True,
        "severity": TestSeverity.HIGH,
        "description": "Custom virtualization engine with MBA obfuscation",
        "source": "academic_research",
    },
    {
        "file_path": "dataset/clean_sample.exe",
        "sample_hash": "qrst7890123456qrst7890123456qrst7890123456qrst7890123456qrst7890",
        "expected_packer": None,
        "expected_vm_protection": False,
        "expected_anti_analysis": False,
        "expected_cfo": False,
        "expected_mba": False,
        "severity": TestSeverity.LOW,
        "description": "Clean unobfuscated binary",
        "source": "control_group",
    },
]


__all__ = ["DEFAULT_TEST_SAMPLES"]
