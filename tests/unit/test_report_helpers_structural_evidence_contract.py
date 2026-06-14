from r2morph.core.report_helpers_structural_evidence import _summarize_structural_evidence


def test_summarize_structural_evidence_compacts_regions() -> None:
    digest = _summarize_structural_evidence(
        [
            {
                "address_range": [0x401010, 0x401011],
                "validators": ["structural", "patch_integrity"],
                "messages": ["invalid mutation", "patched bytes differ"],
                "severities": ["error", "error"],
            },
            {
                "address_range": [0x401020, 0x401021],
                "validators": ["structural"],
                "messages": ["stack balanced"],
                "severities": ["info"],
            },
        ]
    )

    assert digest == {
        "region_count": 2,
        "validators": ["patch_integrity", "structural"],
        "severity_counts": {"error": 2, "info": 1},
        "sample_messages": [
            "invalid mutation",
            "patched bytes differ",
            "stack balanced",
        ],
    }
