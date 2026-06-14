from datetime import datetime, timezone

from r2morph.reporting.sarif_catalogs import MITRE_ATTACK
from r2morph.reporting.sarif_formatter_builders import (
    ReportData,
    build_artifacts,
    build_driver,
    build_invocations,
    build_mitre_taxonomy,
    build_rules,
)


def test_sarif_formatter_builders_round_trip() -> None:
    rules = build_rules(
        [
            {
                "id": "RM001",
                "name": "nop-insertion",
                "short_description": "NOP instruction insertion",
                "full_description": "Inserts benign NOP instructions at safe locations",
                "default_level": "note",
            }
        ]
    )
    driver = build_driver("1.2.3", "https://example.invalid", rules)
    taxonomy = build_mitre_taxonomy(MITRE_ATTACK)
    report_data = ReportData(
        binary_path="input.exe",
        output_path="output.exe",
        start_time=datetime(2026, 6, 14, 12, 0, tzinfo=timezone.utc),
        end_time=datetime(2026, 6, 14, 12, 5, tzinfo=timezone.utc),
        exit_code=7,
    )

    artifacts = build_artifacts(report_data)
    invocations = build_invocations(report_data)

    assert driver.driver.version == "1.2.3"
    assert driver.driver.information_uri == "https://example.invalid"
    assert rules[0].default_level.value == "note"
    assert taxonomy.name == "MITRE ATT&CK"
    assert len(taxonomy.taxa) == len({entry["id"] for entry in MITRE_ATTACK.values()})
    assert [artifact.location.uri for artifact in artifacts] == ["input.exe", "output.exe"]
    assert invocations[0].exit_code == 7
    assert invocations[0].start_time_utc == "2026-06-14T12:00:00+00:00"
    assert invocations[0].end_time_utc == "2026-06-14T12:05:00+00:00"
