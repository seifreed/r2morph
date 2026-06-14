from r2morph.reporting.sarif_schema_core import (
    SARIFArtifactLocation,
    SARIFLevel,
    SARIFLocation,
    SARIFMessage,
    SARIFPhysicalLocation,
    SARIFRegion,
)


def test_sarif_schema_core_round_trip() -> None:
    message = SARIFMessage(text="hello", markdown="**hello**")
    location = SARIFLocation(
        physical_location=SARIFPhysicalLocation(
            artifact_location=SARIFArtifactLocation(uri="file:///bin"),
            region=SARIFRegion(start_line=1, start_column=2, snippet=None),
        ),
        message=message,
    )

    assert SARIFLevel.WARNING.value == "warning"
    assert message.to_dict()["markdown"] == "**hello**"
    assert location.to_dict()["physicalLocation"]["artifactLocation"]["uri"] == "file:///bin"
