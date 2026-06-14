"""Helper builders for SARIF formatter run assembly."""

from __future__ import annotations

from r2morph.reporting.sarif_schema import (
    SARIFArtifact,
    SARIFInvocation,
    SARIFReport,
    SARIFResult,
    SARIFRun,
    SARIFTaxonomy,
    SARIFTool,
)

__all__ = ["build_report", "build_run"]


def build_run(
    tool: SARIFTool,
    results: list[SARIFResult],
    artifacts: list[SARIFArtifact] | None,
    invocations: list[SARIFInvocation] | None,
    taxonomies: list[SARIFTaxonomy] | None,
    source_root: str,
) -> SARIFRun:
    return SARIFRun(
        tool=tool,
        results=results,
        artifacts=artifacts if artifacts else None,
        invocations=invocations if invocations else None,
        taxonomies=taxonomies,
        original_uri_base_ids={"SRCROOT": source_root},
    )


def build_report(
    tool: SARIFTool,
    results: list[SARIFResult],
    artifacts: list[SARIFArtifact] | None,
    invocations: list[SARIFInvocation] | None,
    taxonomies: list[SARIFTaxonomy] | None,
    source_root: str,
) -> SARIFReport:
    return SARIFReport(
        runs=[
            build_run(
                tool,
                results,
                artifacts,
                invocations,
                taxonomies,
                source_root,
            )
        ]
    )
