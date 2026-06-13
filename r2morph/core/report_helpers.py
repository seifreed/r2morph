"""Compatibility facade for report assembly helpers.

This module preserves the legacy import surface while the real logic is
split across evidence, symbolic, and validation helper modules.
"""

from r2morph.core.report_helpers_evidence import (
    _build_discarded_mutation_priority as _build_discarded_mutation_priority,
)
from r2morph.core.report_helpers_evidence import (
    _build_evidence_summary_for_pass as _build_evidence_summary_for_pass,
)
from r2morph.core.report_helpers_evidence import (
    _build_observable_mismatch_map as _build_observable_mismatch_map,
)
from r2morph.core.report_helpers_evidence import (
    _build_observable_mismatch_priority as _build_observable_mismatch_priority,
)
from r2morph.core.report_helpers_evidence import (
    _build_pass_capability_summary_map as _build_pass_capability_summary_map,
)
from r2morph.core.report_helpers_evidence import (
    _build_pass_region_evidence_map as _build_pass_region_evidence_map,
)
from r2morph.core.report_helpers_evidence import (
    _build_pass_triage_map as _build_pass_triage_map,
)
from r2morph.core.report_helpers_evidence import (
    _summarize_diff_digest as _summarize_diff_digest,
)
from r2morph.core.report_helpers_evidence import (
    _summarize_discarded_mutations as _summarize_discarded_mutations,
)
from r2morph.core.report_helpers_evidence import (
    _summarize_normalized_pass_results as _summarize_normalized_pass_results,
)
from r2morph.core.report_helpers_evidence import (
    _summarize_observable_mismatches_by_pass as _summarize_observable_mismatches_by_pass,
)
from r2morph.core.report_helpers_evidence import (
    _summarize_pass_capability_rows as _summarize_pass_capability_rows,
)
from r2morph.core.report_helpers_evidence import (
    _summarize_pass_coverage_buckets as _summarize_pass_coverage_buckets,
)
from r2morph.core.report_helpers_evidence import (
    _summarize_pass_evidence as _summarize_pass_evidence,
)
from r2morph.core.report_helpers_evidence import (
    _summarize_pass_evidence_compact as _summarize_pass_evidence_compact,
)
from r2morph.core.report_helpers_evidence import (
    _summarize_pass_risk_buckets as _summarize_pass_risk_buckets,
)
from r2morph.core.report_helpers_evidence import (
    _summarize_pass_timings as _summarize_pass_timings,
)
from r2morph.core.report_helpers_evidence import (
    _summarize_pass_triage_rows as _summarize_pass_triage_rows,
)
from r2morph.core.report_helpers_evidence import (
    _summarize_structural_evidence as _summarize_structural_evidence,
)
from r2morph.core.report_helpers_symbolic import (
    _build_symbolic_summary_for_pass as _build_symbolic_summary_for_pass,
)
from r2morph.core.report_helpers_symbolic import (
    _summarize_symbolic_coverage_by_pass as _summarize_symbolic_coverage_by_pass,
)
from r2morph.core.report_helpers_symbolic import (
    _summarize_symbolic_issue_passes as _summarize_symbolic_issue_passes,
)
from r2morph.core.report_helpers_symbolic import (
    _summarize_symbolic_overview as _summarize_symbolic_overview,
)
from r2morph.core.report_helpers_symbolic import (
    _summarize_symbolic_severity_by_pass as _summarize_symbolic_severity_by_pass,
)
from r2morph.core.report_helpers_symbolic import (
    _summarize_symbolic_statuses as _summarize_symbolic_statuses,
)
from r2morph.core.report_helpers_validation import (
    _build_pass_validation_context as _build_pass_validation_context,
)
from r2morph.core.report_helpers_validation import (
    _build_validation_role_map as _build_validation_role_map,
)
from r2morph.core.report_helpers_validation import (
    _enrich_validation_policy as _enrich_validation_policy,
)
from r2morph.core.report_helpers_validation import (
    _summarize_degradation_roles as _summarize_degradation_roles,
)
from r2morph.core.report_helpers_validation import (
    _summarize_validation_adjustment_rows as _summarize_validation_adjustment_rows,
)
from r2morph.core.report_helpers_validation import (
    _summarize_validation_adjustments as _summarize_validation_adjustments,
)
from r2morph.core.report_helpers_validation import (
    _summarize_validation_role_rows as _summarize_validation_role_rows,
)

REPORT_SCHEMA_VERSION = 1
