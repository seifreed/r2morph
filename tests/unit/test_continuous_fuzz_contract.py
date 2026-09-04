"""Regression contract for the deterministic parser/rewrite fuzz campaign."""

from scripts.continuous_fuzz import run_campaign
from tests.utils.assertions import expect

_CASE_COUNT = 32
_SEED = 20260827
_SMALL_PAYLOAD = 7
_MAX_FAILURES = 128


def test_continuous_fuzz_campaign_is_reproducible_and_clean() -> None:
    first = run_campaign(cases=_CASE_COUNT, seed=_SEED, max_payload=512)
    second = run_campaign(cases=_CASE_COUNT, seed=_SEED, max_payload=512)

    expect(first == second and first["failure_count"] == 0)


def test_continuous_fuzz_campaign_reports_bounded_scope() -> None:
    report = run_campaign(cases=1, seed=_SEED, max_payload=_SMALL_PAYLOAD)

    expect(
        report["cases"] == 1
        and report["max_payload"] == _SMALL_PAYLOAD
        and report["failure_limit"] == _MAX_FAILURES
        and report["target_runs"] == {"binary_parsers": 1, "vm_dispatcher": 1, "relocations": 1, "binary_rewriter": 1}
    )
