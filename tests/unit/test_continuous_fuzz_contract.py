"""Regression contract for the deterministic parser/rewrite fuzz campaign."""

from logging import getLogger
from pathlib import Path

from scripts.continuous_fuzz import run_campaign
from tests.utils.assertions import expect

_CASE_COUNT = 32
_SEED = 20260827
_SMALL_PAYLOAD = 7
_MAX_FAILURES = 128
_ROOT = Path(__file__).resolve().parents[2]


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
        and report["target_runs"]
        == {
            "assembling": 1,
            "binary_parsers": 1,
            "elf_header_parser": 1,
            "pe_header_parser": 1,
            "macho_load_commands": 1,
            "vm_dispatcher": 1,
            "vm_bytecode": 1,
            "relocations": 1,
            "binary_rewriter": 1,
        }
    )


def test_continuous_fuzz_campaign_counts_expected_parser_diagnostics() -> None:
    parser_logger = getLogger("r2morph.platform.macho_handler")
    original_handlers = tuple(parser_logger.handlers)
    original_propagate = parser_logger.propagate
    report = run_campaign(cases=_CASE_COUNT, seed=_SEED, max_payload=512)

    expect(
        tuple(parser_logger.handlers) == original_handlers
        and parser_logger.propagate is original_propagate
        and all(
            key.startswith(("binary_parsers.", "macho_load_commands."))
            and key.rsplit(".", 1)[1] in {"warning", "error"}
            and count > 0
            for key, count in report["parser_diagnostic_counts"].items()
        )
    )


def test_continuous_fuzz_workflow_runs_on_all_three_platforms() -> None:
    workflow = (_ROOT / ".github" / "workflows" / "fuzz.yml").read_text(encoding="utf-8")

    expect(
        "os: [ubuntu-latest, macos-15, windows-latest]" in workflow
        and "runs-on: ${{ matrix.os }}" in workflow
        and "fail-fast: false" in workflow
        and "shell: bash" in workflow
        and 'wheel_root="$(cygpath -u "$RUNNER_TEMP")/r2morph-fuzz-wheel-check"' in workflow
        and "name: continuous-fuzz-report-${{ matrix.os }}" in workflow
    )
