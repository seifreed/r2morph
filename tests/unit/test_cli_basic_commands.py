from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from r2morph import cli
from tests.utils.assertions import expect
from tests.utils.field_names import MUTATION_NAME_KEY, ONLY_FAILED_MUTATION_KEY
from tests.utils.process import run_command

_EXPECTED_PAYLOAD_FILTERED_SUMMARY_GATE_FAILURE_COMPACT_2 = 2
_EXPECTED_PAYLOAD_FILTERED_SUMMARY_MISMATCH_COMPACT_BY__2 = 2
_EXPECTED_PAYLOAD_FILTERED_SUMMARY_MISMATCH_COUNTS_BY_P_2 = 2
_EXPECTED_PAYLOAD_FILTERED_SUMMARY_MISMATCH_COUNTS_BY_P_2_2 = 2
_EXPECTED_PAYLOAD_FILTERED_SUMMARY_PASS_SYMBOLIC_SUMMAR_2 = 2
_EXPECTED_PAYLOAD_FILTERED_SUMMARY_SYMBOLIC_COVERAGE_BY_2 = 2
_EXPECTED_PRIORITY_0_FAILURE_COUNT_2 = 2


typer_testing = pytest.importorskip("typer.testing")
CliRunner = typer_testing.CliRunner


def test_cli_simple_mode(tmp_path: Path) -> None:
    source = Path("fixtures/dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    input_path = tmp_path / "input.bin"
    output_path = tmp_path / "output.bin"
    input_path.write_bytes(source.read_bytes())

    result = run_command(
        [sys.executable, "-m", "r2morph.cli", str(input_path), str(output_path)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    expect(result.returncode == 0)
    expect(output_path.exists())


def test_cli_no_input_shows_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli.app, [])
    expect(result.exit_code == 0)
    expect(not ("No input file provided" not in result.output))


def test_cli_version_function() -> None:
    result = cli.version()
    expect(not (result is not None))


def test_cli_warns_for_experimental_mutations(tmp_path: Path) -> None:
    source = Path("fixtures/dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    runner = CliRunner()
    output = tmp_path / "out.bin"
    report = tmp_path / "out.report.json"
    result = runner.invoke(
        cli.app,
        [
            "mutate",
            str(source),
            "-o",
            str(output),
            "--report",
            str(report),
            "-m",
            "block",
        ],
    )

    expect(result.exit_code == 0)
    expect(not ("Experimental mutations selected" not in result.output))
    expect(not ("best-effort" not in result.output))


def test_cli_warns_for_symbolic_validation_mode(
    tmp_path: Path,
) -> None:
    source = Path("fixtures/dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    runner = CliRunner()
    output = tmp_path / "out.bin"
    report = tmp_path / "out.report.json"
    result = runner.invoke(
        cli.app,
        [
            "mutate",
            str(source),
            "-o",
            str(output),
            "--report",
            str(report),
            "--validation-mode",
            "symbolic",
            "-m",
            "nop",
        ],
    )

    expect(result.exit_code == 0)
    expect(not ("Experimental validation mode selected" not in result.output))
    expect(not ("semantic equivalence" not in result.output))


def test_cli_report_prints_symbolic_mutation_summary(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "mutations": [
                    {
                        "pass_name": "InstructionSubstitution",
                        "metadata": {
                            "symbolic_requested": True,
                            "symbolic_status": "bounded-step-observables-match",
                            "symbolic_observable_check_performed": True,
                            "symbolic_observable_equivalent": True,
                        },
                    },
                    {
                        "pass_name": "InstructionSubstitution",
                        "start_address": 0x401010,
                        "end_address": 0x401011,
                        "metadata": {
                            "symbolic_requested": True,
                            "symbolic_status": "bounded-step-observable-mismatch",
                            "symbolic_observable_check_performed": True,
                            "symbolic_observable_equivalent": False,
                            "symbolic_observable_mismatches": ["eax", "eflags"],
                        },
                    },
                    {
                        "pass_name": "NopInsertion",
                        "metadata": {
                            "symbolic_requested": True,
                            "symbolic_status": "bounded-step-passed",
                        },
                    },
                    {
                        "pass_name": "BlockReordering",
                        "metadata": {
                            "symbolic_requested": True,
                            "symbolic_status": "unsupported-pass",
                        },
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli.app, ["report", str(report_path)])

    expect(result.exit_code == 0)
    expect(not ("Symbolic Mutation Summary" not in result.output))
    expect(not ("1 observable match" not in result.output))
    expect(not ("1 observable mismatch" not in result.output))
    expect(not ("bounded-step only" not in result.output))
    expect(not ("without symbolic coverage" not in result.output))
    expect(not ("InstructionSubstitution" not in result.output))
    expect(not ("1 match, 1 mismatch" not in result.output))
    expect(not ("NopInsertion" not in result.output))
    expect(not ("1 bounded-only" not in result.output))
    expect(not ("BlockReordering" not in result.output))
    expect(not ("1 without coverage" not in result.output))
    expect(not ("Passes With Symbolic Issues" not in result.output))
    expect(not ("severity=mismatch" not in result.output))
    expect(not ("severity=without-coverage" not in result.output))
    expect(not ("Symbolic Mismatches" not in result.output))
    expect(not ("0x401010-0x401011" not in result.output))
    expect(not ("eax, eflags" not in result.output))


def test_cli_report_surfaces_degraded_validation_mode(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "requested_validation_mode": "symbolic",
                    "validation_mode": "runtime",
                    "degradation_roles": {
                        "degradation-trigger": 1,
                        "executed-under-degraded-mode": 2,
                    },
                },
                "validation_policy": {
                    "policy": "degrade-runtime",
                    "reason": "limited-symbolic-support",
                    "limited_passes": [
                        {
                            "mutation": "register",
                            "pass_name": "RegisterSubstitution",
                            "confidence": "limited",
                        }
                    ],
                },
                "passes": {
                    "RegisterSubstitution": {
                        "validation_context": {
                            "requested_validation_mode": "symbolic",
                            "effective_validation_mode": "runtime",
                            "degraded_execution": True,
                            "degradation_triggered_by_pass": True,
                        }
                    }
                },
                "mutations": [
                    {
                        "pass_name": "RegisterSubstitution",
                        "metadata": {
                            "symbolic_requested": True,
                            "symbolic_status": "real-binary-observable-mismatch",
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli.app, ["report", str(report_path), "--summary-only"])

    expect(result.exit_code == 0)
    expect(not ("Validation Mode Adjustment" not in result.output))
    expect(not ("requested=symbolic, effective=runtime" not in result.output))
    expect(not ("policy=degrade-runtime, reason=limited-symbolic-support" not in result.output))
    expect(not ("Degraded Passes" not in result.output))
    expect(not ("RegisterSubstitution" not in result.output))
    expect(not ("symbolic confidence=limited" not in result.output))
    expect(not ("Degradation Roles" not in result.output))
    expect(not ("degradation-trigger: 1" not in result.output))
    expect(not ("executed-under-degraded-mode: 2" not in result.output))
    expect(not ("Pass Validation Context" not in result.output))
    expect(not ("requested=symbolic, effective=runtime, degraded=yes" not in result.output))
    expect(not ("trigger=yes" not in result.output))


def test_cli_report_only_degraded_filters_json(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "requested_validation_mode": "structural",
                    "validation_mode": "structural",
                },
                "mutations": [
                    {
                        "pass_name": "NopInsertion",
                        "metadata": {"symbolic_requested": False},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli.app, ["report", str(report_path), "--only-degraded"])

    expect(result.exit_code == 0)
    expect(not ('"mutations": []' not in result.output))
    expect(not ('"only_degraded": true' not in result.output))


def test_cli_report_only_pass_accepts_mutation_alias(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "mutations": [
                    {
                        "pass_name": "NopInsertion",
                        "metadata": {
                            "symbolic_requested": True,
                            "symbolic_status": "bounded-step-passed",
                        },
                    }
                ],
                "passes": {
                    "NopInsertion": {
                        "symbolic_summary": {
                            "pass_name": "NopInsertion",
                            "symbolic_requested": 1,
                            "observable_match": 0,
                            "observable_mismatch": 0,
                            "bounded_only": 1,
                            "without_coverage": 0,
                            "severity": "bounded-only",
                            "issue_count": 1,
                            "issues": [],
                        }
                    }
                },
                "summary": {
                    "symbolic_coverage_by_pass": [
                        {
                            "pass_name": "NopInsertion",
                            "symbolic_requested": 1,
                            "observable_match": 0,
                            "observable_mismatch": 0,
                            "bounded_only": 1,
                            "without_coverage": 0,
                        }
                    ],
                    "symbolic_severity_by_pass": [
                        {
                            "pass_name": "NopInsertion",
                            "severity": "bounded-only",
                            "issue_count": 1,
                            "symbolic_requested": 1,
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli.app, ["report", "--only-pass", "nop", str(report_path)])

    expect(result.exit_code == 0)
    expect(not ("Pass Filter Resolution" not in result.output))
    expect(not ("nop -> NopInsertion" not in result.output))
    expect(not ('"only_pass": "NopInsertion"' not in result.output))
    expect(not ('"pass_name": "NopInsertion"' not in result.output))


def test_cli_report_only_degraded_keeps_degraded_pass_details(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "requested_validation_mode": "symbolic",
                    "validation_mode": "runtime",
                    "degradation_roles": {
                        "degradation-trigger": 1,
                    },
                },
                "validation_policy": {
                    "policy": "degrade-runtime",
                    "reason": "limited-symbolic-support",
                    "limited_passes": [
                        {
                            "mutation": "register",
                            "pass_name": "RegisterSubstitution",
                            "confidence": "limited",
                        }
                    ],
                },
                "mutations": [
                    {
                        "pass_name": "RegisterSubstitution",
                        "metadata": {"symbolic_requested": True},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli.app, ["report", str(report_path), "--only-degraded"])

    expect(result.exit_code == 0)
    expect(not ("Degraded Severity Priority" not in result.output))
    expect(not ('"degraded_passes": [' not in result.output))
    expect(not ('"pass_name": "RegisterSubstitution"' not in result.output))
    expect(not ('"degradation_roles": {' not in result.output))
    expect(not ('"degradation-trigger": 1' not in result.output))


def test_cli_report_only_failed_gates_filters_json(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "requested_validation_mode": "structural",
                    "validation_mode": "structural",
                },
                "gate_evaluation": {
                    "requested": {"min_severity": "clean"},
                    "results": {
                        "min_severity_passed": False,
                        "require_pass_severity_passed": True,
                        "require_pass_severity_failures": [],
                        "all_passed": False,
                    },
                },
                "mutations": [
                    {
                        "pass_name": "NopInsertion",
                        "metadata": {"symbolic_requested": False},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli.app, ["report", str(report_path), "--only-failed-gates"])

    expect(result.exit_code == 0)
    expect(not ("Gate Evaluation" not in result.output))
    expect(not ("Gate Failure Summary" not in result.output))
    expect(not ("min_severity_failed=yes, require_pass_failures=0" not in result.output))
    expect(not ("all_passed=no" not in result.output))
    expect(not ('"only_failed_gates": true' not in result.output))
    expect(not ('"failed_gates": true' not in result.output))
    expect(not ('"gate_failures": {' not in result.output))


def test_cli_report_gate_failure_summary_groups_failures_by_pass(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "requested_validation_mode": "structural",
                    "validation_mode": "structural",
                },
                "gate_evaluation": {
                    "requested": {
                        "require_pass_severity": [
                            {"pass_name": "NopInsertion", "max_severity": "clean"},
                            {"pass_name": "InstructionSubstitution", "max_severity": "bounded-only"},
                        ]
                    },
                    "results": {
                        "min_severity_passed": True,
                        "require_pass_severity_passed": False,
                        "require_pass_severity_failures": [
                            "NopInsertion=not-requested(expected <= clean)",
                            "InstructionSubstitution=without-coverage(expected <= bounded-only)",
                        ],
                        "all_passed": False,
                    },
                },
                "mutations": [
                    {
                        "pass_name": "InstructionSubstitution",
                        "metadata": {"symbolic_requested": True},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli.app, ["report", str(report_path), "--summary-only"])

    expect(result.exit_code == 0)
    expect(not ("Gate Failure Summary" not in result.output))
    expect(not ("require_pass_failures=2" not in result.output))
    expect(not ("expected_severity_counts=bounded-only:1, clean:1" not in result.output))
    expect(not ("Gate Failure By Pass" not in result.output))
    expect(not ("NopInsertion" not in result.output))
    expect(not ("InstructionSubstitution" not in result.output))
    expect(not ("count=1, strictest_expected=bounded-only" not in result.output))
    expect(not ("count=1, strictest_expected=clean" not in result.output))
    expect(not ("NopInsertion=not-requested(expected <= clean)" not in result.output))
    expect(not ("InstructionSubstitution=without-coverage(expected <= bounded-only)" not in result.output))
    gate_section = result.output.split("Gate Failure By Pass", 1)[1]
    expect(not (gate_section.index("InstructionSubstitution") >= gate_section.index("NopInsertion")))


def test_cli_report_gate_failure_summary_breaks_same_severity_ties_by_failure_count(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "requested_validation_mode": "structural",
                    "validation_mode": "structural",
                },
                "gate_evaluation": {
                    "requested": {
                        "require_pass_severity": [
                            {"pass_name": "NopInsertion", "max_severity": "clean"},
                            {"pass_name": "NopInsertion", "max_severity": "clean"},
                            {"pass_name": "InstructionSubstitution", "max_severity": "clean"},
                        ]
                    },
                    "results": {
                        "min_severity_passed": True,
                        "require_pass_severity_passed": False,
                        "require_pass_severity_failures": [
                            "NopInsertion=not-requested(expected <= clean)",
                            "NopInsertion=not-requested(expected <= clean)",
                            "InstructionSubstitution=not-requested(expected <= clean)",
                        ],
                        "all_passed": False,
                    },
                },
                "mutations": [
                    {
                        "pass_name": "InstructionSubstitution",
                        "metadata": {"symbolic_requested": True},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli.app, ["report", str(report_path), "--summary-only"])

    expect(result.exit_code == 0)
    expect(not ("expected_severity_counts=clean:3" not in result.output))
    expect(not ("count=2, strictest_expected=clean" not in result.output))
    gate_section = result.output.split("Gate Failure By Pass", 1)[1]
    expect(not (gate_section.index("NopInsertion") >= gate_section.index("InstructionSubstitution")))


def test_cli_report_exports_gate_failure_priority_in_filtered_summary(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    filtered_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "requested_validation_mode": "structural",
                    "validation_mode": "structural",
                },
                "gate_evaluation": {
                    "requested": {
                        "require_pass_severity": [
                            {"pass_name": "NopInsertion", "max_severity": "clean"},
                            {"pass_name": "NopInsertion", "max_severity": "clean"},
                            {"pass_name": "InstructionSubstitution", "max_severity": "clean"},
                        ]
                    },
                    "results": {
                        "min_severity_passed": True,
                        "require_pass_severity_passed": False,
                        "require_pass_severity_failures": [
                            "NopInsertion=not-requested(expected <= clean)",
                            "NopInsertion=not-requested(expected <= clean)",
                            "InstructionSubstitution=not-requested(expected <= clean)",
                        ],
                        "all_passed": False,
                    },
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            str(report_path),
            "--summary-only",
            "--only-failed-gates",
            "--output",
            str(filtered_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(filtered_path.read_text(encoding="utf-8"))
    priority = payload["filtered_summary"]["gate_failure_priority"]
    severity_counts = payload["filtered_summary"]["gate_failures"][
        "require_pass_severity_failures_by_expected_severity"
    ]
    expect([row[MUTATION_NAME_KEY] for row in priority] == ["NopInsertion", "InstructionSubstitution"])
    expect(priority[0]["failure_count"] == _EXPECTED_PRIORITY_0_FAILURE_COUNT_2)
    expect(priority[0]["strictest_expected_severity"] == "clean")
    expect(severity_counts == {"clean": 3})


def test_cli_report_only_expected_severity_filters_gate_summary(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    filtered_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "requested_validation_mode": "structural",
                    "validation_mode": "structural",
                    "gate_failure_priority": [
                        {
                            "pass_name": "InstructionSubstitution",
                            "failure_count": 1,
                            "strictest_expected_severity": "bounded-only",
                            "failures": ["InstructionSubstitution=not-requested(expected <= bounded-only)"],
                        },
                        {
                            "pass_name": "NopInsertion",
                            "failure_count": 1,
                            "strictest_expected_severity": "clean",
                            "failures": ["NopInsertion=not-requested(expected <= clean)"],
                        },
                    ],
                    "gate_failure_severity_priority": [
                        {"severity": "bounded-only", "failure_count": 1},
                        {"severity": "clean", "failure_count": 1},
                    ],
                },
                "gate_evaluation": {
                    "requested": {
                        "require_pass_severity": [
                            {"pass_name": "NopInsertion", "max_severity": "clean"},
                            {
                                "pass_name": "InstructionSubstitution",
                                "max_severity": "bounded-only",
                            },
                        ]
                    },
                    "results": {
                        "min_severity_passed": True,
                        "require_pass_severity_passed": False,
                        "require_pass_severity_failures": [
                            "NopInsertion=not-requested(expected <= clean)",
                            "InstructionSubstitution=not-requested(expected <= bounded-only)",
                        ],
                        "all_passed": False,
                    },
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            str(report_path),
            "--only-failed-gates",
            "--only-expected-severity",
            "clean",
            "--summary-only",
            "--output",
            str(filtered_path),
        ],
    )

    expect(result.exit_code == 0)
    expect(not ("expected_severity_counts=clean:1" not in result.output))
    payload = json.loads(filtered_path.read_text(encoding="utf-8"))
    expect(payload["report_filters"]["only_expected_severity"] == "clean")
    expect(
        payload["filtered_summary"]["gate_failures"]["require_pass_severity_failures_by_expected_severity"]
        == {"clean": 1}
    )
    expect(
        payload["filtered_summary"]["gate_failure_priority"]
        == [
            {
                "pass_name": "NopInsertion",
                "failure_count": 1,
                "strictest_expected_severity": "clean",
                "failures": ["NopInsertion=not-requested(expected <= clean)"],
            }
        ]
    )


def test_cli_report_only_expected_severity_require_results_respects_filtered_gates(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "gate_failure_priority": [
                        {
                            "pass_name": "NopInsertion",
                            "failure_count": 1,
                            "strictest_expected_severity": "clean",
                            "failures": ["NopInsertion=not-requested(expected <= clean)"],
                        }
                    ],
                    "gate_failure_severity_priority": [{"severity": "clean", "failure_count": 1}],
                },
                "gate_evaluation": {
                    "requested": {"require_pass_severity": [{"pass_name": "NopInsertion", "max_severity": "clean"}]},
                    "results": {
                        "min_severity_passed": True,
                        "require_pass_severity_passed": False,
                        "require_pass_severity_failures": ["NopInsertion=not-requested(expected <= clean)"],
                        "all_passed": False,
                    },
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    success = runner.invoke(
        cli.app,
        [
            "report",
            str(report_path),
            "--only-failed-gates",
            "--only-expected-severity",
            "clean",
            "--require-results",
        ],
    )
    failure = runner.invoke(
        cli.app,
        [
            "report",
            str(report_path),
            "--only-failed-gates",
            "--only-expected-severity",
            "mismatch",
            "--require-results",
        ],
    )

    expect(success.exit_code == 0)
    expect(failure.exit_code == 1)


def test_cli_report_only_pass_failure_filters_gate_summary(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    filtered_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "gate_failure_priority": [
                        {
                            "pass_name": "NopInsertion",
                            "failure_count": 1,
                            "strictest_expected_severity": "clean",
                            "failures": ["NopInsertion=not-requested(expected <= clean)"],
                        },
                        {
                            "pass_name": "InstructionSubstitution",
                            "failure_count": 1,
                            "strictest_expected_severity": "bounded-only",
                            "failures": ["InstructionSubstitution=not-requested(expected <= bounded-only)"],
                        },
                    ],
                    "gate_failure_severity_priority": [
                        {"severity": "bounded-only", "failure_count": 1},
                        {"severity": "clean", "failure_count": 1},
                    ],
                },
                "gate_evaluation": {
                    "requested": {
                        "require_pass_severity": [
                            {"pass_name": "NopInsertion", "max_severity": "clean"},
                            {
                                "pass_name": "InstructionSubstitution",
                                "max_severity": "bounded-only",
                            },
                        ]
                    },
                    "results": {
                        "min_severity_passed": True,
                        "require_pass_severity_passed": False,
                        "require_pass_severity_failures": [
                            "NopInsertion=not-requested(expected <= clean)",
                            "InstructionSubstitution=not-requested(expected <= bounded-only)",
                        ],
                        "all_passed": False,
                    },
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            str(report_path),
            "--only-failed-gates",
            "--only-pass-failure",
            "NopInsertion",
            "--summary-only",
            "--output",
            str(filtered_path),
        ],
    )

    expect(result.exit_code == 0)
    expect(not ("expected_severity_counts=clean:1" not in result.output))
    payload = json.loads(filtered_path.read_text(encoding="utf-8"))
    expect(payload["report_filters"][ONLY_FAILED_MUTATION_KEY] == "NopInsertion")
    expect(
        payload["filtered_summary"]["gate_failures"]["require_pass_severity_failures_by_pass"]
        == {"NopInsertion": ["NopInsertion=not-requested(expected <= clean)"]}
    )
    expect(
        payload["filtered_summary"]["gate_failure_priority"]
        == [
            {
                "pass_name": "NopInsertion",
                "failure_count": 1,
                "strictest_expected_severity": "clean",
                "failures": ["NopInsertion=not-requested(expected <= clean)"],
            }
        ]
    )


def test_cli_report_only_pass_failure_require_results_respects_filtered_gates(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "gate_failure_priority": [
                        {
                            "pass_name": "NopInsertion",
                            "failure_count": 1,
                            "strictest_expected_severity": "clean",
                            "failures": ["NopInsertion=not-requested(expected <= clean)"],
                        }
                    ],
                },
                "gate_evaluation": {
                    "requested": {"require_pass_severity": [{"pass_name": "NopInsertion", "max_severity": "clean"}]},
                    "results": {
                        "min_severity_passed": True,
                        "require_pass_severity_passed": False,
                        "require_pass_severity_failures": ["NopInsertion=not-requested(expected <= clean)"],
                        "all_passed": False,
                    },
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    success = runner.invoke(
        cli.app,
        [
            "report",
            str(report_path),
            "--only-failed-gates",
            "--only-pass-failure",
            "NopInsertion",
            "--require-results",
        ],
    )
    failure = runner.invoke(
        cli.app,
        [
            "report",
            str(report_path),
            "--only-failed-gates",
            "--only-pass-failure",
            "RegisterSubstitution",
            "--require-results",
        ],
    )

    expect(success.exit_code == 0)
    expect(failure.exit_code == 1)


def test_cli_report_only_pass_failure_accepts_mutation_alias(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    filtered_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "gate_failure_priority": [
                        {
                            "pass_name": "NopInsertion",
                            "failure_count": 1,
                            "strictest_expected_severity": "clean",
                            "failures": ["NopInsertion=not-requested(expected <= clean)"],
                        }
                    ],
                },
                "gate_evaluation": {
                    "requested": {"require_pass_severity": [{"pass_name": "NopInsertion", "max_severity": "clean"}]},
                    "results": {
                        "min_severity_passed": True,
                        "require_pass_severity_passed": False,
                        "require_pass_severity_failures": ["NopInsertion=not-requested(expected <= clean)"],
                        "all_passed": False,
                    },
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            str(report_path),
            "--only-failed-gates",
            "--only-pass-failure",
            "nop",
            "--summary-only",
            "--output",
            str(filtered_path),
        ],
    )

    expect(result.exit_code == 0)
    expect(not ("Pass Failure Filter Resolution" not in result.output))
    expect(not ("nop -> NopInsertion" not in result.output))
    payload = json.loads(filtered_path.read_text(encoding="utf-8"))
    expect(payload["report_filters"][ONLY_FAILED_MUTATION_KEY] == "NopInsertion")
    expect(payload["filtered_summary"][ONLY_FAILED_MUTATION_KEY] == "NopInsertion")


def test_cli_report_require_results_respects_only_failed_gates_without_mutations(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "requested_validation_mode": "structural",
                    "validation_mode": "structural",
                },
                "gate_evaluation": {
                    "requested": {"min_severity": "clean"},
                    "results": {
                        "min_severity_passed": False,
                        "require_pass_severity_passed": True,
                        "require_pass_severity_failures": [],
                        "all_passed": False,
                    },
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    success = runner.invoke(
        cli.app,
        ["report", str(report_path), "--only-failed-gates", "--require-results"],
    )
    failure = runner.invoke(
        cli.app,
        ["report", str(report_path), "--only-failed-gates", "--require-results", "--min-severity", "clean"],
    )

    expect(success.exit_code == 0)
    expect(failure.exit_code == 1)


def test_cli_report_require_results_respects_min_severity(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "symbolic_severity_by_pass": [
                        {
                            "pass_name": "InstructionSubstitution",
                            "severity": "clean",
                            "issue_count": 0,
                            "symbolic_requested": 1,
                        }
                    ]
                },
                "mutations": [
                    {
                        "pass_name": "InstructionSubstitution",
                        "metadata": {"symbolic_requested": True},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    success = runner.invoke(
        cli.app,
        ["report", str(report_path), "--require-results", "--min-severity", "clean"],
    )
    failure = runner.invoke(
        cli.app,
        ["report", str(report_path), "--require-results", "--min-severity", "bounded-only"],
    )

    expect(success.exit_code == 0)
    expect(failure.exit_code == 1)


def test_cli_report_distinguishes_triggering_vs_degraded_pass_roles(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "requested_validation_mode": "symbolic",
                    "validation_mode": "runtime",
                },
                "validation_policy": {
                    "policy": "degrade-runtime",
                    "reason": "limited-symbolic-support",
                    "limited_passes": [
                        {
                            "mutation": "register",
                            "pass_name": "RegisterSubstitution",
                            "confidence": "limited",
                        }
                    ],
                },
                "passes": {
                    "RegisterSubstitution": {
                        "validation_context": {
                            "requested_validation_mode": "symbolic",
                            "effective_validation_mode": "runtime",
                            "degraded_execution": True,
                            "degradation_triggered_by_pass": True,
                        }
                    },
                    "NopInsertion": {
                        "validation_context": {
                            "requested_validation_mode": "symbolic",
                            "effective_validation_mode": "runtime",
                            "degraded_execution": True,
                            "degradation_triggered_by_pass": False,
                        }
                    },
                },
                "mutations": [
                    {
                        "pass_name": "RegisterSubstitution",
                        "metadata": {"symbolic_requested": True},
                    },
                    {
                        "pass_name": "NopInsertion",
                        "metadata": {"symbolic_requested": True},
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli.app, ["report", str(report_path), "--summary-only"])

    expect(result.exit_code == 0)
    expect(not ("role=degradation-trigger" not in result.output))
    expect(not ("role=executed-under-degraded-mode" not in result.output))

    json_result = runner.invoke(cli.app, ["report", str(report_path)])
    expect(json_result.exit_code == 0)
    expect(not ('"role": "degradation-trigger"' not in json_result.output))
    expect(not ('"role": "executed-under-degraded-mode"' not in json_result.output))


def test_cli_report_skips_symbolic_summary_when_not_present(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps({"mutations": [{"metadata": {}}]}), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli.app, ["report", str(report_path)])

    expect(result.exit_code == 0)
    expect("Symbolic Mutation Summary" not in result.output)
    expect("Symbolic Mismatches" not in result.output)


def test_cli_report_only_mismatches_filters_json(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "mutations": [
                    {
                        "pass_name": "InstructionSubstitution",
                        "start_address": 0x401000,
                        "end_address": 0x401001,
                        "metadata": {
                            "symbolic_requested": True,
                            "symbolic_observable_check_performed": True,
                            "symbolic_observable_equivalent": True,
                        },
                    },
                    {
                        "pass_name": "InstructionSubstitution",
                        "start_address": 0x401010,
                        "end_address": 0x401011,
                        "metadata": {
                            "symbolic_requested": True,
                            "symbolic_observable_check_performed": True,
                            "symbolic_observable_equivalent": False,
                            "symbolic_observable_mismatches": ["eax"],
                        },
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli.app, ["report", "--only-mismatches", str(report_path)])

    expect(result.exit_code == 0)
    expect(not ("Filtered Mismatch Mutations: 1" not in result.output))
    expect(not ("0x401010" not in result.output))
    expect("0x401000" not in result.output)


def test_cli_report_only_mismatches_preserves_degraded_context(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "requested_validation_mode": "symbolic",
                    "validation_mode": "runtime",
                    "degradation_roles": {
                        "degradation-trigger": 1,
                    },
                },
                "validation_policy": {
                    "policy": "degrade-runtime",
                    "reason": "limited-symbolic-support",
                    "limited_passes": [
                        {
                            "mutation": "register",
                            "pass_name": "RegisterSubstitution",
                            "confidence": "limited",
                            "role": "degradation-trigger",
                        }
                    ],
                },
                "passes": {
                    "RegisterSubstitution": {
                        "validation_context": {
                            "requested_validation_mode": "symbolic",
                            "effective_validation_mode": "runtime",
                            "degraded_execution": True,
                            "degradation_triggered_by_pass": True,
                            "role": "degradation-trigger",
                        }
                    }
                },
                "mutations": [
                    {
                        "pass_name": "RegisterSubstitution",
                        "start_address": 0x401010,
                        "end_address": 0x401011,
                        "metadata": {
                            "symbolic_requested": True,
                            "symbolic_observable_check_performed": True,
                            "symbolic_observable_equivalent": False,
                            "symbolic_observable_mismatches": ["rax"],
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        ["report", "--only-mismatches", "--output", str(output_path), str(report_path)],
    )

    expect(result.exit_code == 0)
    expect(not ("Mismatch Degradation Context" not in result.output))
    expect(not ("Mismatch Severity Priority" not in result.output))
    expect(not ("requested=symbolic, effective=runtime" not in result.output))
    expect(not ("trigger_passes=RegisterSubstitution" not in result.output))
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["requested_validation_mode"] == "symbolic")
    expect(payload["filtered_summary"]["validation_mode"] == "runtime")
    expect(not (payload["filtered_summary"]["degraded_validation"] is not True))
    expect(payload["filtered_summary"]["degraded_passes"][0][MUTATION_NAME_KEY] == "RegisterSubstitution")
    expect(payload["filtered_summary"]["degradation_roles"]["degradation-trigger"] == 1)
    expect(payload["filtered_summary"]["symbolic_severity_by_pass"][0][MUTATION_NAME_KEY] == "RegisterSubstitution")
    expect(payload["filtered_summary"]["symbolic_severity_by_pass"][0]["severity"] == "mismatch")
    expect(
        payload["filtered_summary"]["pass_validation_context"]["RegisterSubstitution"]["role"] == "degradation-trigger"
    )


def test_cli_report_only_mismatches_handles_empty_set(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "mutations": [
                    {
                        "pass_name": "InstructionSubstitution",
                        "metadata": {
                            "symbolic_requested": True,
                            "symbolic_observable_check_performed": True,
                            "symbolic_observable_equivalent": True,
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli.app, ["report", "--only-mismatches", str(report_path)])

    expect(result.exit_code == 0)
    expect(not ("Filtered Mismatch Mutations: 0" not in result.output))


def test_cli_report_only_pass_filters_json(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "mutations": [
                    {
                        "pass_name": "InstructionSubstitution",
                        "start_address": 0x401000,
                        "metadata": {"symbolic_requested": True},
                    },
                    {
                        "pass_name": "NopInsertion",
                        "start_address": 0x402000,
                        "metadata": {"symbolic_requested": True},
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        ["report", "--only-pass", "InstructionSubstitution", str(report_path)],
    )

    expect(result.exit_code == 0)
    expect(not ("InstructionSubstitution" not in result.output))
    expect(not ('"pass_name": "InstructionSubstitution"' not in result.output))
    expect('"pass_name": "NopInsertion"' not in result.output)
    expect(not ('"only_pass": "InstructionSubstitution"' not in result.output))


def test_cli_report_only_pass_shows_local_symbolic_summary(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "passes": {
                    "InstructionSubstitution": {
                        "symbolic_summary": {
                            "pass_name": "InstructionSubstitution",
                            "symbolic_requested": 2,
                            "observable_match": 1,
                            "observable_mismatch": 1,
                            "bounded_only": 0,
                            "without_coverage": 0,
                            "severity": "mismatch",
                            "issue_count": 1,
                            "issues": [
                                {
                                    "pass_name": "InstructionSubstitution",
                                    "severity": "mismatch",
                                    "observable_mismatch": 1,
                                    "without_coverage": 0,
                                    "bounded_only": 0,
                                }
                            ],
                        },
                        "evidence_summary": {
                            "pass_name": "InstructionSubstitution",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 1,
                        },
                    }
                },
                "summary": {
                    "pass_evidence": [
                        {
                            "pass_name": "InstructionSubstitution",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 1,
                        }
                    ]
                },
                "mutations": [
                    {
                        "pass_name": "InstructionSubstitution",
                        "metadata": {"symbolic_requested": True},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--only-pass",
            "InstructionSubstitution",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    expect(not ("Pass Symbolic Summary" not in result.output))
    expect(not ("InstructionSubstitution: 1 match, 1 mismatch" not in result.output))
    expect(not ("0 bounded-only, 0 without" not in result.output))
    expect(not ("coverage" not in result.output))
    expect(not ("severity=mismatch" not in result.output))
    expect(not ("issue_count=1" not in result.output))
    expect(not ("issues: mismatch(mismatch=1, without_coverage=0, bounded_only=0)" not in result.output))
    expect(not ("Pass Evidence Summary" not in result.output))
    expect(not ("changed_regions=1" not in result.output))
    expect(not ("changed_bytes=2" not in result.output))
    expect(not ("symbolic_mismatch=1" not in result.output))
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(
        payload["filtered_summary"]["pass_symbolic_summary"]["InstructionSubstitution"]["symbolic_requested"]
        == _EXPECTED_PAYLOAD_FILTERED_SUMMARY_PASS_SYMBOLIC_SUMMAR_2
    )
    expect(
        payload["filtered_summary"]["pass_symbolic_summary"]["InstructionSubstitution"]["issues"][0]["severity"]
        == "mismatch"
    )
    expect(payload["filtered_summary"]["pass_symbolic_summary"]["InstructionSubstitution"]["severity"] == "mismatch")
    expect(payload["filtered_summary"]["pass_evidence"][0][MUTATION_NAME_KEY] == "InstructionSubstitution")
    expect(payload["filtered_summary"]["pass_evidence"][0]["changed_region_count"] == 1)


def test_cli_report_orders_pass_evidence_by_risk(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "pass_evidence": [
                        {
                            "pass_name": "NopInsertion",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 0,
                        },
                        {
                            "pass_name": "RegisterSubstitution",
                            "changed_region_count": 2,
                            "changed_bytes": 4,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 2,
                            "symbolic_binary_mismatched_regions": 2,
                        },
                    ]
                },
                "mutations": [
                    {"pass_name": "NopInsertion", "metadata": {"symbolic_requested": True}},
                    {"pass_name": "RegisterSubstitution", "metadata": {"symbolic_requested": True}},
                ],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        ["report", "--summary-only", "--output", str(output_path), str(report_path)],
    )

    expect(result.exit_code == 0)
    expect(not ("Pass Evidence" not in result.output))
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["pass_evidence"][0][MUTATION_NAME_KEY] == "RegisterSubstitution")
    expect(payload["filtered_summary"]["pass_evidence"][1][MUTATION_NAME_KEY] == "NopInsertion")


def test_cli_report_prefers_persisted_pass_evidence_priority(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "pass_evidence": [
                        {
                            "pass_name": "NopInsertion",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 0,
                        },
                        {
                            "pass_name": "RegisterSubstitution",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 1,
                        },
                    ],
                    "pass_evidence_priority": [
                        {
                            "pass_name": "RegisterSubstitution",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 1,
                        },
                        {
                            "pass_name": "NopInsertion",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 0,
                        },
                    ],
                },
                "mutations": [
                    {"pass_name": "NopInsertion"},
                    {"pass_name": "RegisterSubstitution"},
                ],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        ["report", "--summary-only", "--output", str(output_path), str(report_path)],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["pass_evidence"][0][MUTATION_NAME_KEY] == "RegisterSubstitution")
    expect(payload["filtered_summary"]["pass_evidence"][1][MUTATION_NAME_KEY] == "NopInsertion")


def test_cli_report_only_risky_passes_filters_to_risky_passes(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "passes": {
                    "NopInsertion": {
                        "symbolic_summary": {
                            "pass_name": "NopInsertion",
                            "symbolic_requested": 1,
                            "observable_match": 1,
                            "observable_mismatch": 0,
                            "bounded_only": 0,
                            "without_coverage": 0,
                            "severity": "clean",
                            "issue_count": 0,
                            "issues": [],
                        },
                        "evidence_summary": {
                            "pass_name": "NopInsertion",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 0,
                        },
                    },
                    "RegisterSubstitution": {
                        "symbolic_summary": {
                            "pass_name": "RegisterSubstitution",
                            "symbolic_requested": 1,
                            "observable_match": 0,
                            "observable_mismatch": 1,
                            "bounded_only": 0,
                            "without_coverage": 0,
                            "severity": "mismatch",
                            "issue_count": 1,
                            "issues": [
                                {
                                    "pass_name": "RegisterSubstitution",
                                    "severity": "mismatch",
                                    "observable_mismatch": 1,
                                    "without_coverage": 0,
                                    "bounded_only": 0,
                                }
                            ],
                        },
                        "evidence_summary": {
                            "pass_name": "RegisterSubstitution",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 1,
                        },
                    },
                },
                "summary": {
                    "pass_evidence": [
                        {
                            "pass_name": "NopInsertion",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 0,
                        },
                        {
                            "pass_name": "RegisterSubstitution",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 1,
                        },
                    ]
                },
                "mutations": [
                    {"pass_name": "NopInsertion", "metadata": {"symbolic_requested": True}},
                    {"pass_name": "RegisterSubstitution", "metadata": {"symbolic_requested": True}},
                ],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--only-risky-passes",
            "--summary-only",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    expect(not ("Risky Pass Filter" not in result.output))
    expect(not ("RegisterSubstitution" not in result.output))
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(not (payload["report_filters"]["only_risky_passes"] is not True))
    expect(payload["filtered_summary"]["risky_passes"] == ["RegisterSubstitution"])
    expect(payload["filtered_summary"]["pass_risk_buckets"]["risky"] == ["RegisterSubstitution"])
    expect(payload["filtered_summary"]["pass_risk_buckets"]["symbolic"] == ["RegisterSubstitution"])
    expect(payload["filtered_summary"]["pass_evidence"][0][MUTATION_NAME_KEY] == "RegisterSubstitution")
    expect(payload["filtered_summary"]["symbolic_severity_by_pass"][0][MUTATION_NAME_KEY] == "RegisterSubstitution")


def test_cli_report_only_risky_passes_require_results_uses_pass_evidence(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "passes": {
                    "NopInsertion": {
                        "symbolic_summary": {
                            "pass_name": "NopInsertion",
                            "symbolic_requested": 1,
                            "observable_match": 1,
                            "observable_mismatch": 0,
                            "bounded_only": 0,
                            "without_coverage": 0,
                            "severity": "clean",
                            "issue_count": 0,
                            "issues": [],
                        },
                        "evidence_summary": {
                            "pass_name": "NopInsertion",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 0,
                        },
                    }
                },
                "summary": {
                    "pass_evidence": [
                        {
                            "pass_name": "NopInsertion",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 0,
                        }
                    ]
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--only-risky-passes",
            "--require-results",
            str(report_path),
        ],
    )

    expect(result.exit_code == 1)


def test_cli_report_prefers_persisted_pass_buckets_without_pass_results(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "pass_risk_buckets": {
                        "risky": ["RegisterSubstitution"],
                        "structural": [],
                        "symbolic": ["RegisterSubstitution"],
                        "clean": [],
                        "covered": [],
                        "uncovered": [],
                    },
                    "pass_coverage_buckets": {
                        "covered": ["InstructionSubstitution"],
                        "uncovered": ["ReportFixture"],
                        "clean_only": ["InstructionSubstitution", "ReportFixture"],
                    },
                    "pass_evidence": [
                        {
                            "pass_name": "RegisterSubstitution",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 1,
                        }
                    ],
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--only-risky-passes",
            "--summary-only",
            "--require-results",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["risky_passes"] == ["RegisterSubstitution"])
    expect(payload["filtered_summary"]["pass_risk_buckets"]["symbolic"] == ["RegisterSubstitution"])
    expect(payload["filtered_summary"]["pass_coverage_buckets"]["covered"] == ["InstructionSubstitution"])


def test_cli_report_prefers_persisted_pass_summary_maps_without_pass_results(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "pass_symbolic_summary": {
                        "InstructionSubstitution": {
                            "pass_name": "InstructionSubstitution",
                            "symbolic_requested": 1,
                            "observable_match": 1,
                            "observable_mismatch": 0,
                            "bounded_only": 0,
                            "without_coverage": 0,
                            "severity": "clean",
                            "issue_count": 0,
                            "issues": [],
                        }
                    },
                    "pass_validation_context": {
                        "InstructionSubstitution": {
                            "requested_validation_mode": "symbolic",
                            "effective_validation_mode": "symbolic",
                            "degraded_execution": False,
                            "degradation_triggered_by_pass": False,
                            "role": "requested-mode",
                        }
                    },
                    "pass_risk_buckets": {
                        "risky": [],
                        "structural": [],
                        "symbolic": [],
                        "clean": ["InstructionSubstitution"],
                        "covered": ["InstructionSubstitution"],
                        "uncovered": [],
                    },
                    "pass_coverage_buckets": {
                        "covered": ["InstructionSubstitution"],
                        "uncovered": [],
                        "clean_only": ["InstructionSubstitution"],
                    },
                    "pass_evidence": [
                        {
                            "pass_name": "InstructionSubstitution",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 0,
                        }
                    ],
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--summary-only",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["pass_symbolic_summary"]["InstructionSubstitution"]["severity"] == "clean")
    expect(
        payload["filtered_summary"]["pass_validation_context"]["InstructionSubstitution"]["role"] == "requested-mode"
    )


def test_cli_report_prefers_persisted_capability_and_evidence_maps_without_pass_results(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "pass_capabilities": {
                        "InstructionSubstitution": {
                            "runtime": {"recommended": True},
                            "symbolic": {"recommended": True, "confidence": "best among stable passes"},
                        }
                    },
                    "pass_evidence_map": {
                        "InstructionSubstitution": {
                            "pass_name": "InstructionSubstitution",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 0,
                        }
                    },
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--summary-only",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(
        not (
            payload["filtered_summary"]["pass_capabilities"]["InstructionSubstitution"]["symbolic"]["recommended"]
            is not True
        )
    )
    expect(payload["filtered_summary"]["pass_evidence"][0][MUTATION_NAME_KEY] == "InstructionSubstitution")


def test_cli_report_prefers_persisted_triage_and_discard_summaries_without_pass_results(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "symbolic_overview": {
                        "symbolic_requested": 1,
                        "observable_match": 0,
                        "observable_mismatch": 1,
                        "bounded_only": 0,
                        "without_coverage": 0,
                        "statuses": {"real-binary-observable-mismatch": 1},
                    },
                    "symbolic_status_counts": {"real-binary-observable-mismatch": 1},
                    "pass_triage_rows": [
                        {
                            "pass_name": "RegisterSubstitution",
                            "severity": "mismatch",
                            "issue_count": 1,
                            "symbolic_requested": 1,
                            "observable_match": 0,
                            "observable_mismatch": 1,
                            "bounded_only": 0,
                            "without_coverage": 0,
                            "structural_issue_count": 0,
                            "symbolic_binary_mismatched_regions": 1,
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "role": "requested-mode",
                            "degraded_execution": False,
                            "runtime_recommended": True,
                            "symbolic_recommended": False,
                            "symbolic_confidence": "limited",
                        }
                    ],
                    "pass_capability_summary": [
                        {
                            "pass_name": "RegisterSubstitution",
                            "runtime_recommended": True,
                            "symbolic_recommended": False,
                            "symbolic_confidence": "limited",
                        }
                    ],
                    "validation_role_rows": [
                        {
                            "pass_name": "RegisterSubstitution",
                            "role": "requested-mode",
                            "requested_validation_mode": "symbolic",
                            "effective_validation_mode": "symbolic",
                            "degraded_execution": False,
                        }
                    ],
                    "discarded_mutation_summary": {
                        "by_pass": [
                            {
                                "pass_name": "RegisterSubstitution",
                                "discarded_count": 1,
                                "reasons": {"runtime_validation_failed": 1},
                            }
                        ],
                        "by_reason": {"runtime_validation_failed": 1},
                        "by_pass_map": {
                            "RegisterSubstitution": {
                                "discarded_count": 1,
                                "reasons": {"runtime_validation_failed": 1},
                            }
                        },
                    },
                    "discarded_mutation_priority": [
                        {
                            "pass_name": "RegisterSubstitution",
                            "discarded_count": 1,
                            "reasons": {"runtime_validation_failed": 1},
                        }
                    ],
                    "validation_adjustments": {
                        "requested_validation_mode": "symbolic",
                        "effective_validation_mode": "symbolic",
                        "degraded_validation": False,
                        "policy": None,
                        "reason": None,
                        "trigger_passes": [],
                        "executed_under_degraded_mode_passes": [],
                    },
                    "pass_evidence_compact": [
                        {
                            "pass_name": "RegisterSubstitution",
                            "severity": "mismatch",
                            "structural_issue_count": 0,
                            "symbolic_binary_mismatched_regions": 1,
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "role": "requested-mode",
                            "symbolic_confidence": "limited",
                        }
                    ],
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--summary-only",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["symbolic_statuses"] == {"real-binary-observable-mismatch": 1})
    expect(payload["filtered_summary"]["pass_triage_rows"][0][MUTATION_NAME_KEY] == "RegisterSubstitution")
    expect(payload["filtered_summary"]["pass_capability_summary"][0]["symbolic_confidence"] == "limited")
    expect(payload["filtered_summary"]["validation_role_rows"][0]["role"] == "requested-mode")
    expect(not (payload["filtered_summary"]["validation_adjustments"]["degraded_validation"] is not False))
    expect(
        not (payload["filtered_summary"]["validation_adjustment_compact_summary"]["degraded_validation"] is not False)
    )
    expect(payload["filtered_summary"]["pass_evidence"][0][MUTATION_NAME_KEY] == "RegisterSubstitution")
    expect(payload["filtered_summary"]["discarded_mutation_summary"]["by_reason"] == {"runtime_validation_failed": 1})
    expect(
        payload["filtered_summary"]["discarded_mutation_compact_rows"][0][MUTATION_NAME_KEY] == "RegisterSubstitution"
    )
    expect(payload["filtered_summary"]["discarded_mutation_final_rows"][0][MUTATION_NAME_KEY] == "RegisterSubstitution")
    expect(payload["filtered_summary"]["discarded_mutation_final_rows"][0]["reasons"] == ["runtime_validation_failed"])
    expect(payload["filtered_summary"]["discarded_mutation_compact_by_reason"] == {"runtime_validation_failed": 1})


def test_cli_report_prefers_report_views_and_normalized_pass_results_without_pass_results(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "report_views": {
                        "passes": {
                            "risky": ["RegisterSubstitution"],
                            "structural_risk": [],
                            "symbolic_risk": ["RegisterSubstitution"],
                            "clean": ["ReportFixture"],
                            "covered": [],
                            "uncovered": ["ReportFixture"],
                        },
                        "triage_priority": [
                            {
                                "pass_name": "RegisterSubstitution",
                                "severity": "mismatch",
                                "severity_order": 0,
                                "structural_issue_count": 0,
                                "symbolic_binary_mismatched_regions": 1,
                                "changed_region_count": 1,
                                "changed_bytes": 2,
                            }
                        ],
                        "mismatch_priority": [],
                        "pass_filter_views": {
                            "only_risky_passes": ["RegisterSubstitution"],
                            "only_structural_risk": [],
                            "only_symbolic_risk": ["RegisterSubstitution"],
                            "only_clean_passes": ["ReportFixture"],
                            "only_covered_passes": [],
                            "only_uncovered_passes": ["ReportFixture"],
                        },
                        "mismatch_view": [],
                        "failed_gates": [],
                        "discarded_view": {
                            "priority": [],
                            "by_reason": {},
                            "by_pass": [],
                        },
                    },
                    "normalized_pass_results": [
                        {
                            "pass_name": "RegisterSubstitution",
                            "severity": "mismatch",
                            "issue_count": 1,
                            "structural_issue_count": 0,
                            "symbolic_binary_mismatched_regions": 1,
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "runtime_recommended": True,
                            "symbolic_recommended": False,
                            "symbolic_confidence": "limited",
                            "role": "requested-mode",
                            "symbolic_requested": 1,
                            "observable_match": 0,
                            "observable_mismatch": 1,
                            "bounded_only": 0,
                            "without_coverage": 0,
                        }
                    ],
                    "validation_adjustment_rows": [
                        {
                            "pass_name": "RegisterSubstitution",
                            "role": "requested-mode",
                            "degraded_validation": False,
                            "triggered_adjustment": False,
                            "executed_under_degraded_mode": False,
                            "gate_failures": [],
                            "gate_failure_count": 0,
                        }
                    ],
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--only-risky-passes",
            "--summary-only",
            "--require-results",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["risky_passes"] == ["RegisterSubstitution"])
    expect(payload["filtered_summary"]["pass_triage_rows"][0][MUTATION_NAME_KEY] == "RegisterSubstitution")
    expect(payload["filtered_summary"]["normalized_pass_results"][0][MUTATION_NAME_KEY] == "RegisterSubstitution")
    expect(payload["filtered_summary"]["pass_validation_context"]["RegisterSubstitution"]["role"] == "requested-mode")
    expect(payload["filtered_summary"]["pass_symbolic_summary"]["RegisterSubstitution"]["severity"] == "mismatch")


def test_cli_report_handles_summary_report_views_only_minimal_report(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "report_views": {
                        "passes": {
                            "risky": ["RegisterSubstitution"],
                            "structural_risk": [],
                            "symbolic_risk": ["RegisterSubstitution"],
                            "clean": [],
                            "covered": [],
                            "uncovered": [],
                        },
                        "pass_filter_views": {
                            "only_risky_passes": ["RegisterSubstitution"],
                            "only_structural_risk": [],
                            "only_symbolic_risk": ["RegisterSubstitution"],
                            "only_clean_passes": [],
                            "only_covered_passes": [],
                            "only_uncovered_passes": [],
                        },
                        "only_failed_gates": {
                            "priority": [
                                {
                                    "pass_name": "RegisterSubstitution",
                                    "failure_count": 1,
                                    "strictest_expected_severity": "clean",
                                    "role": "requested-mode",
                                    "failures": ["RegisterSubstitution=not-requested(expected <= clean)"],
                                }
                            ],
                            "by_pass": {
                                "RegisterSubstitution": {
                                    "pass_name": "RegisterSubstitution",
                                    "failure_count": 1,
                                    "strictest_expected_severity": "clean",
                                    "role": "requested-mode",
                                    "failures": ["RegisterSubstitution=not-requested(expected <= clean)"],
                                }
                            },
                            "grouped_by_pass": [
                                {
                                    "pass_name": "RegisterSubstitution",
                                    "failure_count": 1,
                                    "strictest_expected_severity": "clean",
                                    "role": "requested-mode",
                                    "failures": ["RegisterSubstitution=not-requested(expected <= clean)"],
                                }
                            ],
                            "summary": {
                                "all_passed": False,
                                "require_pass_severity_failed": True,
                                "require_pass_severity_failure_count": 1,
                                "require_pass_severity_failures": [
                                    "RegisterSubstitution=not-requested(expected <= clean)"
                                ],
                                "require_pass_severity_failures_by_pass": {
                                    "RegisterSubstitution": ["RegisterSubstitution=not-requested(expected <= clean)"]
                                },
                                "require_pass_severity_failures_by_expected_severity": {"clean": 1},
                            },
                            "severity_priority": [{"severity": "clean", "failure_count": 1}],
                            "expected_severity_counts": {"clean": 1},
                            "failed": True,
                            "failure_count": 1,
                        },
                    },
                    "validation_adjustments": {
                        "requested_validation_mode": "symbolic",
                        "effective_validation_mode": "runtime",
                        "degraded_validation": True,
                    },
                },
                "gate_evaluation": {
                    "requested": {},
                    "results": {"all_passed": False},
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--only-failed-gates",
            "--summary-only",
            "--require-results",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(not (payload["filtered_summary"]["failed_gates"] is not True))
    expect(payload["filtered_summary"]["gate_failure_priority"][0][MUTATION_NAME_KEY] == "RegisterSubstitution")
    expect(
        payload["filtered_summary"]["gate_failures"]["require_pass_severity_failures_by_expected_severity"]
        == {"clean": 1}
    )


def test_cli_report_handles_summary_normalized_pass_results_only_minimal_report(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "normalized_pass_results": [
                        {
                            "pass_name": "InstructionSubstitution",
                            "severity": "clean",
                            "issue_count": 0,
                            "structural_issue_count": 0,
                            "symbolic_binary_mismatched_regions": 0,
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "runtime_recommended": True,
                            "symbolic_recommended": True,
                            "symbolic_confidence": "best among stable passes",
                            "role": "requested-mode",
                            "symbolic_requested": 1,
                            "observable_match": 1,
                            "observable_mismatch": 0,
                            "bounded_only": 0,
                            "without_coverage": 0,
                        }
                    ],
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--only-pass",
            "InstructionSubstitution",
            "--summary-only",
            "--require-results",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["passes"] == ["InstructionSubstitution"])
    expect(payload["filtered_summary"]["normalized_pass_results"][0][MUTATION_NAME_KEY] == "InstructionSubstitution")
    expect(payload["filtered_summary"]["pass_symbolic_summary"]["InstructionSubstitution"]["severity"] == "clean")


def test_cli_report_handles_summary_general_passes_only_minimal_report(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "report_views": {
                        "general_passes": [
                            {
                                "pass_name": "InstructionSubstitution",
                                "severity": "clean",
                                "issue_count": 0,
                                "structural_issue_count": 0,
                                "symbolic_binary_mismatched_regions": 0,
                                "changed_region_count": 1,
                                "changed_bytes": 2,
                                "runtime_recommended": True,
                                "symbolic_recommended": True,
                                "symbolic_confidence": "best among stable passes",
                                "role": "requested-mode",
                                "symbolic_requested": 1,
                                "observable_match": 1,
                                "observable_mismatch": 0,
                                "bounded_only": 0,
                                "without_coverage": 0,
                                "region_evidence_count": 1,
                            }
                        ],
                        "general_summary": {
                            "pass_count": 1,
                            "passes": ["InstructionSubstitution"],
                            "risky_pass_count": 0,
                            "clean_pass_count": 1,
                            "covered_pass_count": 0,
                            "uncovered_pass_count": 0,
                        },
                    },
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--only-pass",
            "InstructionSubstitution",
            "--summary-only",
            "--require-results",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["passes"] == ["InstructionSubstitution"])
    expect(payload["filtered_summary"]["normalized_pass_results"][0][MUTATION_NAME_KEY] == "InstructionSubstitution")
    expect(payload["filtered_summary"]["pass_symbolic_summary"]["InstructionSubstitution"]["severity"] == "clean")


def test_cli_report_handles_summary_general_pass_rows_only_minimal_report(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "schema_version": 1,
                    "report_views": {
                        "general_pass_rows": [
                            {
                                "pass_name": "InstructionSubstitution",
                                "severity": "clean",
                                "issue_count": 0,
                                "structural_issue_count": 0,
                                "symbolic_binary_mismatched_regions": 0,
                                "changed_region_count": 1,
                                "changed_bytes": 2,
                                "runtime_recommended": True,
                                "symbolic_recommended": True,
                                "symbolic_confidence": "best among stable passes",
                                "role": "requested-mode",
                                "symbolic_requested": 1,
                                "observable_match": 1,
                                "observable_mismatch": 0,
                                "bounded_only": 0,
                                "without_coverage": 0,
                                "region_evidence_count": 1,
                                "gate_failure_count": 0,
                                "strictest_expected_severity": "unknown",
                                "discarded_count": 0,
                                "discard_reasons": {},
                                "discard_impacts": {},
                            }
                        ],
                        "general_summary": {
                            "pass_count": 1,
                            "passes": ["InstructionSubstitution"],
                            "risky_pass_count": 0,
                            "clean_pass_count": 1,
                            "covered_pass_count": 0,
                            "uncovered_pass_count": 0,
                        },
                    },
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--only-pass",
            "InstructionSubstitution",
            "--summary-only",
            "--require-results",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["passes"] == ["InstructionSubstitution"])
    expect(payload["filtered_summary"]["normalized_pass_results"][0][MUTATION_NAME_KEY] == "InstructionSubstitution")
    expect(
        payload["filtered_summary"]["pass_capability_summary"][0]["symbolic_confidence"] == "best among stable passes"
    )
    expect(payload["filtered_summary"]["pass_evidence"][0]["changed_region_count"] == 1)


def test_cli_report_handles_summary_general_filter_views_without_schema_version(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "report_views": {
                        "general_filter_views": {
                            "risky": ["RegisterSubstitution"],
                            "structural_risk": [],
                            "symbolic_risk": ["RegisterSubstitution"],
                            "clean": [],
                            "covered": [],
                            "uncovered": [],
                        },
                        "general_pass_rows": [
                            {
                                "pass_name": "RegisterSubstitution",
                                "severity": "mismatch",
                                "issue_count": 1,
                                "structural_issue_count": 0,
                                "symbolic_binary_mismatched_regions": 1,
                                "changed_region_count": 1,
                                "changed_bytes": 2,
                                "runtime_recommended": True,
                                "symbolic_recommended": False,
                                "symbolic_confidence": "limited",
                                "role": "requested-mode",
                                "symbolic_requested": 1,
                                "observable_match": 0,
                                "observable_mismatch": 1,
                                "bounded_only": 0,
                                "without_coverage": 0,
                                "region_evidence_count": 1,
                                "gate_failure_count": 0,
                                "strictest_expected_severity": "unknown",
                                "discarded_count": 0,
                                "discard_reasons": {},
                                "discard_impacts": {},
                            }
                        ],
                        "general_summary": {
                            "pass_count": 1,
                            "passes": ["RegisterSubstitution"],
                            "risky_pass_count": 1,
                            "clean_pass_count": 0,
                            "covered_pass_count": 0,
                            "uncovered_pass_count": 0,
                        },
                        "general_triage_rows": [
                            {
                                "pass_name": "RegisterSubstitution",
                                "severity": "mismatch",
                                "issue_count": 1,
                                "structural_issue_count": 0,
                                "symbolic_binary_mismatched_regions": 1,
                                "changed_region_count": 1,
                                "changed_bytes": 2,
                            }
                        ],
                    }
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--only-risky-passes",
            "--summary-only",
            "--require-results",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["pass_risk_buckets"]["risky"] == ["RegisterSubstitution"])


def test_cli_report_handles_summary_general_filter_views_with_old_schema_version(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "schema_version": 0,
                    "report_views": {
                        "general_filter_views": {
                            "risky": [],
                            "structural_risk": [],
                            "symbolic_risk": [],
                            "clean": ["NopInsertion"],
                            "covered": [],
                            "uncovered": ["NopInsertion"],
                        },
                        "general_pass_rows": [
                            {
                                "pass_name": "NopInsertion",
                                "severity": "clean",
                                "issue_count": 0,
                                "structural_issue_count": 0,
                                "symbolic_binary_mismatched_regions": 0,
                                "changed_region_count": 1,
                                "changed_bytes": 1,
                                "runtime_recommended": True,
                                "symbolic_recommended": True,
                                "symbolic_confidence": "best among stable passes",
                                "role": "requested-mode",
                                "symbolic_requested": 0,
                                "observable_match": 0,
                                "observable_mismatch": 0,
                                "bounded_only": 0,
                                "without_coverage": 0,
                                "region_evidence_count": 0,
                                "gate_failure_count": 0,
                                "strictest_expected_severity": "unknown",
                                "discarded_count": 0,
                                "discard_reasons": {},
                                "discard_impacts": {},
                            }
                        ],
                        "general_summary": {
                            "pass_count": 1,
                            "passes": ["NopInsertion"],
                            "risky_pass_count": 0,
                            "clean_pass_count": 1,
                            "covered_pass_count": 0,
                            "uncovered_pass_count": 1,
                        },
                        "general_triage_rows": [
                            {
                                "pass_name": "NopInsertion",
                                "severity": "clean",
                                "issue_count": 0,
                                "structural_issue_count": 0,
                                "symbolic_binary_mismatched_regions": 0,
                                "changed_region_count": 1,
                                "changed_bytes": 1,
                            }
                        ],
                    },
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--only-clean-passes",
            "--summary-only",
            "--require-results",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["pass_risk_buckets"]["clean"] == ["NopInsertion"])


def test_cli_report_handles_summary_general_views_only_minimal_report(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "report_views": {
                        "general_passes": [
                            {
                                "pass_name": "RegisterSubstitution",
                                "severity": "mismatch",
                                "issue_count": 1,
                                "structural_issue_count": 0,
                                "symbolic_binary_mismatched_regions": 1,
                                "changed_region_count": 1,
                                "changed_bytes": 2,
                                "runtime_recommended": True,
                                "symbolic_recommended": False,
                                "symbolic_confidence": "limited",
                                "role": "requested-mode",
                                "symbolic_requested": 1,
                                "observable_match": 0,
                                "observable_mismatch": 1,
                                "bounded_only": 0,
                                "without_coverage": 0,
                                "region_evidence_count": 1,
                            }
                        ],
                        "general_summary": {
                            "pass_count": 1,
                            "passes": ["RegisterSubstitution"],
                            "risky_pass_count": 1,
                            "clean_pass_count": 0,
                            "covered_pass_count": 0,
                            "uncovered_pass_count": 0,
                        },
                        "general_symbolic": {
                            "overview": {
                                "symbolic_requested": 1,
                                "observable_match": 0,
                                "observable_mismatch": 1,
                                "bounded_only": 0,
                                "without_coverage": 0,
                            },
                            "triage_rows": [
                                {
                                    "pass_name": "RegisterSubstitution",
                                    "severity": "mismatch",
                                    "issue_count": 1,
                                    "symbolic_requested": 1,
                                    "observable_mismatch": 1,
                                    "without_coverage": 0,
                                    "bounded_only": 0,
                                }
                            ],
                        },
                        "general_gates": {
                            "summary": {
                                "require_pass_severity_failed": False,
                                "require_pass_severity_failure_count": 0,
                            }
                        },
                        "general_degradation": {
                            "summary": {
                                "requested_validation_mode": "symbolic",
                                "effective_validation_mode": "symbolic",
                                "degraded_validation": False,
                                "row_count": 0,
                                "passes": [],
                                "gate_failure_count": 0,
                            }
                        },
                        "general_discards": {
                            "summary": {
                                "count": 0,
                                "passes": [],
                                "reasons": {},
                                "impacts": {"high": 0, "medium": 0, "low": 0},
                            },
                            "rows": [],
                        },
                    }
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--summary-only",
            "--require-results",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["symbolic_requested"] == 1)
    expect(payload["filtered_summary"]["observable_mismatch"] == 1)
    expect(payload["filtered_summary"]["general_summary"]["pass_count"] == 1)
    expect(payload["filtered_summary"]["general_symbolic"]["overview"]["observable_mismatch"] == 1)
    expect(not (payload["filtered_summary"]["general_gates"]["summary"]["require_pass_severity_failed"] is not False))
    expect(not (payload["filtered_summary"]["general_degradation"]["summary"]["degraded_validation"] is not False))
    expect(payload["filtered_summary"]["general_discards"]["summary"]["count"] == 0)
    expect(not (payload["filtered_summary"]["validation_adjustments"]["degraded_validation"] is not False))
    expect(payload["filtered_summary"]["discarded_mutation_compact_summary"]["count"] == 0)


def test_cli_report_handles_summary_general_renderer_state_only_minimal_report(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "schema_version": 1,
                    "report_views": {
                        "general_renderer_state": {
                            "summary": {
                                "pass_count": 1,
                                "passes": ["InstructionSubstitution"],
                                "risky_pass_count": 0,
                                "clean_pass_count": 1,
                                "covered_pass_count": 0,
                                "uncovered_pass_count": 0,
                            },
                            "symbolic": {
                                "symbolic_requested": 1,
                                "observable_match": 1,
                                "observable_mismatch": 0,
                                "bounded_only": 0,
                                "without_coverage": 0,
                            },
                            "gates": {
                                "failed": False,
                                "failure_count": 0,
                                "pass_count": 0,
                                "expected_severity_counts": {},
                                "severity_priority": [],
                                "passes": [],
                            },
                            "degradation": {
                                "requested_validation_mode": "symbolic",
                                "effective_validation_mode": "symbolic",
                                "degraded_validation": False,
                                "row_count": 0,
                                "passes": [],
                                "gate_failure_count": 0,
                            },
                            "discards": {
                                "count": 0,
                                "passes": [],
                                "reasons": {},
                                "impacts": {"high": 0, "medium": 0, "low": 0},
                            },
                            "passes": [
                                {
                                    "pass_name": "InstructionSubstitution",
                                    "severity": "clean",
                                    "issue_count": 0,
                                    "structural_issue_count": 0,
                                    "symbolic_binary_mismatched_regions": 0,
                                    "changed_region_count": 1,
                                    "changed_bytes": 2,
                                    "runtime_recommended": True,
                                    "symbolic_recommended": True,
                                    "symbolic_confidence": "best among stable passes",
                                    "role": "requested-mode",
                                    "symbolic_requested": 1,
                                    "observable_match": 1,
                                    "observable_mismatch": 0,
                                    "bounded_only": 0,
                                    "without_coverage": 0,
                                    "region_evidence_count": 1,
                                    "gate_failure_count": 0,
                                    "strictest_expected_severity": "unknown",
                                    "discarded_count": 0,
                                    "discard_reasons": {},
                                    "discard_impacts": {},
                                }
                            ],
                            "triage_rows": [
                                {
                                    "pass_name": "InstructionSubstitution",
                                    "severity": "clean",
                                    "issue_count": 0,
                                    "structural_issue_count": 0,
                                    "symbolic_binary_mismatched_regions": 0,
                                    "changed_region_count": 1,
                                    "changed_bytes": 2,
                                }
                            ],
                        }
                    },
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--summary-only",
            "--require-results",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["general_renderer_state"]["summary"]["pass_count"] == 1)
    expect(payload["filtered_summary"]["symbolic_requested"] == 1)
    expect(payload["filtered_summary"]["general_summary"]["passes"] == ["InstructionSubstitution"])


def test_cli_report_handles_summary_general_renderer_state_general_sections_only_minimal_report(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "schema_version": 1,
                    "report_views": {
                        "general_renderer_state": {
                            "general_summary": {
                                "pass_count": 1,
                                "passes": ["InstructionSubstitution"],
                                "risky_pass_count": 0,
                                "clean_pass_count": 1,
                                "covered_pass_count": 0,
                                "uncovered_pass_count": 0,
                            },
                            "general_symbolic": {
                                "symbolic_requested": 1,
                                "observable_match": 1,
                                "observable_mismatch": 0,
                                "bounded_only": 0,
                                "without_coverage": 0,
                            },
                            "general_gates": {
                                "failed": False,
                                "failure_count": 0,
                                "pass_count": 0,
                                "expected_severity_counts": {},
                                "severity_priority": [],
                                "passes": [],
                            },
                            "general_degradation": {
                                "requested_validation_mode": "symbolic",
                                "effective_validation_mode": "symbolic",
                                "degraded_validation": False,
                                "row_count": 0,
                                "passes": [],
                                "gate_failure_count": 0,
                            },
                            "general_discards": {
                                "count": 0,
                                "passes": [],
                                "reasons": {},
                                "impacts": {"high": 0, "medium": 0, "low": 0},
                            },
                            "pass_rows": [
                                {
                                    "pass_name": "InstructionSubstitution",
                                    "severity": "clean",
                                    "issue_count": 0,
                                    "structural_issue_count": 0,
                                    "symbolic_binary_mismatched_regions": 0,
                                    "changed_region_count": 1,
                                    "changed_bytes": 2,
                                    "runtime_recommended": True,
                                    "symbolic_recommended": True,
                                    "symbolic_confidence": "best among stable passes",
                                    "role": "requested-mode",
                                    "symbolic_requested": 1,
                                    "observable_match": 1,
                                    "observable_mismatch": 0,
                                    "bounded_only": 0,
                                    "without_coverage": 0,
                                    "region_evidence_count": 1,
                                    "gate_failure_count": 0,
                                    "strictest_expected_severity": "unknown",
                                    "discarded_count": 0,
                                    "discard_reasons": {},
                                    "discard_impacts": {},
                                }
                            ],
                            "triage_rows": [
                                {
                                    "pass_name": "InstructionSubstitution",
                                    "severity": "clean",
                                    "issue_count": 0,
                                    "structural_issue_count": 0,
                                    "symbolic_binary_mismatched_regions": 0,
                                    "changed_region_count": 1,
                                    "changed_bytes": 2,
                                }
                            ],
                        }
                    },
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--summary-only",
            "--require-results",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["general_summary"]["passes"] == ["InstructionSubstitution"])
    expect(payload["filtered_summary"]["general_symbolic"]["overview"]["symbolic_requested"] == 1)
    expect(payload["filtered_summary"]["general_degradation"]["summary"]["effective_validation_mode"] == "symbolic")


def test_cli_report_uses_general_renderer_sections_for_gate_and_degradation_payloads(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "schema_version": 1,
                    "report_views": {
                        "general_renderer_state": {
                            "general_summary": {
                                "pass_count": 1,
                                "passes": ["InstructionSubstitution"],
                                "risky_pass_count": 0,
                                "clean_pass_count": 1,
                                "covered_pass_count": 0,
                                "uncovered_pass_count": 0,
                            },
                            "general_gates": {
                                "failed": True,
                                "failure_count": 2,
                                "pass_count": 1,
                                "expected_severity_counts": {"clean": 2},
                                "severity_priority": [{"severity": "clean", "failure_count": 2}],
                                "passes": ["InstructionSubstitution"],
                            },
                            "general_degradation": {
                                "requested_validation_mode": "symbolic",
                                "effective_validation_mode": "runtime",
                                "degraded_validation": True,
                                "row_count": 1,
                                "passes": ["InstructionSubstitution"],
                                "gate_failure_count": 2,
                            },
                            "general_discards": {
                                "count": 1,
                                "passes": ["InstructionSubstitution"],
                                "reasons": {"runtime_validation_failed": 1},
                                "impacts": {"high": 1, "medium": 0, "low": 0},
                            },
                            "general_pass_rows": [
                                {
                                    "pass_name": "InstructionSubstitution",
                                    "severity": "clean",
                                    "issue_count": 0,
                                    "structural_issue_count": 0,
                                    "symbolic_binary_mismatched_regions": 0,
                                    "changed_region_count": 1,
                                    "changed_bytes": 2,
                                    "runtime_recommended": True,
                                    "symbolic_recommended": True,
                                    "symbolic_confidence": "best among stable passes",
                                    "role": "requested-mode",
                                    "symbolic_requested": 1,
                                    "observable_match": 1,
                                    "observable_mismatch": 0,
                                    "bounded_only": 0,
                                    "without_coverage": 0,
                                    "region_evidence_count": 1,
                                    "gate_failure_count": 2,
                                    "strictest_expected_severity": "clean",
                                    "discarded_count": 1,
                                    "discard_reasons": {"runtime_validation_failed": 1},
                                    "discard_impacts": {"high": 1},
                                }
                            ],
                        }
                    },
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--summary-only",
            "--require-results",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(not (payload["filtered_summary"]["gate_failure_compact_summary"]["failed"] is not True))
    expect(
        payload["filtered_summary"]["gate_failure_compact_summary"]["failure_count"]
        == _EXPECTED_PAYLOAD_FILTERED_SUMMARY_GATE_FAILURE_COMPACT_2
    )
    expect(payload["filtered_summary"]["validation_adjustment_summary"]["effective_validation_mode"] == "runtime")
    expect(payload["filtered_summary"]["discarded_mutation_compact_summary"]["count"] == 1)


def test_cli_report_handles_summary_general_renderer_state_general_passes_only_minimal_report(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "schema_version": 1,
                    "report_views": {
                        "general_renderer_state": {
                            "general_summary": {
                                "pass_count": 1,
                                "passes": ["InstructionSubstitution"],
                                "risky_pass_count": 0,
                                "clean_pass_count": 1,
                                "covered_pass_count": 0,
                                "uncovered_pass_count": 0,
                            },
                            "general_passes": [
                                {
                                    "pass_name": "InstructionSubstitution",
                                    "severity": "clean",
                                    "issue_count": 0,
                                    "structural_issue_count": 0,
                                    "symbolic_binary_mismatched_regions": 0,
                                    "changed_region_count": 1,
                                    "changed_bytes": 2,
                                    "runtime_recommended": True,
                                    "symbolic_recommended": True,
                                    "symbolic_confidence": "best among stable passes",
                                    "role": "requested-mode",
                                    "symbolic_requested": 1,
                                    "observable_match": 1,
                                    "observable_mismatch": 0,
                                    "bounded_only": 0,
                                    "without_coverage": 0,
                                    "region_evidence_count": 1,
                                    "gate_failure_count": 0,
                                    "strictest_expected_severity": "unknown",
                                    "discarded_count": 0,
                                    "discard_reasons": {},
                                    "discard_impacts": {},
                                }
                            ],
                        }
                    },
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--only-pass",
            "InstructionSubstitution",
            "--summary-only",
            "--require-results",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["passes"] == ["InstructionSubstitution"])
    expect(payload["filtered_summary"]["general_summary"]["passes"] == ["InstructionSubstitution"])


def test_cli_report_handles_summary_general_renderer_state_summary_rows_only_minimal_report(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "schema_version": 1,
                    "report_views": {
                        "general_renderer_state": {
                            "summary_rows": [
                                {
                                    "section": "passes",
                                    "pass_count": 1,
                                    "passes": ["InstructionSubstitution"],
                                    "risky_pass_count": 0,
                                    "clean_pass_count": 1,
                                    "covered_pass_count": 0,
                                    "uncovered_pass_count": 0,
                                },
                                {
                                    "section": "symbolic",
                                    "symbolic_requested": 1,
                                    "observable_match": 1,
                                    "observable_mismatch": 0,
                                    "bounded_only": 0,
                                    "without_coverage": 0,
                                },
                                {
                                    "section": "gates",
                                    "failed": False,
                                    "failure_count": 0,
                                    "pass_count": 0,
                                    "expected_severity_counts": {},
                                    "severity_priority": [],
                                    "passes": [],
                                },
                                {
                                    "section": "degradation",
                                    "requested_validation_mode": "symbolic",
                                    "effective_validation_mode": "symbolic",
                                    "degraded_validation": False,
                                    "row_count": 0,
                                    "passes": [],
                                    "gate_failure_count": 0,
                                },
                                {
                                    "section": "discards",
                                    "count": 0,
                                    "passes": [],
                                    "reasons": {},
                                    "impacts": {"high": 0, "medium": 0, "low": 0},
                                },
                            ],
                            "passes": [
                                {
                                    "pass_name": "InstructionSubstitution",
                                    "severity": "clean",
                                    "issue_count": 0,
                                    "structural_issue_count": 0,
                                    "symbolic_binary_mismatched_regions": 0,
                                    "changed_region_count": 1,
                                    "changed_bytes": 2,
                                    "runtime_recommended": True,
                                    "symbolic_recommended": True,
                                    "symbolic_confidence": "best among stable passes",
                                    "role": "requested-mode",
                                    "symbolic_requested": 1,
                                    "observable_match": 1,
                                    "observable_mismatch": 0,
                                    "bounded_only": 0,
                                    "without_coverage": 0,
                                    "region_evidence_count": 1,
                                    "gate_failure_count": 0,
                                    "strictest_expected_severity": "unknown",
                                    "discarded_count": 0,
                                    "discard_reasons": {},
                                    "discard_impacts": {},
                                }
                            ],
                            "triage_rows": [
                                {
                                    "pass_name": "InstructionSubstitution",
                                    "severity": "clean",
                                    "issue_count": 0,
                                    "structural_issue_count": 0,
                                    "symbolic_binary_mismatched_regions": 0,
                                    "changed_region_count": 1,
                                    "changed_bytes": 2,
                                }
                            ],
                        }
                    },
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--summary-only",
            "--require-results",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["general_summary_rows"][0]["section"] == "passes")
    expect(payload["filtered_summary"]["general_summary"]["passes"] == ["InstructionSubstitution"])
    expect(payload["filtered_summary"]["symbolic_requested"] == 1)


def test_cli_report_handles_summary_general_renderer_state_filter_views_only_minimal_report(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "schema_version": 1,
                    "report_views": {
                        "general_renderer_state": {
                            "summary": {
                                "pass_count": 1,
                                "passes": ["RegisterSubstitution"],
                                "risky_pass_count": 1,
                                "clean_pass_count": 0,
                                "covered_pass_count": 0,
                                "uncovered_pass_count": 0,
                            },
                            "symbolic": {
                                "symbolic_requested": 1,
                                "observable_match": 0,
                                "observable_mismatch": 1,
                                "bounded_only": 0,
                                "without_coverage": 0,
                            },
                            "gates": {
                                "failed": False,
                                "failure_count": 0,
                                "pass_count": 0,
                                "expected_severity_counts": {},
                                "severity_priority": [],
                                "passes": [],
                            },
                            "degradation": {
                                "requested_validation_mode": "symbolic",
                                "effective_validation_mode": "symbolic",
                                "degraded_validation": False,
                                "row_count": 0,
                                "passes": [],
                                "gate_failure_count": 0,
                            },
                            "discards": {
                                "count": 0,
                                "passes": [],
                                "reasons": {},
                                "impacts": {"high": 0, "medium": 0, "low": 0},
                            },
                            "filter_views": {
                                "risky": ["RegisterSubstitution"],
                                "structural_risk": [],
                                "symbolic_risk": ["RegisterSubstitution"],
                                "clean": [],
                                "covered": [],
                                "uncovered": [],
                            },
                            "passes": [
                                {
                                    "pass_name": "RegisterSubstitution",
                                    "severity": "mismatch",
                                    "issue_count": 1,
                                    "structural_issue_count": 0,
                                    "symbolic_binary_mismatched_regions": 1,
                                    "changed_region_count": 1,
                                    "changed_bytes": 2,
                                    "runtime_recommended": True,
                                    "symbolic_recommended": False,
                                    "symbolic_confidence": "limited",
                                    "role": "requested-mode",
                                    "symbolic_requested": 1,
                                    "observable_match": 0,
                                    "observable_mismatch": 1,
                                    "bounded_only": 0,
                                    "without_coverage": 0,
                                    "region_evidence_count": 1,
                                    "gate_failure_count": 0,
                                    "strictest_expected_severity": "unknown",
                                    "discarded_count": 0,
                                    "discard_reasons": {},
                                    "discard_impacts": {},
                                }
                            ],
                            "triage_rows": [
                                {
                                    "pass_name": "RegisterSubstitution",
                                    "severity": "mismatch",
                                    "issue_count": 1,
                                    "structural_issue_count": 0,
                                    "symbolic_binary_mismatched_regions": 1,
                                    "changed_region_count": 1,
                                    "changed_bytes": 2,
                                }
                            ],
                        }
                    },
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--only-risky-passes",
            "--summary-only",
            "--require-results",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["risky_passes"] == ["RegisterSubstitution"])
    expect(payload["filtered_summary"]["pass_risk_buckets"]["risky"] == ["RegisterSubstitution"])


def test_cli_report_handles_summary_general_renderer_state_general_filter_views_only_minimal_report(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "schema_version": 1,
                    "report_views": {
                        "general_renderer_state": {
                            "general_summary": {
                                "pass_count": 1,
                                "passes": ["RegisterSubstitution"],
                                "risky_pass_count": 1,
                                "clean_pass_count": 0,
                                "covered_pass_count": 0,
                                "uncovered_pass_count": 0,
                            },
                            "general_symbolic": {
                                "symbolic_requested": 1,
                                "observable_match": 0,
                                "observable_mismatch": 1,
                                "bounded_only": 0,
                                "without_coverage": 0,
                            },
                            "general_gates": {
                                "failed": False,
                                "failure_count": 0,
                                "pass_count": 0,
                                "expected_severity_counts": {},
                                "severity_priority": [],
                                "passes": [],
                            },
                            "general_degradation": {
                                "requested_validation_mode": "symbolic",
                                "effective_validation_mode": "symbolic",
                                "degraded_validation": False,
                                "row_count": 0,
                                "passes": [],
                                "gate_failure_count": 0,
                            },
                            "general_discards": {
                                "count": 0,
                                "passes": [],
                                "reasons": {},
                                "impacts": {"high": 0, "medium": 0, "low": 0},
                            },
                            "general_filter_views": {
                                "risky": ["RegisterSubstitution"],
                                "structural_risk": [],
                                "symbolic_risk": ["RegisterSubstitution"],
                                "clean": [],
                                "covered": [],
                                "uncovered": [],
                            },
                            "general_pass_rows": [
                                {
                                    "pass_name": "RegisterSubstitution",
                                    "severity": "mismatch",
                                    "issue_count": 1,
                                    "structural_issue_count": 0,
                                    "symbolic_binary_mismatched_regions": 1,
                                    "changed_region_count": 1,
                                    "changed_bytes": 2,
                                    "runtime_recommended": True,
                                    "symbolic_recommended": False,
                                    "symbolic_confidence": "limited",
                                    "role": "requested-mode",
                                    "symbolic_requested": 1,
                                    "observable_match": 0,
                                    "observable_mismatch": 1,
                                    "bounded_only": 0,
                                    "without_coverage": 0,
                                    "region_evidence_count": 1,
                                    "gate_failure_count": 0,
                                    "strictest_expected_severity": "unknown",
                                    "discarded_count": 0,
                                    "discard_reasons": {},
                                    "discard_impacts": {},
                                }
                            ],
                            "general_triage_rows": [
                                {
                                    "pass_name": "RegisterSubstitution",
                                    "severity": "mismatch",
                                    "issue_count": 1,
                                    "structural_issue_count": 0,
                                    "symbolic_binary_mismatched_regions": 1,
                                    "changed_region_count": 1,
                                    "changed_bytes": 2,
                                }
                            ],
                        }
                    },
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--only-risky-passes",
            "--summary-only",
            "--require-results",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["risky_passes"] == ["RegisterSubstitution"])
    expect(payload["filtered_summary"]["passes"] == ["RegisterSubstitution"])
    expect(payload["filtered_summary"]["pass_risk_buckets"]["risky"] == ["RegisterSubstitution"])


def test_cli_report_handles_summary_general_renderer_state_general_pass_rows_only_minimal_report(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "schema_version": 1,
                    "report_views": {
                        "general_renderer_state": {
                            "general_summary": {
                                "pass_count": 1,
                                "passes": ["InstructionSubstitution"],
                                "risky_pass_count": 0,
                                "clean_pass_count": 1,
                                "covered_pass_count": 0,
                                "uncovered_pass_count": 0,
                            },
                            "general_pass_rows": [
                                {
                                    "pass_name": "InstructionSubstitution",
                                    "severity": "clean",
                                    "issue_count": 0,
                                    "structural_issue_count": 0,
                                    "symbolic_binary_mismatched_regions": 0,
                                    "changed_region_count": 1,
                                    "changed_bytes": 2,
                                    "runtime_recommended": True,
                                    "symbolic_recommended": True,
                                    "symbolic_confidence": "best among stable passes",
                                    "role": "requested-mode",
                                    "symbolic_requested": 1,
                                    "observable_match": 1,
                                    "observable_mismatch": 0,
                                    "bounded_only": 0,
                                    "without_coverage": 0,
                                    "region_evidence_count": 1,
                                    "gate_failure_count": 0,
                                    "strictest_expected_severity": "unknown",
                                    "discarded_count": 0,
                                    "discard_reasons": {},
                                    "discard_impacts": {},
                                }
                            ],
                        }
                    },
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--only-pass",
            "InstructionSubstitution",
            "--summary-only",
            "--require-results",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["passes"] == ["InstructionSubstitution"])
    expect(payload["filtered_summary"]["normalized_pass_results"][0][MUTATION_NAME_KEY] == "InstructionSubstitution")


def test_cli_report_handles_summary_general_summary_rows_only_minimal_report(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "schema_version": 1,
                    "report_views": {
                        "general_summary_rows": [
                            {
                                "section": "passes",
                                "pass_count": 1,
                                "passes": ["InstructionSubstitution"],
                                "risky_pass_count": 0,
                                "clean_pass_count": 1,
                                "covered_pass_count": 0,
                                "uncovered_pass_count": 0,
                            },
                            {
                                "section": "symbolic",
                                "symbolic_requested": 1,
                                "observable_match": 1,
                                "observable_mismatch": 0,
                                "bounded_only": 0,
                                "without_coverage": 0,
                            },
                            {
                                "section": "gates",
                                "failed": False,
                                "failure_count": 0,
                                "pass_count": 0,
                                "expected_severity_counts": {},
                                "severity_priority": [],
                                "passes": [],
                            },
                            {
                                "section": "degradation",
                                "requested_validation_mode": "symbolic",
                                "effective_validation_mode": "symbolic",
                                "degraded_validation": False,
                                "row_count": 0,
                                "passes": [],
                                "gate_failure_count": 0,
                            },
                            {
                                "section": "discards",
                                "count": 0,
                                "passes": [],
                                "reasons": {},
                                "impacts": {"high": 0, "medium": 0, "low": 0},
                            },
                        ],
                        "general_pass_rows": [
                            {
                                "pass_name": "InstructionSubstitution",
                                "severity": "clean",
                                "issue_count": 0,
                                "structural_issue_count": 0,
                                "symbolic_binary_mismatched_regions": 0,
                                "changed_region_count": 1,
                                "changed_bytes": 2,
                                "runtime_recommended": True,
                                "symbolic_recommended": True,
                                "symbolic_confidence": "best among stable passes",
                                "role": "requested-mode",
                                "symbolic_requested": 1,
                                "observable_match": 1,
                                "observable_mismatch": 0,
                                "bounded_only": 0,
                                "without_coverage": 0,
                                "region_evidence_count": 1,
                                "gate_failure_count": 0,
                                "strictest_expected_severity": "unknown",
                                "discarded_count": 0,
                                "discard_reasons": {},
                                "discard_impacts": {},
                            }
                        ],
                    },
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--summary-only",
            "--require-results",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["general_summary"]["pass_count"] == 1)
    expect(payload["filtered_summary"]["general_symbolic"]["overview"]["symbolic_requested"] == 1)
    expect(not (payload["filtered_summary"]["general_gates"]["compact_summary"]["failed"] is not False))
    expect(not (payload["filtered_summary"]["general_degradation"]["summary"]["degraded_validation"] is not False))
    expect(payload["filtered_summary"]["general_discards"]["summary"]["count"] == 0)


def test_cli_report_handles_summary_pass_region_evidence_only_minimal_report(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "report_views": {
                        "only_pass": {
                            "InstructionSubstitution": {
                                "normalized": {
                                    "pass_name": "InstructionSubstitution",
                                    "severity": "mismatch",
                                    "symbolic_requested": 1,
                                    "observable_mismatch": 1,
                                },
                                "symbolic_summary": {
                                    "pass_name": "InstructionSubstitution",
                                    "severity": "mismatch",
                                    "issue_count": 1,
                                    "symbolic_requested": 1,
                                    "observable_mismatch": 1,
                                    "issues": [],
                                },
                            }
                        }
                    },
                    "pass_region_evidence_map": {
                        "InstructionSubstitution": [
                            {
                                "address_range": [4198400, 4198402],
                                "region_exit_equivalent": False,
                                "original_region_exit_address": 4198402,
                                "mutated_region_exit_address": 4198403,
                                "original_trace_length": 2,
                                "mutated_trace_length": 3,
                                "mismatch_count": 1,
                            }
                        ]
                    },
                }
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        ["report", str(report_path), "--only-pass", "InstructionSubstitution"],
    )

    expect(result.exit_code == 0)
    expect(not ("Pass Region Evidence" not in result.output))
    expect(not ("InstructionSubstitution" not in result.output))
    expect(not ("equivalent=false" not in result.output))
    expect(not ("mismatch_count=1" not in result.output))


def test_cli_report_handles_summary_only_failed_gates_minimal_report_without_passes(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "report_views": {
                        "only_failed_gates": {
                            "priority": [],
                            "by_pass": {},
                            "grouped_by_pass": [],
                            "summary": {
                                "all_passed": False,
                                "min_severity_failed": True,
                                "min_severity": "clean",
                                "require_pass_severity_failed": False,
                                "require_pass_severity_failure_count": 0,
                                "require_pass_severity_failures": [],
                                "require_pass_severity_failures_by_pass": {},
                                "require_pass_severity_failures_by_expected_severity": {},
                            },
                            "severity_priority": [],
                            "expected_severity_counts": {},
                            "failed": True,
                            "failure_count": 0,
                            "pass_count": 0,
                            "passes": [],
                        }
                    }
                },
                "gate_evaluation": {
                    "requested": {"min_severity": "clean"},
                    "results": {"all_passed": False, "min_severity_passed": False},
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            str(report_path),
            "--only-failed-gates",
            "--require-results",
            "--output",
            str(output_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(not (payload["filtered_summary"]["failed_gates"] is not True))
    expect(not (payload["filtered_summary"]["gate_failures"]["min_severity_failed"] is not True))
    expect(not (payload["filtered_summary"]["gate_failure_compact_summary"]["failed"] is not True))


def test_cli_report_only_pass_prefers_report_view_without_pass_results(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "report_views": {
                        "only_pass": {
                            "InstructionSubstitution": {
                                "normalized": {
                                    "pass_name": "InstructionSubstitution",
                                    "severity": "clean",
                                    "issue_count": 0,
                                    "symbolic_requested": 1,
                                    "observable_match": 1,
                                    "observable_mismatch": 0,
                                    "bounded_only": 0,
                                    "without_coverage": 0,
                                    "changed_region_count": 1,
                                    "changed_bytes": 2,
                                    "structural_issue_count": 0,
                                    "symbolic_binary_mismatched_regions": 0,
                                    "role": "requested-mode",
                                    "runtime_recommended": True,
                                    "symbolic_recommended": True,
                                    "symbolic_confidence": "best among stable passes",
                                },
                                "symbolic_summary": {
                                    "pass_name": "InstructionSubstitution",
                                    "severity": "clean",
                                    "issue_count": 0,
                                    "symbolic_requested": 1,
                                    "observable_match": 1,
                                    "observable_mismatch": 0,
                                    "bounded_only": 0,
                                    "without_coverage": 0,
                                },
                                "evidence": {
                                    "pass_name": "InstructionSubstitution",
                                    "changed_region_count": 1,
                                    "changed_bytes": 2,
                                    "structural_issue_count": 0,
                                    "symbolic_binary_mismatched_regions": 0,
                                },
                                "region_evidence": [
                                    {
                                        "start_address": 4198400,
                                        "end_address": 4198401,
                                        "equivalent": True,
                                        "mismatch_count": 0,
                                        "mismatches": [],
                                        "step_strategy": "region-exit",
                                        "original_trace_length": 2,
                                        "mutated_trace_length": 2,
                                    }
                                ],
                                "validation_context": {
                                    "role": "requested-mode",
                                    "requested_validation_mode": "symbolic",
                                    "effective_validation_mode": "symbolic",
                                    "degraded_execution": False,
                                    "degradation_triggered_by_pass": False,
                                },
                                "capabilities": {
                                    "pass_name": "InstructionSubstitution",
                                    "runtime_recommended": True,
                                    "symbolic_recommended": True,
                                    "symbolic_confidence": "best among stable passes",
                                },
                            }
                        }
                    },
                    "normalized_pass_results": [
                        {
                            "pass_name": "InstructionSubstitution",
                            "severity": "clean",
                            "issue_count": 0,
                            "symbolic_requested": 1,
                            "observable_match": 1,
                            "observable_mismatch": 0,
                            "bounded_only": 0,
                            "without_coverage": 0,
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_mismatched_regions": 0,
                            "runtime_recommended": True,
                            "symbolic_recommended": True,
                            "symbolic_confidence": "best among stable passes",
                            "role": "requested-mode",
                        }
                    ],
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--only-pass",
            "InstructionSubstitution",
            "--summary-only",
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    expect(not ("Pass Symbolic Summary" not in result.output))
    expect(not ("Pass Evidence Summary" not in result.output))
    expect(not ("Pass Region Evidence" not in result.output))
    expect(not ("Pass Validation Context" not in result.output))
    expect(not ("Pass Capabilities" not in result.output))


def test_cli_report_only_failed_gates_prefers_report_view_without_pass_results(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "failed-gates.report.json"
    output_path = tmp_path / "failed-gates.filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "report_views": {
                        "only_failed_gates": {
                            "priority": [
                                {
                                    "pass_name": "NopInsertion",
                                    "failure_count": 1,
                                    "strictest_expected_severity": "clean",
                                    "role": "requested-mode",
                                    "failures": ["NopInsertion=not-requested(expected <= clean)"],
                                }
                            ],
                            "by_pass": {
                                "NopInsertion": {
                                    "pass_name": "NopInsertion",
                                    "failure_count": 1,
                                    "strictest_expected_severity": "clean",
                                    "role": "requested-mode",
                                    "failures": ["NopInsertion=not-requested(expected <= clean)"],
                                }
                            },
                            "summary": {
                                "all_passed": False,
                                "min_severity_failed": False,
                                "min_severity": None,
                                "require_pass_severity_failed": True,
                                "require_pass_severity_failure_count": 1,
                                "require_pass_severity_failures": ["NopInsertion=not-requested(expected <= clean)"],
                                "require_pass_severity_failures_by_pass": {
                                    "NopInsertion": ["NopInsertion=not-requested(expected <= clean)"]
                                },
                                "require_pass_severity_failures_by_expected_severity": {"clean": 1},
                            },
                            "severity_priority": [{"severity": "clean", "failure_count": 1}],
                            "final_rows": [
                                {
                                    "pass_name": "NopInsertion",
                                    "failure_count": 1,
                                    "strictest_expected_severity": "clean",
                                    "role": "requested-mode",
                                    "failed": True,
                                }
                            ],
                            "final_by_pass": {
                                "NopInsertion": {
                                    "pass_name": "NopInsertion",
                                    "failure_count": 1,
                                    "strictest_expected_severity": "clean",
                                    "role": "requested-mode",
                                    "failed": True,
                                    "failures": ["NopInsertion=not-requested(expected <= clean)"],
                                }
                            },
                            "failed": True,
                            "failure_count": 1,
                        }
                    }
                },
                "gate_evaluation": {
                    "requested": {"require_pass_severity": [{"pass_name": "NopInsertion", "max_severity": "clean"}]},
                    "results": {
                        "all_passed": False,
                        "require_pass_severity_passed": False,
                        "require_pass_severity_failures": ["NopInsertion=not-requested(expected <= clean)"],
                    },
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            str(report_path),
            "--only-failed-gates",
            "--summary-only",
            "--require-results",
            "--output",
            str(output_path),
        ],
    )

    expect(result.exit_code == 0)
    expect(not ("Gate Failure Summary" not in result.output))
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["gate_failures"]["require_pass_severity_failure_count"] == 1)
    expect(payload["filtered_summary"]["gate_failure_priority"][0][MUTATION_NAME_KEY] == "NopInsertion")
    expect(payload["filtered_summary"]["gate_failure_severity_priority"] == [{"severity": "clean", "failure_count": 1}])
    expect(not (payload["filtered_summary"]["gate_failure_compact_summary"]["failed"] is not True))
    expect(
        payload["filtered_summary"]["gate_failure_compact_summary"]["severity_priority"]
        == [{"severity": "clean", "failure_count": 1}]
    )
    expect(
        payload["filtered_summary"]["gate_failure_final_by_pass"]["NopInsertion"]["failures"]
        == ["NopInsertion=not-requested(expected <= clean)"]
    )
    expect(payload["filtered_summary"]["gate_failure_final_rows"][0][MUTATION_NAME_KEY] == "NopInsertion")
    expect(
        payload["filtered_summary"]["gate_failure_final_rows"][0]["failures"]
        == ["NopInsertion=not-requested(expected <= clean)"]
    )


def test_cli_report_only_mismatches_prefers_persisted_report_view(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "report_views": {
                        "only_mismatches": {
                            "priority": [
                                {
                                    "pass_name": "RegisterSubstitution",
                                    "mismatch_count": 2,
                                    "observables": ["rax", "rflags"],
                                    "severity": "mismatch",
                                    "issue_count": 2,
                                    "symbolic_requested": 2,
                                    "role": "requested-mode",
                                    "symbolic_confidence": "limited",
                                }
                            ],
                            "by_pass": {
                                "RegisterSubstitution": {
                                    "pass_name": "RegisterSubstitution",
                                    "mismatch_count": 2,
                                    "observables": ["rax", "rflags"],
                                    "severity": "mismatch",
                                    "issue_count": 2,
                                    "symbolic_requested": 2,
                                    "role": "requested-mode",
                                    "symbolic_confidence": "limited",
                                    "degraded_execution": False,
                                    "degradation_triggered_by_pass": False,
                                    "region_evidence": [],
                                    "region_count": 0,
                                    "region_mismatch_count": 0,
                                    "region_exit_match_count": 0,
                                }
                            },
                            "rows": [
                                {
                                    "pass_name": "RegisterSubstitution",
                                    "mismatch_count": 2,
                                    "observables": ["rax", "rflags"],
                                    "severity": "mismatch",
                                    "issue_count": 2,
                                    "symbolic_requested": 2,
                                    "role": "requested-mode",
                                    "symbolic_confidence": "limited",
                                }
                            ],
                            "compact_rows": [
                                {
                                    "pass_name": "RegisterSubstitution",
                                    "mismatch_count": 2,
                                    "severity": "mismatch",
                                    "role": "requested-mode",
                                    "symbolic_confidence": "limited",
                                    "degraded_execution": False,
                                    "region_count": 0,
                                    "region_mismatch_count": 0,
                                    "region_exit_match_count": 0,
                                    "compact_region": {
                                        "region_count": 0,
                                        "region_mismatch_count": 0,
                                        "region_exit_match_count": 0,
                                    },
                                }
                            ],
                            "final_rows": [
                                {
                                    "pass_name": "RegisterSubstitution",
                                    "mismatch_count": 2,
                                    "severity": "mismatch",
                                    "role": "requested-mode",
                                    "symbolic_confidence": "limited",
                                    "degraded_execution": False,
                                    "region_count": 0,
                                    "region_mismatch_count": 0,
                                    "region_exit_match_count": 0,
                                }
                            ],
                            "final_by_pass": {
                                "RegisterSubstitution": {
                                    "pass_name": "RegisterSubstitution",
                                    "mismatch_count": 2,
                                    "severity": "mismatch",
                                    "role": "requested-mode",
                                    "symbolic_confidence": "limited",
                                    "degraded_execution": False,
                                    "region_count": 0,
                                    "region_mismatch_count": 0,
                                    "region_exit_match_count": 0,
                                    "compact_region": {
                                        "region_count": 0,
                                        "region_mismatch_count": 0,
                                        "region_exit_match_count": 0,
                                    },
                                }
                            },
                            "summary": {
                                "pass_count": 1,
                                "mismatch_count": 2,
                                "region_count": 0,
                                "region_mismatch_count": 0,
                                "region_exit_match_count": 0,
                                "passes": ["RegisterSubstitution"],
                            },
                        },
                        "mismatch_priority": [
                            {
                                "pass_name": "RegisterSubstitution",
                                "mismatch_count": 2,
                                "observables": ["rax", "rflags"],
                                "severity": "mismatch",
                                "issue_count": 2,
                                "symbolic_requested": 2,
                            }
                        ],
                        "mismatch_map": {
                            "RegisterSubstitution": {
                                "pass_name": "RegisterSubstitution",
                                "mismatch_count": 2,
                                "observables": ["rax", "rflags"],
                            }
                        },
                        "mismatch_view": [
                            {
                                "pass_name": "RegisterSubstitution",
                                "mismatch_count": 2,
                                "observables": ["rax", "rflags"],
                                "severity": "mismatch",
                                "issue_count": 2,
                                "symbolic_requested": 2,
                            }
                        ],
                    },
                    "pass_validation_context": {
                        "RegisterSubstitution": {
                            "role": "requested-mode",
                            "requested_validation_mode": "symbolic",
                            "effective_validation_mode": "symbolic",
                            "degraded_execution": False,
                        }
                    },
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--only-mismatches",
            "--summary-only",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(
        payload["filtered_summary"]["mismatch_counts_by_pass"]["RegisterSubstitution"]
        == _EXPECTED_PAYLOAD_FILTERED_SUMMARY_MISMATCH_COUNTS_BY_P_2
    )
    expect(payload["filtered_summary"]["mismatch_observables_by_pass"]["RegisterSubstitution"] == ["rax", "rflags"])
    expect(payload["filtered_summary"]["observable_mismatch_priority"][0][MUTATION_NAME_KEY] == "RegisterSubstitution")
    expect(payload["filtered_summary"]["mismatch_compact_summary"]["pass_count"] == 1)
    expect(
        payload["filtered_summary"]["mismatch_final_by_pass"]["RegisterSubstitution"]["compact_region"]
        == {"region_count": 0, "region_mismatch_count": 0, "region_exit_match_count": 0}
    )
    expect(payload["filtered_summary"]["mismatch_final_rows"][0][MUTATION_NAME_KEY] == "RegisterSubstitution")
    expect(
        payload["filtered_summary"]["mismatch_final_rows"][0]["compact_region"]
        == {"region_count": 0, "region_mismatch_count": 0, "region_exit_match_count": 0}
    )
    expect(
        payload["filtered_summary"]["mismatch_compact_by_pass"]["RegisterSubstitution"]["mismatch_count"]
        == _EXPECTED_PAYLOAD_FILTERED_SUMMARY_MISMATCH_COMPACT_BY__2
    )


def test_cli_report_prefers_discarded_final_by_pass_without_pass_results(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "discarded.report.json"
    output_path = tmp_path / "discarded.filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "report_views": {
                        "discarded_view": {
                            "final_by_pass": {
                                "RegisterSubstitution": {
                                    "pass_name": "RegisterSubstitution",
                                    "discarded_count": 1,
                                    "impact_severity": "medium",
                                    "reason_count": 1,
                                    "reasons": ["runtime_validation_failed"],
                                }
                            },
                            "final_rows": [
                                {
                                    "pass_name": "RegisterSubstitution",
                                    "discarded_count": 1,
                                    "impact_severity": "medium",
                                    "reason_count": 1,
                                    "reasons": ["runtime_validation_failed"],
                                }
                            ],
                            "compact_summary": {
                                "count": 1,
                                "pass_count": 1,
                                "reason_count": 1,
                                "impact_counts": {"high": 0, "medium": 1, "low": 0},
                                "passes": ["RegisterSubstitution"],
                            },
                        }
                    }
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        ["report", str(report_path), "--summary-only", "--output", str(output_path)],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(
        payload["filtered_summary"]["discarded_mutation_final_by_pass"]["RegisterSubstitution"]["reasons"]
        == ["runtime_validation_failed"]
    )


def test_cli_report_handles_summary_only_mismatches_minimal_report_without_passes(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "report_views": {
                        "only_mismatches": {
                            "priority": [],
                            "by_pass": {},
                            "rows": [],
                            "compact_rows": [
                                {
                                    "pass_name": "RegisterSubstitution",
                                    "mismatch_count": 1,
                                    "severity": "mismatch",
                                    "role": "requested-mode",
                                    "symbolic_confidence": "limited",
                                    "degraded_execution": False,
                                    "region_count": 1,
                                    "region_mismatch_count": 1,
                                    "region_exit_match_count": 0,
                                    "compact_region": {
                                        "region_count": 1,
                                        "region_mismatch_count": 1,
                                        "region_exit_match_count": 0,
                                    },
                                }
                            ],
                            "summary": {
                                "pass_count": 1,
                                "mismatch_count": 1,
                                "degraded_pass_count": 0,
                                "trigger_pass_count": 0,
                                "region_count": 1,
                                "region_mismatch_count": 1,
                                "region_exit_match_count": 0,
                                "passes": ["RegisterSubstitution"],
                            },
                        }
                    }
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            str(report_path),
            "--only-mismatches",
            "--summary-only",
            "--require-results",
            "--output",
            str(output_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["mismatch_counts_by_pass"] == {"RegisterSubstitution": 1})


def test_cli_report_handles_summary_only_failed_gates_compact_rows_minimal_report(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "report_views": {
                        "only_failed_gates": {
                            "priority": [],
                            "by_pass": {},
                            "grouped_by_pass": [],
                            "compact_rows": [
                                {
                                    "pass_name": "NopInsertion",
                                    "failure_count": 1,
                                    "strictest_expected_severity": "clean",
                                    "role": "requested-mode",
                                    "failed": True,
                                }
                            ],
                            "summary": {
                                "all_passed": False,
                                "require_pass_severity_failed": True,
                                "require_pass_severity_failure_count": 1,
                                "require_pass_severity_failures": [],
                                "require_pass_severity_failures_by_pass": {},
                                "require_pass_severity_failures_by_expected_severity": {"clean": 1},
                            },
                            "severity_priority": [{"severity": "clean", "failure_count": 1}],
                            "expected_severity_counts": {"clean": 1},
                            "failed": True,
                            "failure_count": 1,
                            "pass_count": 1,
                            "passes": ["NopInsertion"],
                        }
                    }
                },
                "gate_evaluation": {
                    "requested": {},
                    "results": {"all_passed": False},
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            str(report_path),
            "--only-failed-gates",
            "--summary-only",
            "--require-results",
            "--output",
            str(output_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["gate_failure_compact_rows"][0][MUTATION_NAME_KEY] == "NopInsertion")
    expect(payload["filtered_summary"]["gate_failure_compact_rows"][0]["role"] == "requested-mode")
    expect(not (payload["filtered_summary"]["gate_failure_compact_rows"][0]["failed"] is not True))


def test_cli_report_prefers_persisted_symbolic_maps_without_pass_results(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "symbolic_issue_map": {
                        "RegisterSubstitution": {
                            "pass_name": "RegisterSubstitution",
                            "severity": "mismatch",
                            "observable_mismatch": 1,
                            "without_coverage": 0,
                            "bounded_only": 0,
                        }
                    },
                    "symbolic_coverage_map": {
                        "InstructionSubstitution": {
                            "pass_name": "InstructionSubstitution",
                            "symbolic_requested": 1,
                            "observable_match": 1,
                            "observable_mismatch": 0,
                            "bounded_only": 0,
                            "without_coverage": 0,
                        }
                    },
                    "symbolic_severity_map": {
                        "InstructionSubstitution": {
                            "pass_name": "InstructionSubstitution",
                            "severity": "clean",
                            "issue_count": 0,
                            "symbolic_requested": 1,
                        }
                    },
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--summary-only",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["symbolic_issue_passes"][0][MUTATION_NAME_KEY] == "RegisterSubstitution")
    expect(payload["filtered_summary"]["symbolic_coverage_by_pass"][0][MUTATION_NAME_KEY] == "InstructionSubstitution")
    expect(payload["filtered_summary"]["symbolic_severity_by_pass"][0][MUTATION_NAME_KEY] == "InstructionSubstitution")


def test_cli_report_only_structural_risk_filters_to_structural_passes(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "passes": {
                    "NopInsertion": {
                        "symbolic_summary": {
                            "pass_name": "NopInsertion",
                            "symbolic_requested": 1,
                            "observable_match": 1,
                            "observable_mismatch": 0,
                            "bounded_only": 0,
                            "without_coverage": 0,
                            "severity": "clean",
                            "issue_count": 0,
                            "issues": [],
                        },
                        "evidence_summary": {
                            "pass_name": "NopInsertion",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 0,
                        },
                    },
                    "BlockReordering": {
                        "symbolic_summary": {
                            "pass_name": "BlockReordering",
                            "symbolic_requested": 0,
                            "observable_match": 0,
                            "observable_mismatch": 0,
                            "bounded_only": 0,
                            "without_coverage": 0,
                            "severity": "not-requested",
                            "issue_count": 0,
                            "issues": [],
                        },
                        "evidence_summary": {
                            "pass_name": "BlockReordering",
                            "changed_region_count": 2,
                            "changed_bytes": 6,
                            "structural_issue_count": 2,
                            "symbolic_binary_regions_checked": 0,
                            "symbolic_binary_mismatched_regions": 0,
                        },
                    },
                },
                "summary": {
                    "pass_evidence": [
                        {
                            "pass_name": "NopInsertion",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 0,
                        },
                        {
                            "pass_name": "BlockReordering",
                            "changed_region_count": 2,
                            "changed_bytes": 6,
                            "structural_issue_count": 2,
                            "symbolic_binary_regions_checked": 0,
                            "symbolic_binary_mismatched_regions": 0,
                        },
                    ]
                },
                "mutations": [
                    {"pass_name": "NopInsertion", "metadata": {"symbolic_requested": True}},
                    {"pass_name": "BlockReordering", "metadata": {}},
                ],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--only-structural-risk",
            "--summary-only",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    expect(not ("Structural Risk Filter" not in result.output))
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(not (payload["report_filters"]["only_structural_risk"] is not True))
    expect(payload["filtered_summary"]["structural_risk_passes"] == ["BlockReordering"])
    expect(payload["filtered_summary"]["pass_evidence"][0][MUTATION_NAME_KEY] == "BlockReordering")


def test_cli_report_only_symbolic_risk_filters_to_symbolic_passes(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "passes": {
                    "NopInsertion": {
                        "symbolic_summary": {
                            "pass_name": "NopInsertion",
                            "symbolic_requested": 1,
                            "observable_match": 1,
                            "observable_mismatch": 0,
                            "bounded_only": 0,
                            "without_coverage": 0,
                            "severity": "clean",
                            "issue_count": 0,
                            "issues": [],
                        },
                        "evidence_summary": {
                            "pass_name": "NopInsertion",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 0,
                        },
                    },
                    "RegisterSubstitution": {
                        "symbolic_summary": {
                            "pass_name": "RegisterSubstitution",
                            "symbolic_requested": 1,
                            "observable_match": 0,
                            "observable_mismatch": 1,
                            "bounded_only": 0,
                            "without_coverage": 0,
                            "severity": "mismatch",
                            "issue_count": 1,
                            "issues": [
                                {
                                    "pass_name": "RegisterSubstitution",
                                    "severity": "mismatch",
                                    "observable_mismatch": 1,
                                    "without_coverage": 0,
                                    "bounded_only": 0,
                                }
                            ],
                        },
                        "evidence_summary": {
                            "pass_name": "RegisterSubstitution",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 1,
                        },
                    },
                },
                "summary": {
                    "pass_evidence": [
                        {
                            "pass_name": "NopInsertion",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 0,
                        },
                        {
                            "pass_name": "RegisterSubstitution",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 1,
                        },
                    ]
                },
                "mutations": [
                    {"pass_name": "NopInsertion", "metadata": {"symbolic_requested": True}},
                    {"pass_name": "RegisterSubstitution", "metadata": {"symbolic_requested": True}},
                ],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--only-symbolic-risk",
            "--summary-only",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    expect(not ("Symbolic Risk Filter" not in result.output))
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(not (payload["report_filters"]["only_symbolic_risk"] is not True))
    expect(payload["filtered_summary"]["symbolic_risk_passes"] == ["RegisterSubstitution"])
    expect(payload["filtered_summary"]["pass_evidence"][0][MUTATION_NAME_KEY] == "RegisterSubstitution")


def test_cli_report_only_clean_passes_filters_to_clean_passes(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "passes": {
                    "NopInsertion": {
                        "symbolic_summary": {
                            "pass_name": "NopInsertion",
                            "symbolic_requested": 1,
                            "observable_match": 1,
                            "observable_mismatch": 0,
                            "bounded_only": 0,
                            "without_coverage": 0,
                            "severity": "clean",
                            "issue_count": 0,
                            "issues": [],
                        },
                        "evidence_summary": {
                            "pass_name": "NopInsertion",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 0,
                        },
                    },
                    "RegisterSubstitution": {
                        "symbolic_summary": {
                            "pass_name": "RegisterSubstitution",
                            "symbolic_requested": 1,
                            "observable_match": 0,
                            "observable_mismatch": 1,
                            "bounded_only": 0,
                            "without_coverage": 0,
                            "severity": "mismatch",
                            "issue_count": 1,
                            "issues": [
                                {
                                    "pass_name": "RegisterSubstitution",
                                    "severity": "mismatch",
                                    "observable_mismatch": 1,
                                    "without_coverage": 0,
                                    "bounded_only": 0,
                                }
                            ],
                        },
                        "evidence_summary": {
                            "pass_name": "RegisterSubstitution",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 1,
                        },
                    },
                },
                "summary": {
                    "pass_evidence": [
                        {
                            "pass_name": "NopInsertion",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 0,
                        },
                        {
                            "pass_name": "RegisterSubstitution",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 1,
                        },
                    ]
                },
                "mutations": [
                    {"pass_name": "NopInsertion", "metadata": {"symbolic_requested": True}},
                    {"pass_name": "RegisterSubstitution", "metadata": {"symbolic_requested": True}},
                ],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--only-clean-passes",
            "--summary-only",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    expect(not ("Clean Pass Filter" not in result.output))
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(not (payload["report_filters"]["only_clean_passes"] is not True))
    expect(payload["filtered_summary"]["clean_passes"] == ["NopInsertion"])
    expect(payload["filtered_summary"]["pass_risk_buckets"]["clean"] == ["NopInsertion"])
    expect(payload["filtered_summary"]["pass_evidence"][0][MUTATION_NAME_KEY] == "NopInsertion")


def test_cli_report_only_covered_passes_filters_to_covered_passes(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "passes": {
                    "InstructionSubstitution": {
                        "symbolic_summary": {
                            "pass_name": "InstructionSubstitution",
                            "symbolic_requested": 1,
                            "observable_match": 1,
                            "observable_mismatch": 0,
                            "bounded_only": 0,
                            "without_coverage": 0,
                            "severity": "clean",
                            "issue_count": 0,
                            "issues": [],
                        },
                        "evidence_summary": {
                            "pass_name": "InstructionSubstitution",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 0,
                        },
                    },
                    "NopInsertion": {
                        "symbolic_summary": {
                            "pass_name": "NopInsertion",
                            "symbolic_requested": 1,
                            "observable_match": 0,
                            "observable_mismatch": 0,
                            "bounded_only": 0,
                            "without_coverage": 1,
                            "severity": "without-coverage",
                            "issue_count": 1,
                            "issues": [
                                {
                                    "pass_name": "NopInsertion",
                                    "severity": "without-coverage",
                                    "observable_mismatch": 0,
                                    "without_coverage": 1,
                                    "bounded_only": 0,
                                }
                            ],
                        },
                        "evidence_summary": {
                            "pass_name": "NopInsertion",
                            "changed_region_count": 1,
                            "changed_bytes": 1,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 0,
                            "symbolic_binary_mismatched_regions": 0,
                        },
                    },
                },
                "summary": {
                    "pass_evidence": [
                        {
                            "pass_name": "InstructionSubstitution",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 0,
                        },
                        {
                            "pass_name": "NopInsertion",
                            "changed_region_count": 1,
                            "changed_bytes": 1,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 0,
                            "symbolic_binary_mismatched_regions": 0,
                        },
                    ]
                },
                "mutations": [
                    {
                        "pass_name": "InstructionSubstitution",
                        "metadata": {"symbolic_requested": True},
                    },
                    {"pass_name": "NopInsertion", "metadata": {"symbolic_requested": True}},
                ],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--only-covered-passes",
            "--summary-only",
            "--require-results",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    expect(not ("Covered Pass Filter" not in result.output))
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(not (payload["report_filters"]["only_covered_passes"] is not True))
    expect(payload["filtered_summary"]["covered_passes"] == ["InstructionSubstitution"])
    expect(payload["filtered_summary"]["pass_coverage_buckets"]["covered"] == ["InstructionSubstitution"])
    expect(payload["filtered_summary"]["pass_evidence"][0][MUTATION_NAME_KEY] == "InstructionSubstitution")


def test_cli_report_only_uncovered_passes_filters_to_uncovered_passes(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "passes": {
                    "ReportFixture": {
                        "symbolic_summary": {
                            "pass_name": "ReportFixture",
                            "symbolic_requested": 0,
                            "observable_match": 0,
                            "observable_mismatch": 0,
                            "bounded_only": 0,
                            "without_coverage": 0,
                            "severity": "not-requested",
                            "issue_count": 0,
                            "issues": [],
                        },
                        "evidence_summary": {
                            "pass_name": "ReportFixture",
                            "changed_region_count": 1,
                            "changed_bytes": 0,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 0,
                            "symbolic_binary_mismatched_regions": 0,
                        },
                    },
                    "InstructionSubstitution": {
                        "symbolic_summary": {
                            "pass_name": "InstructionSubstitution",
                            "symbolic_requested": 1,
                            "observable_match": 1,
                            "observable_mismatch": 0,
                            "bounded_only": 0,
                            "without_coverage": 0,
                            "severity": "clean",
                            "issue_count": 0,
                            "issues": [],
                        },
                        "evidence_summary": {
                            "pass_name": "InstructionSubstitution",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 0,
                        },
                    },
                },
                "summary": {
                    "pass_evidence": [
                        {
                            "pass_name": "ReportFixture",
                            "changed_region_count": 1,
                            "changed_bytes": 0,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 0,
                            "symbolic_binary_mismatched_regions": 0,
                        },
                        {
                            "pass_name": "InstructionSubstitution",
                            "changed_region_count": 1,
                            "changed_bytes": 2,
                            "structural_issue_count": 0,
                            "symbolic_binary_regions_checked": 1,
                            "symbolic_binary_mismatched_regions": 0,
                        },
                    ]
                },
                "mutations": [
                    {"pass_name": "ReportFixture", "metadata": {}},
                    {
                        "pass_name": "InstructionSubstitution",
                        "metadata": {"symbolic_requested": True},
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--only-uncovered-passes",
            "--summary-only",
            "--require-results",
            "--output",
            str(output_path),
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    expect(not ("Uncovered Pass Filter" not in result.output))
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(not (payload["report_filters"]["only_uncovered_passes"] is not True))
    expect(payload["filtered_summary"]["uncovered_passes"] == ["ReportFixture"])
    expect(payload["filtered_summary"]["pass_coverage_buckets"]["uncovered"] == ["ReportFixture"])
    expect(payload["filtered_summary"]["pass_evidence"][0][MUTATION_NAME_KEY] == "ReportFixture")


def test_cli_report_only_pass_combines_with_only_mismatches(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "mutations": [
                    {
                        "pass_name": "InstructionSubstitution",
                        "start_address": 0x401000,
                        "metadata": {
                            "symbolic_requested": True,
                            "symbolic_observable_check_performed": True,
                            "symbolic_observable_equivalent": False,
                            "symbolic_observable_mismatches": ["eax"],
                        },
                    },
                    {
                        "pass_name": "NopInsertion",
                        "start_address": 0x402000,
                        "metadata": {
                            "symbolic_requested": True,
                            "symbolic_observable_check_performed": True,
                            "symbolic_observable_equivalent": False,
                            "symbolic_observable_mismatches": ["eflags"],
                        },
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--only-pass",
            "InstructionSubstitution",
            "--only-mismatches",
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    expect(not ("Filtered Mismatch Mutations: 1" not in result.output))
    expect(not ('"pass_name": "InstructionSubstitution"' not in result.output))
    expect('"pass_name": "NopInsertion"' not in result.output)
    expect(not ('"only_pass": "InstructionSubstitution"' not in result.output))
    expect(not ('"only_mismatches": true' not in result.output))


def test_cli_report_only_status_filters_json(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "mutations": [
                    {
                        "pass_name": "InstructionSubstitution",
                        "metadata": {
                            "symbolic_requested": True,
                            "symbolic_status": "bounded-step-observables-match",
                        },
                    },
                    {
                        "pass_name": "InstructionSubstitution",
                        "metadata": {
                            "symbolic_requested": True,
                            "symbolic_status": "bounded-step-observable-mismatch",
                        },
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        ["report", "--only-status", "bounded-step-observable-mismatch", str(report_path)],
    )

    expect(result.exit_code == 0)
    expect(not ('"symbolic_status": "bounded-step-observable-mismatch"' not in result.output))
    expect('"symbolic_status": "bounded-step-observables-match"' not in result.output)
    expect(not ('"only_status": "bounded-step-observable-mismatch"' not in result.output))


def test_cli_report_only_status_combines_with_other_filters(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "mutations": [
                    {
                        "pass_name": "InstructionSubstitution",
                        "metadata": {
                            "symbolic_requested": True,
                            "symbolic_status": "bounded-step-observable-mismatch",
                            "symbolic_observable_check_performed": True,
                            "symbolic_observable_equivalent": False,
                        },
                    },
                    {
                        "pass_name": "NopInsertion",
                        "metadata": {
                            "symbolic_requested": True,
                            "symbolic_status": "bounded-step-observable-mismatch",
                            "symbolic_observable_check_performed": True,
                            "symbolic_observable_equivalent": False,
                        },
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        [
            "report",
            "--only-pass",
            "InstructionSubstitution",
            "--only-status",
            "bounded-step-observable-mismatch",
            "--only-mismatches",
            str(report_path),
        ],
    )

    expect(result.exit_code == 0)
    expect(not ("Filtered Mismatch Mutations: 1" not in result.output))
    expect(not ('"pass_name": "InstructionSubstitution"' not in result.output))
    expect('"pass_name": "NopInsertion"' not in result.output)
    expect(not ('"only_status": "bounded-step-observable-mismatch"' not in result.output))
    expect(not ('"only_pass": "InstructionSubstitution"' not in result.output))
    expect(not ('"only_mismatches": true' not in result.output))


def test_cli_report_summary_only_skips_json(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "pass_support": {
                    "InstructionSubstitution": {
                        "validator_capabilities": {
                            "runtime": {"recommended": True},
                            "symbolic": {
                                "confidence": "best among stable passes",
                                "recommended": True,
                            },
                        }
                    }
                },
                "mutations": [
                    {
                        "pass_name": "InstructionSubstitution",
                        "start_address": 0x401010,
                        "end_address": 0x401011,
                        "metadata": {
                            "symbolic_requested": True,
                            "symbolic_status": "bounded-step-observable-mismatch",
                            "symbolic_observable_check_performed": True,
                            "symbolic_observable_equivalent": False,
                            "symbolic_observable_mismatches": ["eax"],
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli.app, ["report", "--summary-only", str(report_path)])

    expect(result.exit_code == 0)
    expect(not ("Symbolic Mutation Summary" not in result.output))
    expect(not ("Passes With Symbolic Issues" not in result.output))
    expect(not ("Pass Capabilities" not in result.output))
    expect(not ("runtime recommended=yes" not in result.output))
    expect(not ("symbolic confidence=best" not in result.output))
    expect(not ("among stable passes" not in result.output))
    expect(not ("Symbolic Mismatches" not in result.output))
    expect('"mutations"' not in result.output)


def test_cli_report_summary_only_combines_with_only_mismatches(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "mutations": [
                    {
                        "pass_name": "InstructionSubstitution",
                        "metadata": {
                            "symbolic_requested": True,
                            "symbolic_observable_check_performed": True,
                            "symbolic_observable_equivalent": False,
                            "symbolic_observable_mismatches": ["eax"],
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        ["report", "--only-mismatches", "--summary-only", str(report_path)],
    )

    expect(result.exit_code == 0)
    expect(not ("Filtered Mismatch Mutations: 1" not in result.output))
    expect(not ("Mismatch Pass Summary" not in result.output))
    expect(not ("InstructionSubstitution" not in result.output))
    expect(not ("mismatch_count=1" not in result.output))
    expect('"mutations"' not in result.output)


def test_cli_report_only_mismatches_prefers_persisted_mismatch_summary(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "observable_mismatch_map": {
                        "InstructionSubstitution": {
                            "pass_name": "InstructionSubstitution",
                            "mismatch_count": 2,
                            "observables": ["eax", "eflags"],
                        }
                    },
                    "observable_mismatch_by_pass": [
                        {
                            "pass_name": "InstructionSubstitution",
                            "mismatch_count": 2,
                            "observables": ["eax", "eflags"],
                        }
                    ],
                },
                "mutations": [],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        ["report", "--only-mismatches", "--summary-only", str(report_path)],
    )

    expect(result.exit_code == 0)
    expect(not ("Filtered Mismatch Mutations: 0" not in result.output))
    expect(not ("Mismatch Pass Summary" not in result.output))
    expect(not ("InstructionSubstitution" not in result.output))
    expect(not ("mismatch_count=2" not in result.output))
    expect(not ("observables=eax,eflags" not in result.output))


def test_cli_report_exports_filtered_pass_capabilities(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "pass_support": {
                    "RegisterSubstitution": {
                        "validator_capabilities": {
                            "runtime": {"recommended": True},
                            "symbolic": {"confidence": "limited", "recommended": False},
                        }
                    }
                },
                "mutations": [
                    {
                        "pass_name": "RegisterSubstitution",
                        "metadata": {
                            "symbolic_requested": True,
                            "symbolic_status": "real-binary-observable-mismatch",
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        ["report", "--summary-only", "--output", str(output_path), str(report_path)],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(
        not (
            payload["filtered_summary"]["pass_capabilities"]["RegisterSubstitution"]["runtime"]["recommended"]
            is not True
        )
    )


def test_cli_report_exports_symbolic_issue_passes_summary(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "mutations": [
                    {
                        "pass_name": "InstructionSubstitution",
                        "metadata": {
                            "symbolic_requested": True,
                            "symbolic_observable_check_performed": True,
                            "symbolic_observable_equivalent": False,
                        },
                    },
                    {
                        "pass_name": "BlockReordering",
                        "metadata": {
                            "symbolic_requested": True,
                            "symbolic_status": "unsupported",
                        },
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        ["report", "--summary-only", "--output", str(output_path), str(report_path)],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["symbolic_issue_passes"][0][MUTATION_NAME_KEY] == "InstructionSubstitution")
    expect(payload["filtered_summary"]["symbolic_issue_passes"][0]["severity"] == "mismatch")
    expect(payload["filtered_summary"]["symbolic_issue_passes"][1][MUTATION_NAME_KEY] == "BlockReordering")
    expect(payload["filtered_summary"]["symbolic_issue_passes"][1]["severity"] == "without-coverage")


def test_cli_report_exports_symbolic_coverage_by_pass_summary(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "symbolic_coverage_by_pass": [
                        {
                            "pass_name": "InstructionSubstitution",
                            "symbolic_requested": 2,
                            "observable_match": 1,
                            "observable_mismatch": 1,
                            "bounded_only": 0,
                            "without_coverage": 0,
                        }
                    ]
                },
                "mutations": [
                    {
                        "pass_name": "InstructionSubstitution",
                        "metadata": {
                            "symbolic_requested": True,
                            "symbolic_observable_check_performed": True,
                            "symbolic_observable_equivalent": True,
                        },
                    },
                    {
                        "pass_name": "InstructionSubstitution",
                        "metadata": {
                            "symbolic_requested": True,
                            "symbolic_observable_check_performed": True,
                            "symbolic_observable_equivalent": False,
                        },
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        ["report", "--summary-only", "--output", str(output_path), str(report_path)],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["symbolic_coverage_by_pass"][0][MUTATION_NAME_KEY] == "InstructionSubstitution")
    expect(
        payload["filtered_summary"]["symbolic_coverage_by_pass"][0]["symbolic_requested"]
        == _EXPECTED_PAYLOAD_FILTERED_SUMMARY_SYMBOLIC_COVERAGE_BY_2
    )
    expect(payload["filtered_summary"]["symbolic_coverage_by_pass"][0]["observable_match"] == 1)
    expect(payload["filtered_summary"]["symbolic_coverage_by_pass"][0]["observable_mismatch"] == 1)


def test_cli_report_exports_symbolic_severity_by_pass_summary(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "summary": {
                    "symbolic_severity_by_pass": [
                        {
                            "pass_name": "InstructionSubstitution",
                            "severity": "mismatch",
                            "issue_count": 1,
                            "symbolic_requested": 2,
                        }
                    ]
                },
                "mutations": [
                    {
                        "pass_name": "InstructionSubstitution",
                        "metadata": {
                            "symbolic_requested": True,
                            "symbolic_observable_check_performed": True,
                            "symbolic_observable_equivalent": False,
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        ["report", "--summary-only", "--output", str(output_path), str(report_path)],
    )

    expect(result.exit_code == 0)
    expect(not ("Severity Priority" not in result.output))
    expect(not ("severity=mismatch" not in result.output))
    expect(not ("issue_count=1" not in result.output))
    expect(not ("severity=mismatch" not in result.output))
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(payload["filtered_summary"]["symbolic_severity_by_pass"][0][MUTATION_NAME_KEY] == "InstructionSubstitution")
    expect(payload["filtered_summary"]["symbolic_severity_by_pass"][0]["severity"] == "mismatch")


def test_cli_report_only_mismatches_exports_pass_mismatch_counts(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    output_path = tmp_path / "filtered.json"
    report_path.write_text(
        json.dumps(
            {
                "passes": {
                    "InstructionSubstitution": {
                        "validation_context": {
                            "requested_validation_mode": "symbolic",
                            "effective_validation_mode": "symbolic",
                            "degraded_execution": False,
                            "degradation_triggered_by_pass": False,
                            "role": "requested-mode",
                        }
                    }
                },
                "mutations": [
                    {
                        "pass_name": "InstructionSubstitution",
                        "metadata": {
                            "symbolic_requested": True,
                            "symbolic_observable_check_performed": True,
                            "symbolic_observable_equivalent": False,
                            "symbolic_observable_mismatches": ["eax"],
                        },
                    },
                    {
                        "pass_name": "InstructionSubstitution",
                        "metadata": {
                            "symbolic_requested": True,
                            "symbolic_observable_check_performed": True,
                            "symbolic_observable_equivalent": False,
                            "symbolic_observable_mismatches": ["eflags"],
                        },
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli.app,
        ["report", "--only-mismatches", "--output", str(output_path), str(report_path)],
    )

    expect(result.exit_code == 0)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    expect(
        payload["filtered_summary"]["mismatch_counts_by_pass"]["InstructionSubstitution"]
        == _EXPECTED_PAYLOAD_FILTERED_SUMMARY_MISMATCH_COUNTS_BY_P_2_2
    )
    expect(payload["filtered_summary"]["mismatch_observables_by_pass"]["InstructionSubstitution"] == ["eax", "eflags"])
    expect(
        payload["filtered_summary"]["pass_validation_context"]["InstructionSubstitution"]["role"] == "requested-mode"
    )
