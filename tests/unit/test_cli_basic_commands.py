from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import json

import pytest

typer_testing = pytest.importorskip("typer.testing")
CliRunner = typer_testing.CliRunner

from r2morph import cli


def test_cli_simple_mode(tmp_path: Path) -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    input_path = tmp_path / "input.bin"
    output_path = tmp_path / "output.bin"
    input_path.write_bytes(source.read_bytes())

    result = subprocess.run(
        [sys.executable, "-m", "r2morph.cli", str(input_path), str(output_path)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0
    assert output_path.exists()


def test_cli_no_input_shows_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli.app, [])
    assert result.exit_code == 0
    assert "No input file provided" in result.output


def test_cli_version_function() -> None:
    result = cli.version()
    assert result is None


def test_cli_warns_for_experimental_mutations(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    class FakeEngine:
        def __init__(self, config=None):
            self.config = config or {}

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def load_binary(self, path):
            self.path = Path(path)
            return self

        def analyze(self):
            return self

        def add_mutation(self, mutation):
            return self

        def run(self, **kwargs):
            return {
                "total_mutations": 0,
                "passes_run": 1,
                "pass_results": {"BlockReordering": {"mutations_applied": 0}},
                "validation": {"all_passed": True},
            }

        def save(self, output_path):
            Path(output_path).write_bytes(self.path.read_bytes())

        def build_report(self, result=None):
            return {"pass_results": {}, "mutations": []}

    monkeypatch.setattr(cli, "MorphEngine", FakeEngine)

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

    assert result.exit_code == 0
    assert "Experimental mutations selected" in result.output
    assert "best-effort" in result.output


def test_cli_warns_for_symbolic_validation_mode(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = Path("dataset/elf_x86_64")
    if not source.exists():
        pytest.skip("ELF test binary not available")

    class FakeEngine:
        def __init__(self, config=None):
            self.config = config or {}

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def load_binary(self, path):
            self.path = Path(path)
            return self

        def analyze(self):
            return self

        def add_mutation(self, mutation):
            return self

        def run(self, **kwargs):
            return {
                "total_mutations": 0,
                "passes_run": 1,
                "pass_results": {"NopInsertion": {"mutations_applied": 0}},
                "validation": {"all_passed": True, "total_issues": 0},
                "validation_mode": kwargs.get("validation_mode"),
            }

        def save(self, output_path):
            Path(output_path).write_bytes(self.path.read_bytes())

        def build_report(self, result=None):
            return {"pass_results": {}, "mutations": []}

    monkeypatch.setattr(cli, "MorphEngine", FakeEngine)

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

    assert result.exit_code == 0
    assert "Experimental validation mode selected" in result.output
    assert "semantic equivalence" in result.output


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

    assert result.exit_code == 0
    assert "Symbolic Mutation Summary" in result.output
    assert "1 observable match" in result.output
    assert "1 observable mismatch" in result.output
    assert "bounded-step only" in result.output
    assert "without symbolic coverage" in result.output
    assert "InstructionSubstitution" in result.output
    assert "1 match, 1 mismatch" in result.output
    assert "NopInsertion" in result.output
    assert "1 bounded-only" in result.output
    assert "BlockReordering" in result.output
    assert "1 without coverage" in result.output
    assert "Passes With Symbolic Issues" in result.output
    assert "severity=mismatch" in result.output
    assert "severity=without-coverage" in result.output
    assert "Symbolic Mismatches" in result.output
    assert "0x401010-0x401011" in result.output
    assert "eax, eflags" in result.output


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

    assert result.exit_code == 0
    assert "Validation Mode Adjustment" in result.output
    assert "requested=symbolic, effective=runtime" in result.output
    assert "policy=degrade-runtime, reason=limited-symbolic-support" in result.output
    assert "Degraded Passes" in result.output
    assert "RegisterSubstitution" in result.output
    assert "symbolic confidence=limited" in result.output
    assert "Degradation Roles" in result.output
    assert "degradation-trigger: 1" in result.output
    assert "executed-under-degraded-mode: 2" in result.output
    assert "Pass Validation Context" in result.output
    assert "requested=symbolic, effective=runtime, degraded=yes" in result.output
    assert "trigger=yes" in result.output


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

    assert result.exit_code == 0
    assert '"mutations": []' in result.output
    assert '"only_degraded": true' in result.output


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

    assert result.exit_code == 0
    assert "Pass Filter Resolution" in result.output
    assert "nop -> NopInsertion" in result.output
    assert '"only_pass": "NopInsertion"' in result.output
    assert '"pass_name": "NopInsertion"' in result.output


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

    assert result.exit_code == 0
    assert "Degraded Severity Priority" in result.output
    assert '"degraded_passes": [' in result.output
    assert '"pass_name": "RegisterSubstitution"' in result.output
    assert '"degradation_roles": {' in result.output
    assert '"degradation-trigger": 1' in result.output


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

    assert result.exit_code == 0
    assert "Gate Evaluation" in result.output
    assert "Gate Failure Summary" in result.output
    assert "min_severity_failed=yes, require_pass_failures=0" in result.output
    assert "all_passed=no" in result.output
    assert '"only_failed_gates": true' in result.output
    assert '"failed_gates": true' in result.output
    assert '"gate_failures": {' in result.output


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

    assert result.exit_code == 0
    assert "Gate Failure Summary" in result.output
    assert "require_pass_failures=2" in result.output
    assert "expected_severity_counts=bounded-only:1, clean:1" in result.output
    assert "Gate Failure By Pass" in result.output
    assert "NopInsertion" in result.output
    assert "InstructionSubstitution" in result.output
    assert "count=1, strictest_expected=bounded-only" in result.output
    assert "count=1, strictest_expected=clean" in result.output
    assert "NopInsertion=not-requested(expected <= clean)" in result.output
    assert "InstructionSubstitution=without-coverage(expected <= bounded-only)" in result.output
    gate_section = result.output.split("Gate Failure By Pass", 1)[1]
    assert gate_section.index("InstructionSubstitution") < gate_section.index("NopInsertion")


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

    assert result.exit_code == 0
    assert "expected_severity_counts=clean:3" in result.output
    assert "count=2, strictest_expected=clean" in result.output
    gate_section = result.output.split("Gate Failure By Pass", 1)[1]
    assert gate_section.index("NopInsertion") < gate_section.index("InstructionSubstitution")


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

    assert result.exit_code == 0
    payload = json.loads(filtered_path.read_text(encoding="utf-8"))
    priority = payload["filtered_summary"]["gate_failure_priority"]
    severity_counts = payload["filtered_summary"]["gate_failures"][
        "require_pass_severity_failures_by_expected_severity"
    ]
    assert [row["pass_name"] for row in priority] == [
        "NopInsertion",
        "InstructionSubstitution",
    ]
    assert priority[0]["failure_count"] == 2
    assert priority[0]["strictest_expected_severity"] == "clean"
    assert severity_counts == {"clean": 3}


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

    assert result.exit_code == 0
    assert "expected_severity_counts=clean:1" in result.output
    payload = json.loads(filtered_path.read_text(encoding="utf-8"))
    assert payload["report_filters"]["only_expected_severity"] == "clean"
    assert payload["filtered_summary"]["gate_failures"]["require_pass_severity_failures_by_expected_severity"] == {
        "clean": 1
    }
    assert payload["filtered_summary"]["gate_failure_priority"] == [
        {
            "pass_name": "NopInsertion",
            "failure_count": 1,
            "strictest_expected_severity": "clean",
            "failures": ["NopInsertion=not-requested(expected <= clean)"],
        }
    ]


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

    assert success.exit_code == 0
    assert failure.exit_code == 1


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

    assert result.exit_code == 0
    assert "expected_severity_counts=clean:1" in result.output
    payload = json.loads(filtered_path.read_text(encoding="utf-8"))
    assert payload["report_filters"]["only_pass_failure"] == "NopInsertion"
    assert payload["filtered_summary"]["gate_failures"]["require_pass_severity_failures_by_pass"] == {
        "NopInsertion": ["NopInsertion=not-requested(expected <= clean)"]
    }
    assert payload["filtered_summary"]["gate_failure_priority"] == [
        {
            "pass_name": "NopInsertion",
            "failure_count": 1,
            "strictest_expected_severity": "clean",
            "failures": ["NopInsertion=not-requested(expected <= clean)"],
        }
    ]


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

    assert success.exit_code == 0
    assert failure.exit_code == 1


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

    assert result.exit_code == 0
    assert "Pass Failure Filter Resolution" in result.output
    assert "nop -> NopInsertion" in result.output
    payload = json.loads(filtered_path.read_text(encoding="utf-8"))
    assert payload["report_filters"]["only_pass_failure"] == "NopInsertion"
    assert payload["filtered_summary"]["only_pass_failure"] == "NopInsertion"


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

    assert success.exit_code == 0
    assert failure.exit_code == 1


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

    assert success.exit_code == 0
    assert failure.exit_code == 1


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

    assert result.exit_code == 0
    assert "role=degradation-trigger" in result.output
    assert "role=executed-under-degraded-mode" in result.output

    json_result = runner.invoke(cli.app, ["report", str(report_path)])
    assert json_result.exit_code == 0
    assert '"role": "degradation-trigger"' in json_result.output
    assert '"role": "executed-under-degraded-mode"' in json_result.output


def test_cli_report_skips_symbolic_summary_when_not_present(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps({"mutations": [{"metadata": {}}]}), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli.app, ["report", str(report_path)])

    assert result.exit_code == 0
    assert "Symbolic Mutation Summary" not in result.output
    assert "Symbolic Mismatches" not in result.output


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

    assert result.exit_code == 0
    assert "Filtered Mismatch Mutations: 1" in result.output
    assert "0x401010" in result.output
    assert "0x401000" not in result.output


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

    assert result.exit_code == 0
    assert "Mismatch Degradation Context" in result.output
    assert "Mismatch Severity Priority" in result.output
    assert "requested=symbolic, effective=runtime" in result.output
    assert "trigger_passes=RegisterSubstitution" in result.output
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["requested_validation_mode"] == "symbolic"
    assert payload["filtered_summary"]["validation_mode"] == "runtime"
    assert payload["filtered_summary"]["degraded_validation"] is True
    assert payload["filtered_summary"]["degraded_passes"][0]["pass_name"] == "RegisterSubstitution"
    assert payload["filtered_summary"]["degradation_roles"]["degradation-trigger"] == 1
    assert payload["filtered_summary"]["symbolic_severity_by_pass"][0]["pass_name"] == "RegisterSubstitution"
    assert payload["filtered_summary"]["symbolic_severity_by_pass"][0]["severity"] == "mismatch"
    assert (
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

    assert result.exit_code == 0
    assert "Filtered Mismatch Mutations: 0" in result.output


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

    assert result.exit_code == 0
    assert "InstructionSubstitution" in result.output
    assert '"pass_name": "InstructionSubstitution"' in result.output
    assert '"pass_name": "NopInsertion"' not in result.output
    assert '"only_pass": "InstructionSubstitution"' in result.output


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

    assert result.exit_code == 0
    assert "Pass Symbolic Summary" in result.output
    assert "InstructionSubstitution: 1 match, 1 mismatch" in result.output
    assert "0 bounded-only, 0 without" in result.output
    assert "coverage" in result.output
    assert "severity=mismatch" in result.output
    assert "issue_count=1" in result.output
    assert "issues: mismatch(mismatch=1, without_coverage=0, bounded_only=0)" in result.output
    assert "Pass Evidence Summary" in result.output
    assert "changed_regions=1" in result.output
    assert "changed_bytes=2" in result.output
    assert "symbolic_mismatch=1" in result.output
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["pass_symbolic_summary"]["InstructionSubstitution"]["symbolic_requested"] == 2
    assert (
        payload["filtered_summary"]["pass_symbolic_summary"]["InstructionSubstitution"]["issues"][0]["severity"]
        == "mismatch"
    )
    assert payload["filtered_summary"]["pass_symbolic_summary"]["InstructionSubstitution"]["severity"] == "mismatch"
    assert payload["filtered_summary"]["pass_evidence"][0]["pass_name"] == "InstructionSubstitution"
    assert payload["filtered_summary"]["pass_evidence"][0]["changed_region_count"] == 1


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

    assert result.exit_code == 0
    assert "Pass Evidence" in result.output
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["pass_evidence"][0]["pass_name"] == "RegisterSubstitution"
    assert payload["filtered_summary"]["pass_evidence"][1]["pass_name"] == "NopInsertion"


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["pass_evidence"][0]["pass_name"] == "RegisterSubstitution"
    assert payload["filtered_summary"]["pass_evidence"][1]["pass_name"] == "NopInsertion"


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

    assert result.exit_code == 0
    assert "Risky Pass Filter" in result.output
    assert "RegisterSubstitution" in result.output
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["report_filters"]["only_risky_passes"] is True
    assert payload["filtered_summary"]["risky_passes"] == ["RegisterSubstitution"]
    assert payload["filtered_summary"]["pass_risk_buckets"]["risky"] == ["RegisterSubstitution"]
    assert payload["filtered_summary"]["pass_risk_buckets"]["symbolic"] == ["RegisterSubstitution"]
    assert payload["filtered_summary"]["pass_evidence"][0]["pass_name"] == "RegisterSubstitution"
    assert payload["filtered_summary"]["symbolic_severity_by_pass"][0]["pass_name"] == ("RegisterSubstitution")


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

    assert result.exit_code == 1


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["risky_passes"] == ["RegisterSubstitution"]
    assert payload["filtered_summary"]["pass_risk_buckets"]["symbolic"] == ["RegisterSubstitution"]
    assert payload["filtered_summary"]["pass_coverage_buckets"]["covered"] == ["InstructionSubstitution"]


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["pass_symbolic_summary"]["InstructionSubstitution"]["severity"] == "clean"
    assert payload["filtered_summary"]["pass_validation_context"]["InstructionSubstitution"]["role"] == "requested-mode"


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert (
        payload["filtered_summary"]["pass_capabilities"]["InstructionSubstitution"]["symbolic"]["recommended"] is True
    )
    assert payload["filtered_summary"]["pass_evidence"][0]["pass_name"] == "InstructionSubstitution"


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["symbolic_statuses"] == {"real-binary-observable-mismatch": 1}
    assert payload["filtered_summary"]["pass_triage_rows"][0]["pass_name"] == "RegisterSubstitution"
    assert payload["filtered_summary"]["pass_capability_summary"][0]["symbolic_confidence"] == "limited"
    assert payload["filtered_summary"]["validation_role_rows"][0]["role"] == "requested-mode"
    assert payload["filtered_summary"]["validation_adjustments"]["degraded_validation"] is False
    assert payload["filtered_summary"]["validation_adjustment_compact_summary"]["degraded_validation"] is False
    assert payload["filtered_summary"]["pass_evidence"][0]["pass_name"] == "RegisterSubstitution"
    assert payload["filtered_summary"]["discarded_mutation_summary"]["by_reason"] == {"runtime_validation_failed": 1}
    assert payload["filtered_summary"]["discarded_mutation_compact_rows"][0]["pass_name"] == ("RegisterSubstitution")
    assert payload["filtered_summary"]["discarded_mutation_final_rows"][0]["pass_name"] == ("RegisterSubstitution")
    assert payload["filtered_summary"]["discarded_mutation_final_rows"][0]["reasons"] == ["runtime_validation_failed"]
    assert payload["filtered_summary"]["discarded_mutation_compact_by_reason"] == {"runtime_validation_failed": 1}


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["risky_passes"] == ["RegisterSubstitution"]
    assert payload["filtered_summary"]["pass_triage_rows"][0]["pass_name"] == "RegisterSubstitution"
    assert payload["filtered_summary"]["normalized_pass_results"][0]["pass_name"] == ("RegisterSubstitution")
    assert payload["filtered_summary"]["pass_validation_context"]["RegisterSubstitution"]["role"] == "requested-mode"
    assert payload["filtered_summary"]["pass_symbolic_summary"]["RegisterSubstitution"]["severity"] == "mismatch"


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["failed_gates"] is True
    assert payload["filtered_summary"]["gate_failure_priority"][0]["pass_name"] == ("RegisterSubstitution")
    assert payload["filtered_summary"]["gate_failures"]["require_pass_severity_failures_by_expected_severity"] == {
        "clean": 1
    }


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["passes"] == ["InstructionSubstitution"]
    assert payload["filtered_summary"]["normalized_pass_results"][0]["pass_name"] == ("InstructionSubstitution")
    assert payload["filtered_summary"]["pass_symbolic_summary"]["InstructionSubstitution"]["severity"] == "clean"


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["passes"] == ["InstructionSubstitution"]
    assert payload["filtered_summary"]["normalized_pass_results"][0]["pass_name"] == ("InstructionSubstitution")
    assert payload["filtered_summary"]["pass_symbolic_summary"]["InstructionSubstitution"]["severity"] == "clean"


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["passes"] == ["InstructionSubstitution"]
    assert payload["filtered_summary"]["normalized_pass_results"][0]["pass_name"] == ("InstructionSubstitution")
    assert (
        payload["filtered_summary"]["pass_capability_summary"][0]["symbolic_confidence"] == "best among stable passes"
    )
    assert payload["filtered_summary"]["pass_evidence"][0]["changed_region_count"] == 1


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["pass_risk_buckets"]["risky"] == ["RegisterSubstitution"]


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["pass_risk_buckets"]["clean"] == ["NopInsertion"]


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["symbolic_requested"] == 1
    assert payload["filtered_summary"]["observable_mismatch"] == 1
    assert payload["filtered_summary"]["general_summary"]["pass_count"] == 1
    assert payload["filtered_summary"]["general_symbolic"]["overview"]["observable_mismatch"] == 1
    assert payload["filtered_summary"]["general_gates"]["summary"]["require_pass_severity_failed"] is False
    assert payload["filtered_summary"]["general_degradation"]["summary"]["degraded_validation"] is False
    assert payload["filtered_summary"]["general_discards"]["summary"]["count"] == 0
    assert payload["filtered_summary"]["validation_adjustments"]["degraded_validation"] is False
    assert payload["filtered_summary"]["discarded_mutation_compact_summary"]["count"] == 0


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["general_renderer_state"]["summary"]["pass_count"] == 1
    assert payload["filtered_summary"]["symbolic_requested"] == 1
    assert payload["filtered_summary"]["general_summary"]["passes"] == ["InstructionSubstitution"]


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["general_summary"]["passes"] == ["InstructionSubstitution"]
    assert payload["filtered_summary"]["general_symbolic"]["overview"]["symbolic_requested"] == 1
    assert payload["filtered_summary"]["general_degradation"]["summary"]["effective_validation_mode"] == "symbolic"


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["gate_failure_compact_summary"]["failed"] is True
    assert payload["filtered_summary"]["gate_failure_compact_summary"]["failure_count"] == 2
    assert payload["filtered_summary"]["validation_adjustment_summary"]["effective_validation_mode"] == "runtime"
    assert payload["filtered_summary"]["discarded_mutation_compact_summary"]["count"] == 1


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["passes"] == ["InstructionSubstitution"]
    assert payload["filtered_summary"]["general_summary"]["passes"] == ["InstructionSubstitution"]


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["general_summary_rows"][0]["section"] == "passes"
    assert payload["filtered_summary"]["general_summary"]["passes"] == ["InstructionSubstitution"]
    assert payload["filtered_summary"]["symbolic_requested"] == 1


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["risky_passes"] == ["RegisterSubstitution"]
    assert payload["filtered_summary"]["pass_risk_buckets"]["risky"] == ["RegisterSubstitution"]


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["risky_passes"] == ["RegisterSubstitution"]
    assert payload["filtered_summary"]["passes"] == ["RegisterSubstitution"]
    assert payload["filtered_summary"]["pass_risk_buckets"]["risky"] == ["RegisterSubstitution"]


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["passes"] == ["InstructionSubstitution"]
    assert payload["filtered_summary"]["normalized_pass_results"][0]["pass_name"] == ("InstructionSubstitution")


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["general_summary"]["pass_count"] == 1
    assert payload["filtered_summary"]["general_symbolic"]["overview"]["symbolic_requested"] == 1
    assert payload["filtered_summary"]["general_gates"]["compact_summary"]["failed"] is False
    assert payload["filtered_summary"]["general_degradation"]["summary"]["degraded_validation"] is False
    assert payload["filtered_summary"]["general_discards"]["summary"]["count"] == 0


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

    assert result.exit_code == 0
    assert "Pass Region Evidence" in result.output
    assert "InstructionSubstitution" in result.output
    assert "equivalent=false" in result.output
    assert "mismatch_count=1" in result.output


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["failed_gates"] is True
    assert payload["filtered_summary"]["gate_failures"]["min_severity_failed"] is True
    assert payload["filtered_summary"]["gate_failure_compact_summary"]["failed"] is True


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

    assert result.exit_code == 0
    assert "Pass Symbolic Summary" in result.output
    assert "Pass Evidence Summary" in result.output
    assert "Pass Region Evidence" in result.output
    assert "Pass Validation Context" in result.output
    assert "Pass Capabilities" in result.output


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

    assert result.exit_code == 0
    assert "Gate Failure Summary" in result.output
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["gate_failures"]["require_pass_severity_failure_count"] == 1
    assert payload["filtered_summary"]["gate_failure_priority"][0]["pass_name"] == "NopInsertion"
    assert payload["filtered_summary"]["gate_failure_severity_priority"] == [{"severity": "clean", "failure_count": 1}]
    assert payload["filtered_summary"]["gate_failure_compact_summary"]["failed"] is True
    assert payload["filtered_summary"]["gate_failure_compact_summary"]["severity_priority"] == [
        {"severity": "clean", "failure_count": 1}
    ]
    assert payload["filtered_summary"]["gate_failure_final_by_pass"]["NopInsertion"]["failures"] == [
        "NopInsertion=not-requested(expected <= clean)"
    ]
    assert payload["filtered_summary"]["gate_failure_final_rows"][0]["pass_name"] == "NopInsertion"
    assert payload["filtered_summary"]["gate_failure_final_rows"][0]["failures"] == [
        "NopInsertion=not-requested(expected <= clean)"
    ]


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["mismatch_counts_by_pass"]["RegisterSubstitution"] == 2
    assert payload["filtered_summary"]["mismatch_observables_by_pass"]["RegisterSubstitution"] == ["rax", "rflags"]
    assert payload["filtered_summary"]["observable_mismatch_priority"][0]["pass_name"] == ("RegisterSubstitution")
    assert payload["filtered_summary"]["mismatch_compact_summary"]["pass_count"] == 1
    assert payload["filtered_summary"]["mismatch_final_by_pass"]["RegisterSubstitution"]["compact_region"] == {
        "region_count": 0,
        "region_mismatch_count": 0,
        "region_exit_match_count": 0,
    }
    assert payload["filtered_summary"]["mismatch_final_rows"][0]["pass_name"] == ("RegisterSubstitution")
    assert payload["filtered_summary"]["mismatch_final_rows"][0]["compact_region"] == {
        "region_count": 0,
        "region_mismatch_count": 0,
        "region_exit_match_count": 0,
    }
    assert payload["filtered_summary"]["mismatch_compact_by_pass"]["RegisterSubstitution"]["mismatch_count"] == 2


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["discarded_mutation_final_by_pass"]["RegisterSubstitution"]["reasons"] == [
        "runtime_validation_failed"
    ]


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["mismatch_counts_by_pass"] == {"RegisterSubstitution": 1}


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["gate_failure_compact_rows"][0]["pass_name"] == "NopInsertion"
    assert payload["filtered_summary"]["gate_failure_compact_rows"][0]["role"] == ("requested-mode")
    assert payload["filtered_summary"]["gate_failure_compact_rows"][0]["failed"] is True


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["symbolic_issue_passes"][0]["pass_name"] == "RegisterSubstitution"
    assert payload["filtered_summary"]["symbolic_coverage_by_pass"][0]["pass_name"] == "InstructionSubstitution"
    assert payload["filtered_summary"]["symbolic_severity_by_pass"][0]["pass_name"] == "InstructionSubstitution"


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

    assert result.exit_code == 0
    assert "Structural Risk Filter" in result.output
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["report_filters"]["only_structural_risk"] is True
    assert payload["filtered_summary"]["structural_risk_passes"] == ["BlockReordering"]
    assert payload["filtered_summary"]["pass_evidence"][0]["pass_name"] == "BlockReordering"


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

    assert result.exit_code == 0
    assert "Symbolic Risk Filter" in result.output
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["report_filters"]["only_symbolic_risk"] is True
    assert payload["filtered_summary"]["symbolic_risk_passes"] == ["RegisterSubstitution"]
    assert payload["filtered_summary"]["pass_evidence"][0]["pass_name"] == "RegisterSubstitution"


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

    assert result.exit_code == 0
    assert "Clean Pass Filter" in result.output
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["report_filters"]["only_clean_passes"] is True
    assert payload["filtered_summary"]["clean_passes"] == ["NopInsertion"]
    assert payload["filtered_summary"]["pass_risk_buckets"]["clean"] == ["NopInsertion"]
    assert payload["filtered_summary"]["pass_evidence"][0]["pass_name"] == "NopInsertion"


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

    assert result.exit_code == 0
    assert "Covered Pass Filter" in result.output
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["report_filters"]["only_covered_passes"] is True
    assert payload["filtered_summary"]["covered_passes"] == ["InstructionSubstitution"]
    assert payload["filtered_summary"]["pass_coverage_buckets"]["covered"] == ["InstructionSubstitution"]
    assert payload["filtered_summary"]["pass_evidence"][0]["pass_name"] == ("InstructionSubstitution")


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

    assert result.exit_code == 0
    assert "Uncovered Pass Filter" in result.output
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["report_filters"]["only_uncovered_passes"] is True
    assert payload["filtered_summary"]["uncovered_passes"] == ["ReportFixture"]
    assert payload["filtered_summary"]["pass_coverage_buckets"]["uncovered"] == ["ReportFixture"]
    assert payload["filtered_summary"]["pass_evidence"][0]["pass_name"] == "ReportFixture"


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

    assert result.exit_code == 0
    assert "Filtered Mismatch Mutations: 1" in result.output
    assert '"pass_name": "InstructionSubstitution"' in result.output
    assert '"pass_name": "NopInsertion"' not in result.output
    assert '"only_pass": "InstructionSubstitution"' in result.output
    assert '"only_mismatches": true' in result.output


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

    assert result.exit_code == 0
    assert '"symbolic_status": "bounded-step-observable-mismatch"' in result.output
    assert '"symbolic_status": "bounded-step-observables-match"' not in result.output
    assert '"only_status": "bounded-step-observable-mismatch"' in result.output


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

    assert result.exit_code == 0
    assert "Filtered Mismatch Mutations: 1" in result.output
    assert '"pass_name": "InstructionSubstitution"' in result.output
    assert '"pass_name": "NopInsertion"' not in result.output
    assert '"only_status": "bounded-step-observable-mismatch"' in result.output
    assert '"only_pass": "InstructionSubstitution"' in result.output
    assert '"only_mismatches": true' in result.output


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

    assert result.exit_code == 0
    assert "Symbolic Mutation Summary" in result.output
    assert "Passes With Symbolic Issues" in result.output
    assert "Pass Capabilities" in result.output
    assert "runtime recommended=yes" in result.output
    assert "symbolic confidence=best" in result.output
    assert "among stable passes" in result.output
    assert "Symbolic Mismatches" in result.output
    assert '"mutations"' not in result.output


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

    assert result.exit_code == 0
    assert "Filtered Mismatch Mutations: 1" in result.output
    assert "Mismatch Pass Summary" in result.output
    assert "InstructionSubstitution" in result.output
    assert "mismatch_count=1" in result.output
    assert '"mutations"' not in result.output


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

    assert result.exit_code == 0
    assert "Filtered Mismatch Mutations: 0" in result.output
    assert "Mismatch Pass Summary" in result.output
    assert "InstructionSubstitution" in result.output
    assert "mismatch_count=2" in result.output
    assert "observables=eax,eflags" in result.output


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["pass_capabilities"]["RegisterSubstitution"]["runtime"]["recommended"] is True


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["symbolic_issue_passes"][0]["pass_name"] == "InstructionSubstitution"
    assert payload["filtered_summary"]["symbolic_issue_passes"][0]["severity"] == "mismatch"
    assert payload["filtered_summary"]["symbolic_issue_passes"][1]["pass_name"] == "BlockReordering"
    assert payload["filtered_summary"]["symbolic_issue_passes"][1]["severity"] == "without-coverage"


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["symbolic_coverage_by_pass"][0]["pass_name"] == "InstructionSubstitution"
    assert payload["filtered_summary"]["symbolic_coverage_by_pass"][0]["symbolic_requested"] == 2
    assert payload["filtered_summary"]["symbolic_coverage_by_pass"][0]["observable_match"] == 1
    assert payload["filtered_summary"]["symbolic_coverage_by_pass"][0]["observable_mismatch"] == 1


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

    assert result.exit_code == 0
    assert "Severity Priority" in result.output
    assert "severity=mismatch" in result.output
    assert "issue_count=1" in result.output
    assert "severity=mismatch" in result.output
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["symbolic_severity_by_pass"][0]["pass_name"] == "InstructionSubstitution"
    assert payload["filtered_summary"]["symbolic_severity_by_pass"][0]["severity"] == "mismatch"


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

    assert result.exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["filtered_summary"]["mismatch_counts_by_pass"]["InstructionSubstitution"] == 2
    assert payload["filtered_summary"]["mismatch_observables_by_pass"]["InstructionSubstitution"] == [
        "eax",
        "eflags",
    ]
    assert payload["filtered_summary"]["pass_validation_context"]["InstructionSubstitution"]["role"] == "requested-mode"
