import json
from pathlib import Path

from click.testing import CliRunner
from typer.main import get_command

from r2morph.cli import analyze as analyze_cmd
from r2morph.cli import app
from r2morph.cli import functions as functions_cmd
from tests.utils.assertions import expect

runner = CliRunner()
app_cmd = get_command(app)


def test_cli_help_and_simple_mode(tmp_path):
    result = runner.invoke(app_cmd, ["--help"])
    expect(result.exit_code == 0)

    binary_path = Path("fixtures/dataset/elf_x86_64")
    output_path = tmp_path / "elf_simple"

    result = runner.invoke(app_cmd, ["morph", str(binary_path), "-o", str(output_path), "-m", "nop"])
    expect(result.exit_code == 0, f"morph failed: {result.output}")
    expect(output_path.exists())


def test_cli_direct_analyze_and_functions(capfd):
    binary_path = Path("fixtures/dataset/elf_x86_64")
    analyze_cmd(binary_path, verbose=False)
    functions_cmd(binary_path, limit=5, verbose=False)
    events = capfd.readouterr().err
    expect("operation=cli.analyze" in events and "operation=cli.functions" in events)


def test_cli_diff_logs_operation_completion(capfd):
    binary_path = Path("fixtures/dataset/elf_x86_64")
    result = runner.invoke(app_cmd, ["diff", str(binary_path), str(binary_path)])
    stderr = capfd.readouterr().err

    expect(result.exit_code == 0 and "operation=cli.diff" in stderr)


def test_cli_validate_logs_runtime_outcome(capfd):
    binary_path = Path("fixtures/dataset/elf_x86_64")
    result = runner.invoke(
        app_cmd,
        ["validate", str(binary_path), str(binary_path)],
        env={"R2MORPH_LOG_FORMAT": "json"},
    )
    stderr = capfd.readouterr().err
    validation_result = json.loads(result.output)
    outcome_event = next(
        json.loads(line) for line in stderr.splitlines() if '"event_name":"cli.validate.result"' in line
    )
    completion_event = next(
        json.loads(line) for line in stderr.splitlines() if '"event_name":"cli.validate.completed"' in line
    )

    expect(
        result.exit_code == (0 if validation_result["passed"] else 1)
        and outcome_event["status"] == ("passed" if validation_result["passed"] else "failed")
        and outcome_event["outcome"] == ("success" if validation_result["passed"] else "failure")
        and outcome_event["correlation_id"] == completion_event["correlation_id"]
    )


def test_cli_direct_morph(tmp_path):
    binary_path = Path("fixtures/dataset/elf_x86_64")
    output_path = tmp_path / "elf_morphed"

    result = runner.invoke(
        app_cmd,
        ["morph", str(binary_path), "-o", str(output_path), "-m", "nop"],
    )
    expect(result.exit_code == 0, f"morph failed: {result.output}")
    expect(output_path.exists())
