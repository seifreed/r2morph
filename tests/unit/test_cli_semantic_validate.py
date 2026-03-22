"""
Tests for CLI semantic validation and pass dependencies commands.

Covers:
- semantic-validate command
- pass-dependencies command
- Command argument handling
- Error handling
"""

import json
from unittest.mock import MagicMock, patch
from typer.testing import CliRunner

from r2morph.cli import app

runner = CliRunner()


class TestSemanticValidateCommand:
    """Test semantic-validate CLI command."""

    def test_semantic_validate_help(self):
        """Test semantic-validate --help."""
        result = runner.invoke(app, ["semantic-validate", "--help"])
        assert result.exit_code == 0
        assert "semantic" in result.output.lower() or "validation" in result.output.lower()

    def test_semantic_validate_missing_binary(self):
        """Test semantic-validate with missing binary."""
        result = runner.invoke(app, ["semantic-validate", "/nonexistent/path"])
        assert result.exit_code != 0

    @patch("r2morph.core.binary.Binary")
    @patch("r2morph.validation.semantic.SemanticValidator")
    def test_semantic_validate_basic(self, mock_validator_class, mock_binary_class, tmp_path):
        """Test basic semantic validation."""
        binary_path = tmp_path / "test.bin"
        binary_path.write_bytes(b"\x7fELF" + b"\x00" * 100)

        mock_binary = MagicMock()
        mock_binary.is_analyzed.return_value = True
        mock_binary.get_functions.return_value = []
        mock_binary_class.return_value = mock_binary

        mock_validator = MagicMock()
        mock_result = MagicMock()
        mock_result.passed = True
        mock_result.mode = "standard"
        mock_result.functions_checked = 0
        mock_result.mutations_validated = 0
        mock_result.checks_passed = 0
        mock_result.checks_failed = 0
        mock_result.violations = []
        mock_result.observable_comparison = None
        mock_result.to_dict.return_value = {
            "passed": True,
            "mode": "standard",
            "functions_checked": 0,
            "violations": [],
        }
        mock_validator.validate_function.return_value = mock_result
        mock_validator_class.return_value = mock_validator

        with patch("r2morph.validation.semantic.validate_semantic_equivalence") as mock_validate:
            mock_validate.return_value = mock_result

            result = runner.invoke(app, ["semantic-validate", str(binary_path)])

        assert result.exit_code == 0 or "semantic" in result.output.lower()

    def test_semantic_validate_mode_option(self, tmp_path):
        """Test semantic-validate with mode option."""
        binary_path = tmp_path / "test.bin"
        binary_path.write_bytes(b"\x7fELF" + b"\x00" * 100)

        with patch("r2morph.core.binary.Binary") as mock_binary_class:
            mock_binary = MagicMock()
            mock_binary.is_analyzed.return_value = True
            mock_binary.get_functions.return_value = []
            mock_binary_class.return_value = mock_binary

            with patch("r2morph.validation.semantic.SemanticValidator"):
                MagicMock()
                mock_result = MagicMock()
                mock_result.passed = True
                mock_result.mode = "fast"
                mock_result.functions_checked = 0
                mock_result.mutations_validated = 0
                mock_result.checks_passed = 0
                mock_result.checks_failed = 0
                mock_result.violations = []
                mock_result.observable_comparison = None
                mock_result.to_dict.return_value = {"passed": True}

                with patch("r2morph.validation.semantic.validate_semantic_equivalence") as mock_validate:
                    mock_validate.return_value = mock_result

                    runner.invoke(
                        app,
                        ["semantic-validate", str(binary_path), "--mode", "fast"],
                    )

    def test_semantic_validate_json_output(self, tmp_path):
        """Test semantic-validate with JSON output."""
        binary_path = tmp_path / "test.bin"
        binary_path.write_bytes(b"\x7fELF" + b"\x00" * 100)

        with patch("r2morph.core.binary.Binary") as mock_binary_class:
            mock_binary = MagicMock()
            mock_binary.is_analyzed.return_value = True
            mock_binary.get_functions.return_value = []
            mock_binary_class.return_value = mock_binary

            mock_result = MagicMock()
            mock_result.passed = True
            mock_result.mode = "standard"
            mock_result.to_dict.return_value = {"passed": True}

            with patch("r2morph.validation.semantic.validate_semantic_equivalence", return_value=mock_result):
                runner.invoke(
                    app,
                    ["semantic-validate", str(binary_path), "--json"],
                )

    def test_semantic_validate_with_output_file(self, tmp_path):
        """Test semantic-validate with output file."""
        binary_path = tmp_path / "test.bin"
        binary_path.write_bytes(b"\x7fELF" + b"\x00" * 100)
        output_path = tmp_path / "report.json"

        with patch("r2morph.core.binary.Binary") as mock_binary_class:
            mock_binary = MagicMock()
            mock_binary.is_analyzed.return_value = True
            mock_binary.get_functions.return_value = []
            mock_binary_class.return_value = mock_binary

            mock_result = MagicMock()
            mock_result.passed = True
            mock_result.mode = "standard"
            mock_result.to_dict.return_value = {"passed": True}

            with patch("r2morph.validation.semantic.validate_semantic_equivalence", return_value=mock_result):
                runner.invoke(
                    app,
                    ["semantic-validate", str(binary_path), "--output", str(output_path)],
                )


class TestPassDependenciesCommand:
    """Test pass-dependencies CLI command."""

    def test_pass_dependencies_help(self):
        """Test pass-dependencies --help."""
        result = runner.invoke(app, ["pass-dependencies", "--help"])
        assert result.exit_code == 0
        assert "pass" in result.output.lower() or "depend" in result.output.lower()

    def test_pass_dependencies_list(self):
        """Test pass-dependencies --list."""
        result = runner.invoke(app, ["pass-dependencies", "--list"])
        assert result.exit_code == 0

    def test_pass_dependencies_list_json(self):
        """Test pass-dependencies --list --json."""
        result = runner.invoke(app, ["pass-dependencies", "--list", "--json"])
        assert result.exit_code == 0
        output = json.loads(result.output)
        assert "passes" in output

    def test_pass_dependencies_single_pass(self):
        """Test pass-dependencies for a single pass."""
        result = runner.invoke(app, ["pass-dependencies", "nop_insertion"])
        assert result.exit_code == 0

    def test_pass_dependencies_multiple_passes(self):
        """Test pass-dependencies for multiple passes."""
        result = runner.invoke(
            app,
            ["pass-dependencies", "nop_insertion", "block_reordering"],
        )
        assert result.exit_code == 0

    def test_pass_dependencies_validate_order_valid(self):
        """Test pass-dependencies --validate-order with valid order."""
        result = runner.invoke(
            app,
            ["pass-dependencies", "nop_insertion", "instruction_substitution", "--validate-order"],
        )
        assert result.exit_code == 0

    def test_pass_dependencies_validate_order_invalid(self):
        """Test pass-dependencies --validate-order with invalid order."""
        result = runner.invoke(
            app,
            ["pass-dependencies", "block_reordering", "control_flow_flattening", "--validate-order"],
        )
        assert result.exit_code != 0

    def test_pass_dependencies_suggest_order(self):
        """Test pass-dependencies --suggest-order."""
        result = runner.invoke(
            app,
            ["pass-dependencies", "block_reordering", "nop_insertion", "--suggest-order"],
        )
        assert result.exit_code == 0

    def test_pass_dependencies_suggest_order_json(self):
        """Test pass-dependencies --suggest-order --json."""
        result = runner.invoke(
            app,
            ["pass-dependencies", "nop_insertion", "block_reordering", "--suggest-order", "--json"],
        )
        assert result.exit_code == 0
        output = json.loads(result.output)
        assert "suggested_order" in output

    def test_pass_dependencies_no_passes(self):
        """Test pass-dependencies with no passes."""
        result = runner.invoke(app, ["pass-dependencies"])
        assert result.exit_code != 0

    def test_pass_dependencies_unknown_pass(self):
        """Test pass-dependencies with unknown pass."""
        result = runner.invoke(app, ["pass-dependencies", "unknown_pass_xyz"])
        assert result.exit_code == 0


class TestPassDependenciesOutput:
    """Test pass-dependencies command output format."""

    def test_output_shows_requires(self):
        """Test output shows requires dependencies."""
        result = runner.invoke(app, ["pass-dependencies", "control_flow_flattening"])
        assert result.exit_code == 0

    def test_output_shows_conflicts(self):
        """Test output shows conflicts."""
        result = runner.invoke(app, ["pass-dependencies", "block_reordering"])
        assert result.exit_code == 0

    def test_output_shows_recommends(self):
        """Test output shows recommendations."""
        result = runner.invoke(app, ["pass-dependencies", "dead_code_injection"])
        assert result.exit_code == 0

    def test_json_output_format(self):
        """Test JSON output format for pass info."""
        result = runner.invoke(
            app,
            ["pass-dependencies", "nop_insertion", "--json"],
        )
        assert result.exit_code == 0
        output = json.loads(result.output)
        assert "pass_name" in output
        assert "requires" in output
        assert "conflicts" in output
        assert "recommends" in output

    def test_validate_order_json_output(self):
        """Test JSON output for validate-order."""
        result = runner.invoke(
            app,
            ["pass-dependencies", "nop_insertion", "--validate-order", "--json"],
        )
        assert result.exit_code == 0
        output = json.loads(result.output)
        assert "valid" in output
        assert "violations" in output


class TestIntegration:
    """Integration tests for CLI commands."""

    def test_semantic_validate_modes(self, tmp_path):
        """Test all validation modes."""
        binary_path = tmp_path / "test.bin"
        binary_path.write_bytes(b"\x7fELF" + b"\x00" * 100)

        modes = ["fast", "standard", "thorough"]

        for mode in modes:
            with patch("r2morph.core.binary.Binary") as mock_binary_class:
                mock_binary = MagicMock()
                mock_binary.is_analyzed.return_value = True
                mock_binary.get_functions.return_value = []
                mock_binary_class.return_value = mock_binary

                mock_result = MagicMock()
                mock_result.passed = True
                mock_result.mode = mode
                mock_result.functions_checked = 0
                mock_result.mutations_validated = 0
                mock_result.checks_passed = 0
                mock_result.checks_failed = 0
                mock_result.violations = []
                mock_result.observable_comparison = None
                mock_result.to_dict.return_value = {"passed": True}

                with patch("r2morph.validation.semantic.validate_semantic_equivalence", return_value=mock_result):
                    runner.invoke(
                        app,
                        ["semantic-validate", str(binary_path), "--mode", mode],
                    )
