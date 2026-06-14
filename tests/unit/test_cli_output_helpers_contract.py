from types import SimpleNamespace

from r2morph.cli_output_helpers import (
    build_binary_analysis_rows,
    build_function_limit_notice,
    build_function_rows,
)


def test_build_binary_analysis_rows_formats_numeric_fields() -> None:
    rows = build_binary_analysis_rows(
        {
            "architecture": {"arch": "x86", "bits": 64, "format": "elf", "endian": "little"},
            "total_functions": 3,
            "total_instructions": 42,
            "total_basic_blocks": 7,
            "total_code_size": 512,
            "avg_function_size": 170.5,
            "avg_instructions_per_function": 14.0,
        }
    )

    assert rows[0] == ("Architecture", "x86 (64-bit)")
    assert rows[-1] == ("Avg Instructions/Function", "14.00")


def test_build_function_rows_preserves_display_order() -> None:
    rows = build_function_rows(
        [
            SimpleNamespace(address=0x1000, name="main", size=256, get_instructions_count=lambda: 12),
            SimpleNamespace(address=0x2000, name="test", size=128, get_instructions_count=lambda: 8),
        ],
        limit=1,
    )

    assert rows == [("0x1000", "main", "256", "12")]


def test_build_function_limit_notice_only_shows_when_truncated() -> None:
    assert build_function_limit_notice(10, 5) is None
    assert build_function_limit_notice(10, 11) == "Showing 10 of 11 functions. Use --limit to show more."
