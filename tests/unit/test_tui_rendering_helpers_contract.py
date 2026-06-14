from types import SimpleNamespace

from r2morph.tui_presets import PASS_DESCRIPTIONS
from r2morph.tui_rendering_helpers import (
    build_config_basic_lines,
    build_config_rich_rows,
    build_function_basic_lines,
    build_function_rich_rows,
    build_main_menu_actions,
    build_pass_basic_lines,
    build_pass_rich_rows,
    build_preview_basic_lines,
    build_preview_rich_rows,
)


def test_build_main_menu_actions_preserves_order() -> None:
    assert build_main_menu_actions()[0] == ("F", "Select Functions", "Choose functions to mutate")


def test_build_function_rich_rows_truncates_and_formats() -> None:
    rows = build_function_rich_rows(
        [
            SimpleNamespace(address=0x1000, name="main", size=256, selected=True),
            SimpleNamespace(address=0x2000, name="test", size=128, selected=False),
        ],
        limit=1,
    )

    assert rows == [("X", "0x1000", "main", "256")]


def test_build_function_basic_lines_include_indices() -> None:
    lines = build_function_basic_lines(
        [
            SimpleNamespace(address=0x1000, name="main", size=256, selected=True),
        ]
    )

    assert lines == ["[X] 0: 0x1000 main (256 bytes)"]


def test_build_pass_rich_rows_include_status_markup() -> None:
    expected_desc = PASS_DESCRIPTIONS["nop"][0]
    rows = build_pass_rich_rows(
        [
            SimpleNamespace(name="nop", description="Insert NOP", selected=True, is_stable=True),
        ]
    )

    assert rows == [("X", "nop", "[green]stable[/green]", expected_desc)]


def test_build_pass_basic_lines_include_description() -> None:
    expected_desc = PASS_DESCRIPTIONS["nop"][0]
    lines = build_pass_basic_lines(
        [
            SimpleNamespace(name="nop", description="Insert NOP", selected=False, is_stable=True),
        ]
    )

    assert lines == [f"[ ] 0: nop (stable) - {expected_desc}"]


def test_build_config_rows_use_types_and_defaults() -> None:
    rich_rows = build_config_rich_rows(
        "nop",
        {"enabled": True, "depth": 3, "mode": "fast"},
    )
    basic_lines = build_config_basic_lines("nop", {"enabled": True, "depth": 3, "mode": "fast"})

    assert ("enabled", "bool", "true", "true | false") in rich_rows
    assert ("depth", "int", "3", "<number>") in rich_rows
    assert ("mode", "str", "fast", "<value>") in rich_rows
    assert basic_lines == ["  enabled: True", "  depth: 3", "  mode: fast"]


def test_build_preview_rows_format_bytes_and_names() -> None:
    mutations = [
        SimpleNamespace(
            address=0x1000,
            function="main",
            pass_name="nop",
            original_bytes=b"\x90\x90\x90\x90",
            mutated_bytes=b"\x90\x90\x90\x90\x90\x90",
            description="",
        )
    ]

    rich_rows = build_preview_rich_rows(mutations, start=0, end=1)
    basic_lines = build_preview_basic_lines(mutations, start=0, end=1)

    assert rich_rows == [("0x1000", "main", "nop", "90909090", "909090909090")]
    assert basic_lines[0] == "0x1000 | main                 | nop            "
