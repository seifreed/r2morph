"""
Unit tests for TUI (Terminal User Interface).
"""

import pytest

from r2morph.tui import (
    TUIAction,
    TUIFunction,
    TUIMutation,
    TUIPass,
    TUIProgress,
    TUIResult,
    TUIMainScreen,
    TUIFunctionScreen,
    TUIPassScreen,
    TUIPreviewScreen,
    TUIProgressIndicator,
    MutationTUI,
    create_default_passes,
    run_interactive_mode,
)


class TestTUITypes:
    def test_tui_action_values(self):
        assert TUIAction.SELECT_FUNCTIONS == "select_functions"
        assert TUIAction.SELECT_PASSES == "select_passes"
        assert TUIAction.PREVIEW_MUTATIONS == "preview_mutations"
        assert TUIAction.CONFIRM == "confirm"
        assert TUIAction.EXECUTE == "execute"
        assert TUIAction.CANCEL == "cancel"

    def test_tui_function(self):
        func = TUIFunction(address=0x1000, name="main", size=256, selected=False)
        assert func.address == 0x1000
        assert func.name == "main"
        assert func.size == 256
        assert func.selected is False

    def test_tui_function_selected(self):
        func = TUIFunction(address=0x2000, name="test", size=128, selected=True)
        assert func.selected is True

    def test_tui_pass(self):
        mp = TUIPass(
            name="nop",
            description="Insert NOP instructions",
            is_stable=True,
            selected=False,
        )
        assert mp.name == "nop"
        assert mp.description == "Insert NOP instructions"
        assert mp.is_stable is True
        assert mp.selected is False

    def test_tui_pass_configurable(self):
        mp = TUIPass(
            name="cff",
            description="Control flow flattening",
            is_stable=False,
            configurable=True,
            config={"depth": 2},
        )
        assert mp.configurable is True
        assert mp.config == {"depth": 2}

    def test_tui_mutation(self):
        mutation = TUIMutation(
            address=0x1000,
            function="main",
            pass_name="nop",
            original_bytes=b"\x90",
            mutated_bytes=b"\x90\x90",
        )
        assert mutation.address == 0x1000
        assert mutation.function == "main"
        assert mutation.pass_name == "nop"
        assert mutation.original_bytes == b"\x90"
        assert mutation.mutated_bytes == b"\x90\x90"

    def test_tui_mutation_with_description(self):
        mutation = TUIMutation(
            address=0x1000,
            function=None,
            pass_name="substitute",
            original_bytes=b"\x75\x00",
            mutated_bytes=b"\x75\x00",
            description="Replaced JNE with equivalent",
        )
        assert mutation.description == "Replaced JNE with equivalent"

    def test_tui_progress(self):
        progress = TUIProgress(total=100, current=50, message="Processing")
        assert progress.total == 100
        assert progress.current == 50
        assert progress.message == "Processing"
        assert progress.status == "running"

    def test_tui_result(self):
        funcs = [TUIFunction(0x1000, "main", 100)]
        passes = [TUIPass("nop", "Insert NOP", True)]
        result = TUIResult(functions=funcs, passes=passes, confirmed=True)

        assert len(result.functions) == 1
        assert len(result.passes) == 1
        assert result.confirmed is True


class TestTUIScreens:
    def test_main_screen_initialization(self):
        screen = TUIMainScreen()
        assert screen.console is not None

    def test_function_screen_initialization(self):
        screen = TUIFunctionScreen()
        assert screen.console is not None

    def test_function_screen_render_basic(self):
        screen = TUIFunctionScreen()
        functions = [
            TUIFunction(0x1000, "main", 256, selected=True),
            TUIFunction(0x2000, "test", 128, selected=False),
        ]
        screen._render_basic(functions)

    def test_pass_screen_initialization(self):
        screen = TUIPassScreen()
        assert screen.console is not None

    def test_pass_screen_render_basic(self):
        screen = TUIPassScreen()
        passes = [
            TUIPass("nop", "Insert NOP", True, selected=True),
            TUIPass("cff", "Control flow", False, selected=False),
        ]
        screen._render_basic(passes)

    def test_preview_screen_initialization(self):
        screen = TUIPreviewScreen()
        assert screen.console is not None

    def test_preview_screen_render_basic(self):
        screen = TUIPreviewScreen()
        mutations = [
            TUIMutation(0x1000, "main", "nop", b"\x90", b"\x90\x90"),
            TUIMutation(0x1001, "main", "nop", b"\x90", b"\x90\x90"),
        ]
        screen._render_basic(mutations, page=0, page_size=10)


class TestTUIProgressIndicator:
    def test_progress_indicator_initialization(self):
        indicator = TUIProgressIndicator()
        assert indicator.console is not None

    def test_progress_indicator_stop(self):
        indicator = TUIProgressIndicator()
        indicator.stop()


class TestMutationTUI:
    def test_tui_initialization(self):
        tui = MutationTUI()
        assert tui.console is not None
        assert tui.main_screen is not None
        assert tui.function_screen is not None
        assert tui.pass_screen is not None
        assert tui.preview_screen is not None


class TestCreateDefaultPasses:
    def test_create_default_passes(self):
        passes = create_default_passes()

        assert len(passes) == 8

        stable_passes = [p for p in passes if p.is_stable]
        assert len(stable_passes) == 3

        experimental_passes = [p for p in passes if not p.is_stable]
        assert len(experimental_passes) == 5

        pass_names = [p.name for p in passes]
        assert "nop" in pass_names
        assert "substitute" in pass_names
        assert "register" in pass_names
        assert "block" in pass_names
        assert "dead-code" in pass_names
        assert "opaque" in pass_names
        assert "expand" in pass_names
        assert "cff" in pass_names

    def test_stable_passes_marked_correctly(self):
        passes = create_default_passes()

        for p in passes:
            if p.name in ("nop", "substitute", "register"):
                assert p.is_stable is True, f"{p.name} should be stable"
            else:
                assert p.is_stable is False, f"{p.name} should be experimental"


class TestRunInteractiveMode:
    def test_create_default_passes_integration(self):
        functions = [
            {"address": 0x1000, "name": "main", "size": 256},
            {"address": 0x2000, "name": "test", "size": 128},
        ]

        passes = create_default_passes()
        assert len(passes) == 8

    def test_run_interactive_mode_type_check(self):
        functions = [
            {"address": 0x1000, "name": "main", "size": 256},
        ]

        tui_functions = [
            TUIFunction(
                address=f.get("address", 0),
                name=f.get("name", "unknown"),
                size=f.get("size", 0),
            )
            for f in functions
        ]
        assert len(tui_functions) == 1
        assert tui_functions[0].address == 0x1000


class TestTUIPassScreenDescriptions:
    def test_pass_descriptions_exist(self):
        descriptions = TUIPassScreen.PASS_DESCRIPTIONS

        assert "nop" in descriptions
        assert "substitute" in descriptions
        assert "register" in descriptions
        assert "block" in descriptions
        assert "dead-code" in descriptions
        assert "opaque" in descriptions
        assert "expand" in descriptions
        assert "cff" in descriptions

        for name, (desc, is_stable) in descriptions.items():
            assert isinstance(desc, str)
            assert len(desc) > 0
            assert isinstance(is_stable, bool)
