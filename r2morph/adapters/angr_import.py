"""Optional angr import boundary."""

from __future__ import annotations

import importlib
import warnings
from dataclasses import dataclass
from typing import Any

_PY314_CTYPES_PACK_WARNING = r"Due to '_pack_', the '.*' Structure.*"


class _ScopedPycparserParser:
    """Provide angr's scope-aware parser call against pycparser 3's parser core."""

    def __init__(self, owner: Any, parser_module: Any) -> None:
        self.owner = owner
        self.parser_module = parser_module

    def parse(self, input: str, lexer: Any, debug: bool = False) -> Any:
        self.owner.clex = lexer
        self.owner.clex.input(input, self.owner.clex.filename)
        self.owner._tokens = self.parser_module._TokenStream(self.owner.clex)
        ast = self.owner._parse_translation_unit_or_empty()
        token = self.owner._peek()
        if token is not None:
            self.owner._parse_error(f"before: {token.value}", self.owner._tok_coord(token))
        return ast


def _install_pycparser_filename_compatibility() -> None:
    """Bridge the pycparser 3.0 filename setter removed from its lexer API."""
    try:
        pycparser_lexer = importlib.import_module("pycparser.c_lexer")
    except ImportError:
        return

    filename_property = pycparser_lexer.CLexer.filename
    if isinstance(filename_property, property) and filename_property.fset is None:
        pycparser_lexer.CLexer.filename = property(
            filename_property.fget,
            lambda lexer, filename: setattr(lexer, "_filename", filename),
        )
    if not hasattr(pycparser_lexer.CLexer, "reset_lineno"):
        pycparser_lexer.CLexer.reset_lineno = lambda lexer: setattr(lexer, "_lineno", 1)

    pycparser_parser = importlib.import_module("pycparser.c_parser")
    parser_class = pycparser_parser.CParser
    if not hasattr(parser_class, "cparser"):
        original_init = parser_class.__init__

        def init_with_angr_parser(self: Any, *args: Any, **kwargs: Any) -> None:
            original_init(self, *args, **kwargs)
            self.cparser = _ScopedPycparserParser(self, pycparser_parser)

        parser_class.__init__ = init_with_angr_parser


@dataclass(frozen=True)
class AngrImport:
    available: bool
    angr: Any | None = None
    claripy: Any | None = None
    project: Any | None = None
    cfg_fast: Any | None = None
    exploration_technique: Any | None = None


def import_angr_modules(
    *,
    claripy: bool = False,
    project: bool = False,
    cfg_fast: bool = False,
    exploration_technique: bool = False,
) -> AngrImport:
    try:
        _install_pycparser_filename_compatibility()
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message=_PY314_CTYPES_PACK_WARNING, category=DeprecationWarning)
            angr_module = importlib.import_module("angr")
            claripy_module = importlib.import_module("claripy") if claripy else None
            project_class = angr_module.Project if project else None
            cfg_fast_class = importlib.import_module("angr.analyses").CFGFast if cfg_fast else None
            technique_class = (
                importlib.import_module("angr.exploration_techniques").ExplorationTechnique
                if exploration_technique
                else None
            )
    except ImportError:
        return AngrImport(available=False)

    return AngrImport(
        available=True,
        angr=angr_module,
        claripy=claripy_module,
        project=project_class,
        cfg_fast=cfg_fast_class,
        exploration_technique=technique_class,
    )
