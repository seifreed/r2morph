"""A real BinarySignerProtocol double that records calls instead of signing."""

from __future__ import annotations

from pathlib import Path
from typing import Any


class RecordingBinarySigner:
    """Records every sign_output call; performs no signing side effects."""

    def __init__(self) -> None:
        self.calls: list[tuple[Path, dict[str, Any]]] = []

    def sign_output(self, output_path: Path, config: dict[str, Any]) -> None:
        self.calls.append((output_path, config))
