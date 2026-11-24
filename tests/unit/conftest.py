"""Shared unit-test doubles for external instrumentation backends."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from r2morph.instrumentation import frida_engine


@pytest.fixture
def frida_device(monkeypatch: pytest.MonkeyPatch) -> Mock:
    """Provide a local Frida device double without loading its native runtime."""
    device = Mock()
    device.name = "unit-test-device"
    device.enumerate_processes.return_value = []
    device.spawn.return_value = 1234
    device.attach.return_value = Mock()
    module = SimpleNamespace(get_local_device=lambda: device)
    monkeypatch.setattr(frida_engine, "FRIDA_AVAILABLE", True)
    monkeypatch.setattr(frida_engine, "_load_frida", lambda: module)
    return device
