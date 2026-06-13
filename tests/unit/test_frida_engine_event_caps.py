"""Regression tests for the §10 retention bound on Frida runtime events.

FridaEngine accumulates api_call / anti-analysis / memory-operation events
as scripts report them. A long instrumentation session must not grow these
collections without limit, so each is a deque capped at MAX_RUNTIME_EVENTS;
the running totals live in self.stats and are unaffected by the cap.

These tests need no real Frida runtime - _on_script_message is a plain
handler driven with the message dicts Frida would deliver.
"""

from r2morph.instrumentation.frida_engine import MAX_RUNTIME_EVENTS, FridaEngine


def _send(payload_type: str) -> dict:
    return {"type": "send", "payload": {"type": payload_type, "function": "f"}}


def test_anti_analysis_events_are_capped():
    engine = FridaEngine()
    overflow = 5

    for _ in range(MAX_RUNTIME_EVENTS + overflow):
        engine._on_script_message(_send("anti_debug"), None)

    assert len(engine.anti_analysis_events) == MAX_RUNTIME_EVENTS


def test_api_calls_capped_but_running_total_preserved():
    engine = FridaEngine()
    overflow = 3
    total = MAX_RUNTIME_EVENTS + overflow

    for _ in range(total):
        engine._on_script_message(_send("api_call"), None)

    # retained sample is bounded, but the running counter keeps the true total
    assert len(engine.api_calls) == MAX_RUNTIME_EVENTS
    assert engine.stats["api_calls_intercepted"] == total


def test_memory_accesses_are_capped():
    engine = FridaEngine()

    for _ in range(MAX_RUNTIME_EVENTS + 2):
        engine._on_script_message(_send("memory_operation"), None)

    assert len(engine.memory_accesses) == MAX_RUNTIME_EVENTS
