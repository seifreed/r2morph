from r2morph import factories


def test_factories_only_expose_core_construction_helpers() -> None:
    assert hasattr(factories, "create_binary_reader")
    assert hasattr(factories, "create_binary_writer")
    assert hasattr(factories, "create_assembly_service")
    assert hasattr(factories, "create_memory_manager")

    assert not hasattr(factories, "create_report_emitter")
    assert not hasattr(factories, "create_console_renderer")
    assert not hasattr(factories, "create_gate_evaluator")
    assert not hasattr(factories, "create_summary_aggregator")
