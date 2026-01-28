from r2morph.detection.control_flow_detector import ControlFlowAnalyzer


def test_control_flow_analyzer_get_function_address_prefers_offset():
    analyzer = ControlFlowAnalyzer(binary=None)

    func = {"offset": 0x1234, "addr": 0x9999}
    assert analyzer._get_function_address(func) == 0x1234


def test_control_flow_analyzer_get_function_address_fallbacks():
    analyzer = ControlFlowAnalyzer(binary=None)

    func = {"addr": 0x5678}
    assert analyzer._get_function_address(func) == 0x5678

    assert analyzer._get_function_address({}) == 0
