from r2morph.detection.control_flow_detector import ControlFlowAnalyzer
from tests.utils.assertions import expect

_EXPECTED_ANALYZER_GET_FUNCTION_ADDRESS_FUNC_22136 = 0x5678
_EXPECTED_ANALYZER_GET_FUNCTION_ADDRESS_FUNC_4660 = 0x1234


def test_control_flow_analyzer_get_function_address_prefers_offset():
    analyzer = ControlFlowAnalyzer(binary=None)

    func = {"offset": 0x1234, "addr": 0x9999}
    expect(analyzer._get_function_address(func) == _EXPECTED_ANALYZER_GET_FUNCTION_ADDRESS_FUNC_4660)


def test_control_flow_analyzer_get_function_address_fallbacks():
    analyzer = ControlFlowAnalyzer(binary=None)

    func = {"addr": 0x5678}
    expect(analyzer._get_function_address(func) == _EXPECTED_ANALYZER_GET_FUNCTION_ADDRESS_FUNC_22136)

    expect(analyzer._get_function_address({}) == 0)
