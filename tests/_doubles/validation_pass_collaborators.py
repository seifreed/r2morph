class FakeAnnotator:
    def _annotate_mutations_with_symbolic_metadata(self, pass_result, metadata):
        for mutation in pass_result["mutations"]:
            mutation.setdefault("metadata", {})["annotated"] = metadata["symbolic_status"]


class FakeComparator:
    def _compare_real_binary_regions(self, binary, pass_result, bridge_module):
        return {
            "symbolic_binary_check_performed": True,
            "symbolic_binary_equivalent": True,
            "symbolic_binary_reason": "matched",
        }


class FakeSymbolicValidator:
    def __init__(self):
        self._binary_comparator = FakeComparator()
        self._mutation_annotator = FakeAnnotator()

    def _run_symbolic_precheck(self, binary, pass_result):
        return {
            "symbolic_requested": True,
            "symbolic_status": "checked",
            "symbolic_reason": "ok",
        }


class FakeAbiValidator:
    def __init__(self, issues):
        self._issues = issues

    def collect_violations(self, binary, pass_result):
        return list(self._issues)
