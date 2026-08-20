from r2morph.analysis.symbolic.syntia_learning import learn_instruction_semantics
from r2morph.analysis.symbolic.syntia_models import InstructionSemantics
from tests.utils.assertions import expect

_EXPECTED_SEMANTICS_ADDRESS_4096 = 0x1000
_EXPECTED_SEMANTICS_CONFIDENCE_0_75 = 0.75


class _LearningFramework:
    def __init__(self) -> None:
        self.semantics_cache: dict[bytes, InstructionSemantics] = {}
        self.synthesis_stats: dict[str, int] = {
            "instructions_analyzed": 0,
            "semantics_learned": 0,
            "synthesis_failures": 0,
            "cache_hits": 0,
        }

    def _fallback_semantic_analysis(self, instruction_bytes: bytes, disassembly: str) -> dict[str, object]:
        return {"semantics": f"fallback:{disassembly}", "confidence": 0.75}

    def _assess_semantic_complexity(self, semantics: InstructionSemantics) -> object:
        return "simple"


def test_syntia_learning_contract_misses_and_caches() -> None:
    framework = _LearningFramework()

    semantics = learn_instruction_semantics(framework, b"\x90", 0x1000, "nop")

    expect(semantics.address == _EXPECTED_SEMANTICS_ADDRESS_4096)
    expect(semantics.learned_semantics == "fallback:nop")
    expect(semantics.confidence == _EXPECTED_SEMANTICS_CONFIDENCE_0_75)
    expect(semantics.complexity == "simple")
    expect(not (framework.semantics_cache[b"\x90"] is not semantics))
    expect(framework.synthesis_stats["instructions_analyzed"] == 1)
    expect(framework.synthesis_stats["cache_hits"] == 0)


def test_syntia_learning_contract_reuses_cache() -> None:
    framework = _LearningFramework()
    cached = InstructionSemantics(address=0x1000, instruction_bytes=b"\x90", disassembly="nop")
    framework.semantics_cache[b"\x90"] = cached

    semantics = learn_instruction_semantics(framework, b"\x90", 0x1001, "mov eax, ebx")

    expect(not (semantics is not cached))
    expect(framework.synthesis_stats["cache_hits"] == 1)
    expect(framework.synthesis_stats["instructions_analyzed"] == 0)
