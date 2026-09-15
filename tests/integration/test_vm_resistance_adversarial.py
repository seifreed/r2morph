"""Real automated adversarial evidence for diversified VM builds."""

from pathlib import Path
from typing import cast

from scripts.vm_resistance_adversarial import measure, measure_corpus
from tests.utils.assertions import expect

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / "elf_vm_shift_x86_64"
_EXPECTED_SEED_COUNT = 4
_EXPECTED_TAMPER_PROBE_COUNT = 8
_EXPECTED_CORPUS_FIXTURE_COUNT = 2
_CORPUS_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dataset" / "elf_vm_bigimm_x86_64"


def test_vm_resistance_measurement_records_automated_adversarial_contract() -> None:
    report = measure(_FIXTURE, first_seed=20260915, count=4)
    campaign = cast(dict[str, object], report["seed_campaign"])
    diversity = cast(dict[str, object], report["opcode_and_dispatcher_diversity"])
    progressive = cast(dict[str, object], report["progressive_bytecode"])
    tamper = cast(dict[str, object], report["anti_tamper"])
    validation = cast(dict[str, object], report["automated_validation"])
    human_review = cast(dict[str, object], report["human_adversarial_review"])
    handler_report = cast(dict[str, object], diversity["handler_report"])
    grammar_report = cast(dict[str, object], diversity["bytecode_grammar_report"])
    single_layer = cast(dict[str, object], tamper["single_layer"])
    nested = cast(dict[str, object], tamper["nested"])

    expect(
        validation["status"] == "completed"
        and campaign["semantic_parity"] is True
        and campaign["distinct_artifacts"] is True
        and diversity["dispatcher_unique_count"] == _EXPECTED_SEED_COUNT
        and handler_report["cross_seed_has_exact_normalised_matches"] is False
        and grammar_report["target_stride_diverse"] is True
        and single_layer["tamper_diverged"] is True
        and nested["tamper_diverged"] is True
        and single_layer["all_tamper_probes_diverged"] is True
        and nested["all_tamper_probes_diverged"] is True
        and single_layer["tamper_probe_count"] == nested["tamper_probe_count"] == _EXPECTED_TAMPER_PROBE_COUNT
        and progressive["growth_observed"] is True
        and progressive["depth_1_exit_code"] == progressive["baseline_exit_code"]
        and progressive["depth_2_exit_code"] == progressive["baseline_exit_code"]
        and human_review["status"] == "pending-human-adversarial-review"
    )


def test_vm_resistance_corpus_requires_diversity_across_real_fixtures() -> None:
    report = measure_corpus((_FIXTURE, _CORPUS_FIXTURE), first_seed=20260915, count=2)

    expect(
        report["fixture_count"] == _EXPECTED_CORPUS_FIXTURE_COUNT
        and report["automated_validation"]["status"] == "completed"
        and report["semantic_parity"] is True
        and report["cross_fixture_distinct_artifacts"] is True
        and report["all_tamper_probes_diverged"] is True
        and report["progressive_growth_observed"] is True
        and report["human_adversarial_review"]["status"] == "pending-human-adversarial-review"
    )
