"""
Real integration tests for runtime validation inside the mutation pipeline.
"""

from __future__ import annotations

import importlib.util
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from r2morph import MorphEngine
from r2morph.core.engine_run import EngineRunOptions
from r2morph.mutations.base import MutationPass
from r2morph.session import MorphSession
from r2morph.validation.validator import BinaryValidator, RuntimeComparisonConfig
from tests.utils.assertions import expect

if importlib.util.find_spec("r2pipe") is None:
    pytest.skip("r2pipe not installed", allow_module_level=True)


class _PatchStringPass(MutationPass):
    def __init__(self, original: bytes, replacement: bytes):
        super().__init__("PatchString")
        self.original = original
        self.replacement = replacement

    def apply(self, binary):
        for section in binary.get_sections():
            vaddr = int(section.get("vaddr", 0))
            size = int(section.get("vsize", section.get("size", 0)) or 0)
            if vaddr == 0 or size <= 0:
                continue
            try:
                blob = binary.read_bytes(vaddr, size)
            except Exception:
                logging.getLogger(__name__).debug("ignored optional runtime error", exc_info=True)
                continue
            index = blob.find(self.original)
            if index < 0:
                continue
            patch_addr = vaddr + index
            before = blob[index : index + len(self.original)]
            if not binary.write_bytes(patch_addr, self.replacement):
                continue
            self._record_mutation(
                function_address=None,
                start_address=patch_addr,
                end_address=patch_addr + len(self.replacement) - 1,
                original_bytes=before,
                mutated_bytes=self.replacement,
                original_disasm="<data>",
                mutated_disasm="<data>",
                mutation_kind="data_patch",
                metadata={"patched_string": before.decode("utf-8", errors="replace")},
            )
            return {"mutations_applied": 1}
        return {"mutations_applied": 0}


def test_runtime_validation_rolls_back_failed_pass_on_real_binary(
    patchable_runtime_binary: Path,
    tmp_path: Path,
):
    validator = BinaryValidator(
        timeout=5,
        comparison=RuntimeComparisonConfig(normalize_whitespace=False),
    )
    validator.add_test_case(description="default")

    with MorphEngine(config={"seed": 7}) as engine:
        engine.load_binary(patchable_runtime_binary).analyze()
        engine.add_mutation(_PatchStringPass(b"value:42", b"value:99"))
        result = engine.run(
            EngineRunOptions(
                validation_mode="runtime",
                runtime_validator=validator,
                runtime_validate_per_pass=True,
                rollback_policy="skip-invalid-pass",
                report_path=tmp_path / "runtime-pass.report.json",
            )
        )
        output = tmp_path / "runtime-pass.out"
        engine.save(output)

    expect(result["total_mutations"] == 0)
    expect(result["rolled_back_passes"] == 1)
    expect(result["discarded_mutations"] == 1)
    expect(result["validation"]["runtime_passes"])
    expect(not (result["validation"]["runtime_passes"][0]["passed"] is not False))
    expect(result["pass_results"]["PatchString"]["rollback_reason"] == "runtime_validation_failed")
    expect(
        result["pass_results"]["PatchString"]["discarded_mutations_detail"][0]["metadata"]["discard_reason"]
        == "runtime_validation_failed"
    )

    final_result = validator.validate(patchable_runtime_binary, output)
    expect(not (final_result.passed is not True))


def test_morph_session_parallel_creation_is_unique_and_stable(
    patchable_runtime_binary: Path,
    tmp_path: Path,
):
    def _run_session(index: int):
        session = MorphSession(working_dir=tmp_path / "parallel_sessions")
        try:
            working_copy = session.start(patchable_runtime_binary)
            output = tmp_path / f"session_{index}.bin"
            ok = session.finalize(output)
            session_dir = session.session_dir
            session_id = session.session_id
            return session_id, session_dir, working_copy.exists(), ok, output.exists()
        finally:
            session.cleanup()

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(_run_session, range(24)))

    ids = [item[0] for item in results]
    dirs = [str(item[1]) for item in results]
    expect(len(ids) == len(set(ids)))
    expect(len(dirs) == len(set(dirs)))
    expect(all(item[2] for item in results))
    expect(all(item[3] for item in results))
    expect(all(item[4] for item in results))
