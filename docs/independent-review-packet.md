# Independent Review Packet

This packet defines the human review required before the current virtualizer
milestone can be marked complete. It is intentionally unsigned: automated
checks are evidence, not a human approval.

## Target

- Commit: `c820685f`
- Scope: ELF x86-64 CodeVirtualization, VM diversification, analyzer corpus,
  and dispatcher/relocation/rewriter fuzzing.
- Binary Ninja: excluded by project decision.

## Evidence

- [`compatibility-corpus.md`](compatibility-corpus.md)
- [`protection-adversarial-corpus-2026-09-05-44bca563-triton.json`](protection-adversarial-corpus-2026-09-05-44bca563-triton.json)
- [`protection-adversarial-corpus-2026-09-05-a92e8b9-triton.json`](protection-adversarial-corpus-2026-09-05-a92e8b9-triton.json)
- [`protection-adversarial-corpus-2026-09-05-fa85d18-triton.json`](protection-adversarial-corpus-2026-09-05-fa85d18-triton.json)
- [`protection-adversarial-corpus-2026-09-05-c820685f-triton.json`](protection-adversarial-corpus-2026-09-05-c820685f-triton.json)
- [`protection-ida-mcp-corpus-2026-09-05-7c3d4f32.json`](protection-ida-mcp-corpus-2026-09-05-7c3d4f32.json)
- [`protection-ghidra-corpus-2026-09-04-88258a05.json`](protection-ghidra-corpus-2026-09-04-88258a05.json)
- [`protection-adversarial-corpus-2026-09-05-83e6eee6-triton.json`](protection-adversarial-corpus-2026-09-05-83e6eee6-triton.json)
- [`protection-fuzz-2026-09-05-2e4ad8e.json`](protection-fuzz-2026-09-05-2e4ad8e.json)
- [`independent-review.json`](independent-review.json)

The current evidence records 159/159 virtualized samples, 318/318 IDA
analyses, 954 Triton pairs, 954 angr pairs, and 80,000 fuzz target runs.
The automated review still reports `human_signoff: not-attested`.
The current corpus rerun records 47 explicit Unicorn errors and 1,908 local
IDA/Ghidra-unavailable rows; these are not attributed to Triton or angr.
Binary Ninja remains excluded by project decision.

## Reproduction

Run from the repository root with the pinned Python 3.13 environment:

```bash
source /tmp/r2morph-venv313/bin/activate
python scripts/independent_review.py --output /tmp/independent-review.json
python -m pytest -q --no-cov tests/unit/test_independent_review_contract.py tests/unit/test_adversarial_benchmark_contract.py
```

The reviewer should compare the generated report with the committed reports,
then inspect the implementation and regression tests rather than relying on
the aggregate counters alone.

## Human checklist

- [ ] Confirm the `elf_vm_fppackedidxnb_x86_64` regression is generic and not
      sample-specific.
- [ ] Inspect memory, direct/indirect calls, returns, flags, FP/SIMD,
      varargs/ABI, unwinding, TLS/signals, SSA, and liveness paths.
- [ ] Confirm unsupported instructions fail closed and cannot silently produce
      a partial protected function.
- [ ] Review VM ISA/opcode diversification, dispatcher/handler alternatives,
      superinstructions, anti-tamper, and progressive bytecode protection.
- [ ] Review the fuzz properties and failure handling for dispatcher,
      relocations, and rewriting.
- [ ] Check that reports contain bounded metadata rather than raw sample bytes
      or analyst host paths.
- [ ] Record any finding with a reproducer, severity, and affected commit.

## Sign-off

```text
Reviewer:
Affiliation:
Date (UTC):
Independence statement:
Result: APPROVE / APPROVE WITH FINDINGS / REJECT
Findings:
Reviewed commit: c820685f
```

No approval is implied until a human reviewer fills this section outside the
automated test process.
