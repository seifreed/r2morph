# Region VM register-file encryption (gap #4)

Status: planned, staged. Highest-payoff structural gap toward VMProtect/Themida
maturity. This document is the safe execution plan; each stage is a separate
commit gated by `tests/integration/test_code_virtualization_real.py` (87 dataset
fixtures across every handler family — the loud gate that turns a slot-access
miscompile into a red exit-code test rather than a silent one).

## The tell

IDA decompiles the region interpreter's context as a flat, contiguously indexed
stack frame: `[rsp + slot*8]` with a computable index and plaintext values
(`v20`, `v24`, `v25`, …). Commercial protectors keep the VM context in an
indexed/encrypted array the decompiler cannot read as a plain register file.

## Why it is not a one-pass change

- **88 GP slot-access sites** across `region_handlers` / `region_microops` /
  `region_codegen`, mostly `mov`-form load/store but a few use the slot as a
  direct ALU operand (`add qword ptr [rsp+r8*8], rax`, `imul rax,[rsp+r9*8]`).
- **41 program-rsp pointer uses** (`rsp_off = slot[RSP_INDEX]*8`, 21 codegen +
  16 handlers + 4 nesting). The relocated program rsp is stored *inside* the
  indexed array. Encrypting the array uniformly means every one of these 41
  dereference bases must decrypt first — and a missed decrypt is a wrong
  *address* (crash), not merely wrong data. This is the landmine.
- **XMM slots** and **nesting** need parity.

Handlers index slots dynamically (`[rsp+rN*8]`, rN from the bytecode), so the
rsp slot cannot be statically exempted while it lives in the indexed array.

## De-risking insight

Move the relocated program rsp **out of the indexed array into its own dedicated
frame slot** first. Then only the 15 pure-data slots are encrypted; the 41
pointer uses stay plaintext and untouched by the cipher. This collapses the
correctness surface from "88 data + 41 pointer" to "88 data".

## Key material (reuse, no new setup)

The entry prologue already materializes the self-checksum broadcasts into
`_KEY_DWORD_SLOT` (`[rsp+0x200]`, `checksum*0x01010101`) and `_KEY_QWORD_SLOT`
(`[rsp+0x208]`, `checksum*0x0101010101010101`) for the operand cipher. Reuse
them as the register-file key: `xor rax, qword ptr [rsp+0x208]` (or the dword
slot for 32-bit accesses). The key is checksum-derived, so IDA cannot fold the
XOR to plaintext — the frame renders as `v ^ (0x0101010101010101 * v_checksum)`,
exactly like the already-hidden operand cipher and anti-debug constants.

## Stages (one gated commit each)

1. **Separate program-rsp** into a dedicated non-indexed frame slot; route the
   41 `rsp_off` uses to it; drop rsp from the indexed array. Behavior-preserving.
   Gate: the rsp fixtures (movtorsp, pushpop, pushimm, leave, prologue) plus the
   full suite stay green.
2. **Encrypt the 15 GP data slots**, all-or-nothing atomically: encrypt on entry
   spill, decrypt on exit reload, decrypt-on-load / encrypt-on-store at every
   handler site (including the ALU-operand sites, restructured to load→op). Use
   the reused key slots. Gate: full real-exec suite green.
3. **Nesting parity + XMM** as needed for FP regions.
4. **IDA verify**: the frame values render as checksum-keyed XORs, no plaintext
   register moves; dispatch stays opaque; fixtures still run.

Do not merge a stage whose gate is not green — a partial encryption (some slots
encrypted, some not) misdecodes and is caught by the suite.
