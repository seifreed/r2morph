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

## Rejected: separating the program rsp (gate-disproven)

The first attempt moved the relocated program rsp into its own dedicated slot
outside the array, on the premise that rsp is never a dynamic slot operand (the
register-*value* decoder does reject it). The real-exec gate rejected this: 18
memory-operand handlers failed. rsp *is* reached dynamically — not as a value
operand but as a **memory-addressing base register**. Stack-relative addressing
(`[rsp+disp]`, ubiquitous for locals) decodes base=RSP_INDEX and reads the rsp
value from the array slot at runtime, so pulling rsp out of the array starves
every stack-relative load/store. The relocated rsp must stay in the array.

## Correct model: uniform encryption, no special slot

Because rsp is read dynamically as a memory base like any other register, there
is no slot to exempt. Encrypt the whole array uniformly: **decrypt on every slot
read, encrypt on every slot write, with no exceptions.** rsp then rides the
cipher like the rest and every base-register read decrypts it back before use —
consistent by construction. This is conceptually simpler than a carve-out but
covers more sites: the data-operand loads/stores, the memory-handler
base-register loads, the push/pop/rspadj/leave and call-path rsp reads, plus the
entry spill and exit reload.

Key timing: the checksum-broadcast key slots are materialized *after* the entry
spill, so the spill cannot encrypt inline — add a short post-key pass that
re-reads each occupied slot and XORs it in place once the key is ready.

## Key material (reuse, no new setup)

The entry prologue already materializes the self-checksum broadcasts into
`_KEY_DWORD_SLOT` (`[rsp+0x200]`, `checksum*0x01010101`) and `_KEY_QWORD_SLOT`
(`[rsp+0x208]`, `checksum*0x0101010101010101`) for the operand cipher. Reuse
them as the register-file key: `xor rax, qword ptr [rsp+0x208]` (or the dword
slot for 32-bit accesses). The key is checksum-derived, so IDA cannot fold the
XOR to plaintext — the frame renders as `v ^ (0x0101010101010101 * v_checksum)`,
exactly like the already-hidden operand cipher and anti-debug constants.

## Execution (atomic, one gated commit)

The encryption is all-or-nothing: any slot access that reads plaintext where the
array now holds ciphertext (or vice-versa) misdecodes, so the whole array's
accesses must flip together in one commit, gated by the full real-exec suite.

1. **Enumerate every slot access** — data loads/stores, memory-handler
   base-register loads, push/pop/rspadj/leave, the call-path rsp read, the entry
   spill, the exit reload — across region_handlers / region_microops /
   region_fp_handlers / region_codegen / region_nesting.
2. **Wrap each** with the reused checksum key: `xor REG, <key slot>` (width-matched
   dword/qword) after every load, before every store. ALU-operand sites
   (`imul rax,[slot]`, `add [slot],rax`) restructure to load→decrypt→op→
   encrypt→store.
3. **Post-key spill encryption pass**: after the key slots are materialized,
   re-read each occupied array slot and XOR it in place (the spill ran before the
   key existed).
4. **Nesting + XMM parity.**
5. **IDA verify**: frame values render as checksum-keyed XORs
   (`v ^ (0x0101010101010101 * v_checksum)`), no plaintext register moves;
   dispatch stays opaque; the dataset fixtures still run.

Do not merge unless the full real-exec suite is green — a partial encryption is
caught there (as the rejected rsp-carve-out attempt was, by 18 memory-handler
failures).
