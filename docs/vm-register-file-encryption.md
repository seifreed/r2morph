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

## Implementation recipe (derived; the vstack landed with this exact method)

Key operands (module constants in region_handlers): the checksum qword key is a
uniform byte broadcast, so one slot reads at any width —
`_RFK_Q/D/W/B = "{qword|dword|word|byte} ptr [rsp+_KEY_QWORD_SLOT]"`. A sub-width
read/write needs no merge: the untouched upper lanes stay validly encrypted.

Per-site rules:
- **Every slot read** `mov REG, <w> ptr [rsp+rN*8]` → append `xor REG, <w>-key`.
  Universally safe (a slot always holds a real register value; decrypt → real),
  regardless of whether the value is used as data or an address base. Most are two
  recurring width-ternary patterns (src→rax/eax off r9, dst→r10/r10d off r8) that
  fold with one `replace_all` each.
- **Flag-dead / mov result write** `mov <w> ptr [rsp+rN*8], REG` → prepend
  `xor REG, <w>-key`. REG is dead after (jmp follows), and no flag capture follows,
  so the encrypting xor's flag clobber is harmless.
- **Flag-LIVE RMW write** (`{op} qword [slot], rax; pushfq` and the 32-bit
  `mov r11d,[slot]; {op} r11d,eax; mov [slot],r11; pushfq`): the encrypting xor
  sets flags, so it must NOT sit between the op and `pushfq`. Restructure to
  `mov r11,[slot]; xor r11,key (decrypt); {op} r11,rax; pushfq; pop [FLAGS];
  xor r11,key (encrypt); mov [slot],r11`. This is the delicate class — handle each
  explicitly, never mechanically.
- **ALU-operand read** (`imul rax,[slot]`): load to a scratch first
  (`mov r11,[slot]; xor r11,key; imul rax,r11`).
- **Sub-width setcc/movx** (`mov byte [slot], cl`, `mov r11b, byte [slot]`): use
  `_RFK_B/_RFK_W` at the matching width; partial stores leave upper lanes encrypted.
- **div implicit rax/rdx**: the divisor slot read decrypts; rax/rdx come from
  already-decrypted slots, so no extra work beyond the standard read rule.

The relocated program rsp is IN the encrypted array (`rsp_off = slot[RSP_INDEX]*8`,
inside `[0x00,0x80)`) — it cannot be carved out (see the rejected attempt above), so
every one of the ~41 `rsp_off` accesses is a slot access under this cipher:
- push/pop/mov-rsp/leave/pushi read or write `[rsp+rsp_off]` → decrypt on read,
  encrypt on write, exactly like a data slot.
- `_rspadj_handler_asm` does `{op} qword [rsp+rsp_off], rax; pushfq` — a flag-LIVE
  RMW on the rsp slot → apply the flag-RMW restructure (decrypt→op→pushfq→encrypt).
- the codegen `vcall`/`vret` rsp reads/writes and the call-path
  `mov rsp,[r12+slot[RSP_INDEX]*8]` (decrypt via r12) and the entry_setup rsp write.
This puts the true surface near ~130 sites (≈90 GP-data + ≈41 rsp), which is why
this is a dedicated multi-hour pass, not a single-turn edit. A partial application
(some rsp accesses ciphered, some not) misdecodes the program stack pointer — a
wrong address, caught by the pushpop/leave/prologue/call fixtures.

Boundaries (region entry in region_codegen `_interpreter_asm`; nesting entry in
region_nesting `build_nested_region_blob`):
- The GP spill runs BEFORE the key exists → after the key-materialize block, add a
  post-key pass that re-reads each of the 15 spilled data slots and XORs them in
  place (`mov rax,[slot]; xor rax,_RFK_Q; mov [slot],rax`).
- The relocated-rsp write in entry_setup runs AFTER the key → encrypt inline.
- The call-path rsp read (`mov rsp, qword ptr [r12+slot[RSP_INDEX]*8]`) reads the
  encrypted rsp with r12 as base while overwriting rsp → decrypt via r12:
  `mov rsp,[r12+..]; xor rsp, qword ptr [r12+_KEY_QWORD_SLOT]`.
- `reload_seq` (exit restore) is emitted INSIDE the vret/exit handler bodies, so
  its reads are covered by the standard read rule automatically.

Nesting scope: `handler_instances_asm` is SHARED by region and nesting, so every
handler-body edit covers both VMs — only the two entry sequences (spill pass +
rsp write, once each) are nesting-specific. This roughly halves the surface.

Gate: full `test_code_virtualization_real.py` (114 tests, 87 fixtures across every
handler family). Commit only when green; otherwise revert so the branch never
carries a partial (misdecoding) cipher.
