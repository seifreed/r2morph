# VM maturity assessment — 2026-08-12

Measured against a commercial protector baseline (VMProtect / Themida), using the
decompiler as the adversary rather than a disassembler.

**Verdict: the VM pipeline is a correct, feature-rich virtualizer with meaningful
static-decompiler resistance, but it remains below the reference protectors.**
Hex-Rays no longer reconstructs the dispatch, handlers, keys or plaintext VM
context, but it still recovers the integrity and anti-debug prologue and identifies
the appended executable payload and its interpreter functions.

## Cumulative hardening state (2026-08-12 session)

The gaps below were worked in order; this is where the VM stands after that pass,
re-verified by decompiling a freshly virtualized `fixtures/dataset/elf_vm_incall_x86_64`:

- **Dispatch — resistant.** Only the runtime-XOR-encrypted threaded table remains;
  the interpreter decompiles to an opaque `jmp rax`, no switch is reconstructed, and
  the handlers are not attributed to the interpreter. (gap 1, closed)
- **Handler set — much larger and no longer collapsible.** Per-op instance count is
  a 3–6 draw (a mid-size region shows ~40–65 handlers, IDA reads a per-layer bound
  in the low tens vs the mid-teens before), each arithmetic and (region) addressing
  instance draws its own MBA fold from deepened pools, and emission order is shuffled
  in both VMs so block layout no longer leaks the opcode ordering. Handler-head junk
  and opaque-predicate pools were widened in both VMs. (gap 2, substantially advanced)
- **Anti-debug constants — opaque.** `strcpy(…"/proc/self/status")` is gone; the path
  words and `TracerPid` tag decompile as `0x0101010101010101 * v_checksum ^ 0x…`,
  keyed on the self-checksum the decompiler cannot fold. (gaps 3/5, done for the
  constants)

- **Key schedule — hidden for all three VMs.** Both the dispatch-table key and the
  opcode/operand cipher key are now the runtime self-checksum, not build constants:
  the table decrypt and every operand decrypt render as `X ^ (0x…01 * v_checksum)`,
  so no key literal is exposed (IDA-verified — the prologue shows `0x1010101 *
  v_checksum` and `0x0101010101010101 * v_checksum` in place of the former `xor_key`
  constant). This holds for the region and nested VMs and for the straight-line engine
  VM as well: the engine's operand cipher key is the checksum slot read directly
  (`code_virtualization_engine_codegen.py`, `key = byte ptr [rsp + checksum_offset]`)
  and its bytecode is XORed with the checksum byte, so it carries no `xor_key` literal
  either.

- **Register files — checksum-ciphered in all three VMs, scattered in region VMs.** All 16 GP slots, including the
  relocated program `rsp`, are stored XORed with the runtime checksum broadcast;
  every handler decrypts on read and encrypts on write. A fresh IDA run over seed
  `20260811` renders the entry context as 15 independent
  `slot ^= 0x0101010101010101 * v_checksum` expressions before opaque threaded
  dispatch, rather than plaintext register values. The same transform now covers
  the straight-line engine's per-build frame layout. IDA renders its entry as 15
  checksum-keyed slot expressions, its relocated `rsp` as a keyed pointer, and its
  exit reloads as keyed reads. Region and nested schemes now move one or two GP
  slots into safe outlier cells on every build, leaving holes in the historical
  16-qword array. IDA confirms the change: the previous consecutive locals at
  `rsp+0x100..0x178` became a gapped set with holes at `0x110`, `0x118`, `0x180`
  and `0x188`, plus outliers at `0x190` and `0x1A8`. The straight-line engine now
  applies the same invariant using its own reserved GP window: IDA shows a gap at
  `rsp+0x160..0x170` and outliers at `0x180`, `0x188` and `0x198`. Runtime tracing
  can still observe all three.

- **Payload segment multiplicity — reduced.** The injector now relocates the
  program-header table once and extends that terminal RX load for later VM blobs.
  On `fixtures/dataset/elf_vm_incall_x86_64`, two virtualized functions now add one program
  header and IDA reports one appended RX `LOAD` (`0x402000..0x40bb84`) instead of
  two appended loads. The single large executable payload remains structurally
  obvious.

- **Self-checksum traversal — no longer linear.** The three VMs share an
  alternating-ends traversal: each iteration consumes one byte from each end of
  the interpreter and converges inward, with the per-build variant selecting which
  end is mixed first. IDA no longer emits the former single-pointer linear `for`,
  but it still recovers the two pointers, range and fold. This breaks the simplest
  checksum-loop signatures without pretending the integrity design is hidden.

- **Anti-debug probe — no foldable constants left.** The tracer probe's three
  syscall numbers (`openat`/`read`/`close`) and the `AT_FDCWD` dirfd were the last
  plaintext immediates in it; a decompiler folded them and attributed the probe as
  `sys_openat`/`sys_read`/`sys_close`, pointing straight at the `/proc/self/status`
  read. They now live in the same checksum-keyed island as the path words and scan
  tag and de-mask at runtime, so IDA renders the three syscalls as bare, unnamed
  `syscall` instructions with no attributable constant (number, dirfd and flags all
  opaque — IDA-verified on a virtualized `fixtures/dataset/elf_vm_incall` build). The probe's
  *structure* (three syscalls, a tag scan, a digit check) is still visible; only its
  constants are gone. (gaps 3/5, done for the constants)

**Still recovered by the decompiler, and still below the reference protectors:** the
self-checksum loop and anti-debug probe *structure* (the checksum loop, tag scan and
timestamp reads) remain visible even though their constants are gone; the
spill/encrypt register-frame pattern remains visible; and the payload is
structurally obvious (one appended RX `PT_LOAD`, large interpreter functions).
These are the remaining
milestones and each is a dedicated redesign — see the gap list.

## Method

`fixtures/dataset/elf_vm_incall_x86_64`, `elf_switch_abs_x86_64`, `elf_blockswap_x86_64` and
`elf_vm_arith_x86_64` virtualized at `probability=1.0`, `vm_nesting_depth=2`, several
seeds, then opened in IDA Pro (idalib) with auto-analysis and decompiled. The
initial baseline covered both former dispatch shapes; current builds only use the
encrypted threaded shape.

The 2026-08-11 recheck used `elf_vm_incall_x86_64`, seed `20260811`, nesting
depth 2 and SHA-256
`7c7d9799be38b8d7ae1e34d24211dcaaac0b97680f443bde576a1b26b9a61cd1`.
It virtualized two functions (35 native instructions, 39,644 bytecode bytes),
preserved exit code 45, and was opened through the IDA MCP with auto-analysis.

The 2026-08-12 engine recheck used `elf_vm_run_callfallback_x86_64`, seed
`20260812`, and SHA-256
`5ccc5324fe0cea773bd60ee7d8c649d2fd5f6bf6f5586735df038ecfae04f93b`.
It virtualized one straight-line run (three native instructions, 51,917 generated
bytes), preserved exit code 45, and produced one appended RX `LOAD`. IDA attributed
only 225 instructions to the interpreter entry, stopped at its opaque indirect
jump, and left the handler body range unattributed.

The 2026-08-12 scattered-frame recheck used `elf_vm_redzone_x86_64`, seed
`20260812`, nesting depth 1 and SHA-256
`50139691a46424fcffb8b8e9666b2e092c0277249130e25fff68f79dd96f5c8c`.
It virtualized the caller and red-zone callee, preserved exit code 42, and produced
one appended RX `LOAD` (`0x202000..0x2082e1`). IDA resolved the two interpreters as
8,833 and 15,525-byte functions and decompiled the scattered checksum-ciphered
frame described above.

The matching straight-line engine recheck used
`elf_vm_run_callfallback_x86_64`, seed `20260812`, and SHA-256
`f600fa2503acb2a12f089f7b4acf2ac8b9b5411256cc5471372039a42312d538`.
It virtualized one three-instruction run into 52,625 generated bytes, preserved
the fixture's execution contract, and produced one appended RX `LOAD`
(`0x402000..0x40ee39`). IDA attributed 945 bytes to the interpreter entry before
the opaque indirect jump and recovered the gapped checksum-ciphered frame above.

## What the decompiler recovers

The interpreter decompiles through its prologue and stops at an opaque indirect
jump; handlers are not attributed to it. Everything below is read directly off the
pseudocode, with no manual work:

| Asset | How it appears |
|---|---|
| Dispatch | opaque bounded indirect `jmp rax`; no switch or handler attribution |
| Opcode cipher | runtime self-checksum plus stream position; no key literal |
| Operand cipher | checksum-broadcast XOR; no build-constant key |
| Register file | gapped checksum-ciphered frame in region, nested and engine VMs |
| Self-checksum | two pointers converge from both range ends; range and fold remain explicit |
| Tracer probe | three unnamed syscalls and an opaque tag compare; scan structure visible |
| Handler count | roughly 40–65 polymorphic instances, not attributed to the dispatcher |

Structural tells at the file level: the payload lands in one extra unnamed RX
`PT_LOAD` above the image, and each interpreter remains a large contiguous function
whose bounds IDA resolves exactly.

## The anti-debug constants cannot be hidden by *immediate* masking (now solved by checksum-keying)

`code_virtualization_antidebug.py` already stores the procfs path and the `TracerPid`
tag as `const ^ mask` with a per-build mask, specifically to avoid plaintext
immediates. In `.text` that works — the bytes differ per build. It does **not**
survive decompilation, because the mask is a second immediate two instructions away
and Hex-Rays constant-folds the pair:

```
mov rax, 8320FCD68921A39Ah     ; ciphertext
mov rdx, 0E653D3B5E653D3B5h    ; mask
xor rax, rdx                   ; -> folded back to "/proc/se"
```

Sourcing the mask from data instead (`mov rdx, cs:qword_4025C9`) was tried and
**rejected**: Hex-Rays propagates constants out of the non-writable segment just as
readily, the pseudocode still renders `strcpy(v25, "/proc/self/status")`, and the
change bought nothing the per-build mask did not already provide.

The general lesson, and the constraint any fix must respect: **a key that is a
build-time constant is recoverable by constant propagation no matter where it is
stored.** Only a key the decompiler cannot evaluate helps — one derived at runtime
from code bytes (the existing self-checksum) or from the environment. Deriving it
from the checksum is circular today, because the checksummed range covers the
immediates being masked; breaking that requires either a two-pass assembly or
placing the masked constants in the appended bytecode region, which lies outside the
checksummed range and is therefore free of the circularity.

**Done for the anti-debug constants.** The `/proc/self/status` path words and the
`TracerPid` scan tag now live in a small constant island appended after the
dispatch table — outside the checksummed `[vm_entry, vm_table)` span, so free of the
circularity — stored as `const ^ broadcast(checksum)` and de-masked at runtime by
XORing the interpreter's own self-checksum byte back out. Because the key is the
result of a loop over the whole code segment, Hex-Rays keeps it as an opaque runtime
variable and can no longer fold the expression: the prologue now decompiles to
`filename[0] = 0x0101010101010101 * v_checksum ^ 0x…` rather than
`strcpy(filename, "/proc/self/status")`, and the tracer tag compare reads
`buf == (0x0101010101010101 * v_checksum ^ 0x…)` instead of the literal qword. The
plaintext string — the single most damning line in this report — is gone from both
the raw file and the pseudocode. The same mechanism now applies to both VMs and the
nested interpreter. The self-checksum loop itself and the opcode/table constants
folded into it remain visible; only the anti-debug constants were relocated.

## Gap list, in priority order

1. **Half of all builds ship a dispatch the decompiler reconstructs exactly — remove
   the switch shape.** The shape is drawn per build
   (`code_virtualization_region.py:974`), for diversity, but the two shapes are not
   of equal strength:
   - `DISPATCH_SWITCH` emits an explicit `cmp al, mid` / `je` binary ladder
     (`code_virtualization_dispatch.py:_switch_ladder`). Hex-Rays rebuilds it into a
     clean `switch`, handing over the opcode-to-handler mapping directly. Every
     switch-shape build decompiled here gave up its whole ISA this way.
   - `DISPATCH_THREADED` dispatches through an offset table that is **XOR-encrypted
     at runtime**, so IDA cannot resolve an entry statically, cannot synthesize a
     switch, and could not even attribute the handlers to the interpreter (in a
     forced-threaded build they landed in a separate 121-block function).

   Shape diversity is worth less than a strong floor: a protector must not emit a
   fully reconstructible variant half the time.

   **Closed.** The switch shape, its ladder emitter (`switch_dispatch` /
   `_switch_ladder`) and the per-build `dispatch_shape` field are gone from both
   VMs; every build now dispatches through the threaded encrypted offset table.
   Dropping the draw shifts the scheme RNG stream, so generated code changes for a
   given seed (behaviour does not). The dispatch-shape tests now pin the floor —
   no build emits a compare/branch ladder — instead of asserting both shapes exist.
2. **The ISA is tiny and each opcode has one handler instance.** 8–13 opcodes against
   the reference protectors' hundreds of handler variants. Handler duplication and
   per-instance polymorphism exist in the codebase but do not multiply the *visible*
   case count enough to matter.

   **Partly closed.** The per-op instance count was raised from a 1–2 draw to a 2–4
   draw in the shared assignment (`_assign_opcode_multiplicity`), which both VMs now
   use. A mid-size region that carried 8–13 handlers, one instance per opcode, now
   carries ~30–44 handler instances with a floor of two per opcode, each copy
   diverging in executed code (per-instance live junk, opaque predicates, scratch
   renames) so a decompiler cannot fold them back together. The lone-instance tell
   — an opcode that decompiles to a single case — is gone. Duplicate *arithmetic*
   handlers now also diverge **semantically**: each instance draws its own MBA fold
   from a 4096-value space (35/36 distinct across a mid-size region), so two copies
   of the same operation compute it by different instruction sequences rather than
   only wearing different junk. The flag/compare/shift representation stays per-build
   (it is a shared encoding producer and consumer handlers must agree on), so this
   is not yet the reference protectors' hundreds of fully-distinct handler families,
   but the arithmetic core — the bulk of most handler sets — is no longer trivially
   collapsible by behaviour.
3. **Key material is compile-time constant**, so every cipher in the VM is recoverable
   by constant propagation (see above).

   **Closed.** Opcode, operand, dispatch-table, register-file and virtual-stack
   ciphers are keyed by the runtime self-checksum or its lane broadcast; no separate
   build-constant key remains in the decompiled decode paths.
4. **The register file is a recognizable stack context** with a computable index, so a
   devirtualizer can name every virtual register.

   **Substantially closed for static recovery.** The per-build slot permutation
   already breaks positional naming, and every GP slot is now checksum-ciphered at
   rest across the region, nested and straight-line engine VMs. IDA sees the entry encryption but cannot
   fold the runtime key or recover plaintext handler accesses. Region and nested
   and engine builds now guarantee at least one hole and one safe outlier in the GP
   layout, so their physical context is no longer one contiguous 16-qword array.
   The spill/encrypt pattern is still recognizable, and a runtime tracer can still
   observe decrypt/use/store.
5. **Integrity and anti-debug are observable and centralized** — one checksum byte,
   one slot, folded by two probes whose ranges and algorithms are all visible.

   **Partly closed.** The anti-debug *constants* (the procfs path and the tracer tag)
   no longer decompile to literals: they are checksum-keyed in an out-of-range island
   (see above), so the decompiler renders opaque XOR expressions instead of
   `"/proc/self/status"`. The checksum traversal now alternates both range ends and
   varies which end is read first, so the old single-pointer signature is gone, but
   the range and fold structure remain visible. Hiding those needs the integrity and
   probes virtualized too, not just their constants or traversal spelling.
6. **The payload is structurally obvious**: appended `RX` segments, one contiguous
   interpreter function, contiguous bytecode at a resolvable symbol.

   **Partly closed.** All VM blobs in one mutation run now share a single appended
   RX segment, so segment count no longer reveals the number of virtualized
   functions. The segment and the large contiguous interpreter functions are still
   immediately visible and remain a major maturity gap.

## What is already good

Region-level virtualization of whole functions including in-function calls, switch
tables and FP; VM-in-VM nesting; per-build operand-field permutation, ISA
personality and handler junk; bytecode encrypted against a
runtime self-checksum so tampering misdecodes rather than branching to a failure
path; position-independent output. The weakness is not the feature set — it is that
none of it is opaque to a decompiler.
