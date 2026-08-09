# VM maturity assessment — 2026-08-09

Measured against a commercial protector baseline (VMProtect / Themida), using the
decompiler as the adversary rather than a disassembler.

**Verdict: the region VM is a correct, feature-rich virtualizer that does not yet
resist a decompiler. One Hex-Rays press recovers the interpreter, the ISA, the key
schedule and the anti-debug logic.** It is well below the reference protectors.

## Method

`dataset/elf_vm_incall_x86_64`, `elf_switch_abs_x86_64`, `elf_blockswap_x86_64` and
`elf_vm_arith_x86_64` virtualized at `probability=1.0`, `vm_nesting_depth=2`, several
seeds, then opened in IDA Pro (idalib) with auto-analysis and decompiled. Both
dispatch shapes were covered: the shape is drawn per build
(`code_virtualization_region.py:974`), so seeds were chosen to hit each.

## What the decompiler recovers

The interpreter decompiles into a single function with a `while(1)` and a `switch`
over the opcode. Everything below is read directly off the pseudocode, with no
manual work:

| Asset | How it appears |
|---|---|
| Dispatch | `while(1) { ... switch (v25) { case 8u: ... } }` |
| Opcode cipher | one line: `v24 = v43 ^ ((BYTE)vip - (BYTE)base) ^ v44 ^ *vip` |
| Operand cipher | `(0x0101010101010101 * delta) ^ *(qword*)(p+1) ^ K`, `K` a literal |
| Register file | a plain stack array, slot index `delta ^ byte ^ K` |
| Self-checksum | `for (i = start_0; i < byte_402857; ++i)` — range and algorithm both explicit |
| Tracer probe | `strcpy(v31, "/proc/self/status")` plus the `TracerPid` tag as a literal qword |
| Handler count | 8–13 opcodes, one instance each |

Structural tells at the file level: the payload lands in extra unnamed `RX` `PT_LOAD`
segments above the image, and the interpreter is a single contiguous function whose
bounds IDA resolves exactly.

## The anti-debug constants cannot be hidden by masking

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

## Gap list, in priority order

1. **The dispatch loop reconstructs as a `switch`.** The threaded shape barely helps:
   in a threaded build only 2 of ~12 opcodes leave through the computed `jmp r10`;
   the rest are inlined into a comparison tree that Hex-Rays folds back into a
   `switch`. A protector-grade VM has no reconstructible central dispatch.
2. **The ISA is tiny and each opcode has one handler instance.** 8–13 opcodes against
   the reference protectors' hundreds of handler variants. Handler duplication and
   per-instance polymorphism exist in the codebase but do not multiply the *visible*
   case count enough to matter.
3. **Key material is compile-time constant**, so every cipher in the VM is recoverable
   by constant propagation (see above).
4. **The register file is a flat stack array** with a computable index, so a
   devirtualizer can name every virtual register.
5. **Integrity and anti-debug are observable and centralized** — one checksum byte,
   one slot, folded by two probes whose ranges and algorithms are all visible.
6. **The payload is structurally obvious**: appended `RX` segments, one contiguous
   interpreter function, contiguous bytecode at a resolvable symbol.

## What is already good

Region-level virtualization of whole functions including in-function calls, switch
tables and FP; VM-in-VM nesting; per-build operand-field permutation, ISA
personality, dispatch-shape selection and handler junk; bytecode encrypted against a
runtime self-checksum so tampering misdecodes rather than branching to a failure
path; position-independent output. The weakness is not the feature set — it is that
none of it is opaque to a decompiler.
