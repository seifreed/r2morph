# VM literal recursion — scoping

Status: working. The devirtualization oracle, the VM front-end pieces, and the
end-to-end emulated round trip a recursion spike needs are built and green (see §5);
an interpreter whose own dispatch loop is virtualized still runs correctly. This
note captures what "literal recursion" means for the code-virtualization VM, why
the current codebase could not express it, and what the spike had to build. All
file:line references are against the tree this note was written from; treat them as
anchors, not guarantees.

## 1. Goal — what "literal recursion" means

The region interpreter is a computed-goto dispatch loop: it decodes an opcode
byte, bounds-checks it, indexes an encrypted dispatch table, and jumps to the
selected handler, which decodes the next opcode and jumps again. The hot path
of that loop is a **register-indirect jump** (`jmp rax` after the table load)
plus the **flag save/restore** the handlers rely on.

"Nesting" (`code_virtualization_region_nesting.py`) is often mistaken for
recursion. It is not. Nesting peels a contiguous run of *pure, flag-independent
arithmetic/stack micro-ops* out of one layer's bytecode into a second,
independently-keyed VM layer, reached by an `enter_inner` transfer and returning
through `inner_exit`. It never re-virtualizes control flow, never touches the
dispatch loop, and bails entirely on any `call`/`icall`/`callmem*`
(`code_virtualization_region_nesting.py:278`). The layers share one register
frame; each is still a plain straight-line-plus-branch region.

**Literal recursion** is the strictly harder thing nesting is not: feed the
interpreter's *own* dispatch code — the computed `jmp rax`, the table index, the
flag transfer — back through the region virtualizer, so that recovering the
outer VM reveals a second VM whose bytecode *is the first VM's interpreter*.
The primary VM would then be executing a virtualized copy of its own fetch/
decode/dispatch cycle. This is nested virtualization of the interpreter, not of
the payload the interpreter runs.

## 2. Why it is blocked today

The region front-end (`extract_region` → `_classify` → guards) is built for
*reducible, straight-line-with-in-function-branches, stack-balanced, ret/syscall
terminated* code. Dispatch-loop-shaped code violates that contract at six
independent points, and the devirtualization side that a spike would validate
against has three unimplemented recovery stubs.

### Structural guards that reject dispatch-shaped code

1. **`_classify` accepts only direct `jmp` / `cjmp`.**
   `code_virtualization_region.py:287-288` returns `["jmp", target]` for a
   direct jump and `:289-291` returns `["jcc", cond, target]` for a conditional
   one. Every other jump kind — the computed/indirect `jmp rax`, and r2's
   `ujmp`/`rjmp`/`ijmp`/`mjmp` families — falls through to `return None`
   (`:292`). The dispatch loop's defining instruction is exactly a computed
   `jmp rax`, so classification rejects it before anything else runs. **This is
   the direct blocker for re-virtualizing the `jmp rax` dispatch.**

2. **No `pushfq`/`popfq` classification path.** The push/pop decoders are
   GP-register-only: `_decode_push` (`code_virtualization_region_decoders.py:93`)
   requires the mnemonic to be exactly `push` and the operand to be a 64-bit GP
   register or an imm32; `_decode_pop` (`:187`) is the symmetric GP-only case.
   `pushfq`/`popfq` (distinct mnemonics operating on RFLAGS) are never decoded,
   so the flag save/restore that a virtualized dispatch loop must carry has no
   item representation at all.

3. **`extract_region` requires a `ret`/`syscall` terminator.**
   `code_virtualization_region.py:647-649` collects exit addresses from
   instructions typed `ret`/`swi`/`syscall` and returns `None` when there are
   none. A dispatch loop is an infinite computed-goto: it has no `ret` and no
   `syscall` — it exits only by jumping to a handler that itself jumps back.
   With no terminator there are no VM exits to build, so extraction refuses the
   region.

4. **Stack-balance guard.** `_stack_balanced` (`code_virtualization_region.py:327-399`,
   gated at `:710-711`) requires every path to reach each terminator at its
   entry stack depth, tracking per-item byte depth and the `mov reg, rsp`
   frame-pointer snapshot; a conflicting depth, an underflow, or a non-zero
   depth at a terminator rejects the region (`:377`). Dispatch code pushes/pops
   flag and scratch state across the computed jump in a pattern the linear
   depth model cannot prove balanced, and it has no terminator to balance
   against in the first place.

5. **Self-referential-call guard.** `code_virtualization_region.py:702-708`
   rejects any `call` whose target lands inside the function's own
   `[func_lo, func_hi)` span, because such a call would recurse into the
   trampoline or hit body bytes the dead-body fill overwrites. The interpreter
   reaches its handlers by an in-range computed jump — morally the same
   self-referential control transfer this guard exists to forbid — so even if
   the jump were reclassified, the "stay out of your own span" invariant would
   have to be rethought.

6. **Reducibility assumption of the whole front-end.** `extract_region`
   (`:637`) is documented to accept only register ops, comparisons, `nop`,
   in-function branches, and terminators, resolving every branch target to an
   item index (`:684-700`) and returning `None` on any unresolved target. A
   dispatch loop's target set is *data-dependent* (an entry read from an
   encrypted table), not a static set of in-function labels, so it cannot be
   resolved to fixed item indices at all.

### Extractor recovery stubs (the validation side is not built)

A recursion spike needs a devirtualizer that can actually recover a virtualized
interpreter to prove round-trip correctness. Three recovery functions in
`r2morph/devirtualization/vm_handler_analyzer.py` are explicit no-ops:

- **`_extract_table_from_block`** (`:191-194`) returns `None` — handler-table
  address recovery from a dispatcher block is unimplemented.
- **`_analyze_vm_context`** (`:391-400`) returns without doing anything and
  documents that register-allocation / context-pointer / spill-slot inference
  is "not yet implemented", deliberately leaving `VMArchitecture` at defaults
  rather than fabricating values.
- **`_locate_vm_bytecode`** (`:402-408`) returns without doing anything;
  bytecode-section discovery adjacent to the dispatcher is "not yet
  implemented".

Without table, context, and bytecode recovery there is no way to observe that a
recursively virtualized interpreter is still semantically the interpreter, so a
spike would be flying blind.

## 3. What a real spike needs

Each item below is a genuine, generic capability (not a sample-specific hack).
They are ordered roughly by dependency.

1. **Indirect-jump classifier path.** Extend `_classify` to recognize a
   register-indirect / table-indexed computed jump and lower it to a new item
   kind (e.g. an `ijmp` micro-op) whose runtime target is a value in a slot
   rather than a static item index. This is the load-bearing change; the branch
   resolver (`:684-700`) and the encoders must learn a target that is computed
   at run time, not resolved at build time.

2. **`pushfq`/`popfq` as first-class flag-transfer items.** Add decoders and
   handlers that model RFLAGS save/restore as explicit VM items, so the flag
   state a virtualized dispatch loop moves across the computed jump has a
   representation the flag-liveness analysis (`_flag_dead_op_indices`,
   `code_virtualization_region.py:438`) and the micro-op lowering can reason
   about. Without this the interpreter's own flag handling cannot be lowered.

3. **Loop-terminator relaxation.** Introduce a terminator notion for a
   computed-goto loop — an explicit "dispatch exit" edge — so `extract_region`
   (`:647-649`) and `_stack_balanced` (`:327-399`) have something to anchor the
   exit/balance analysis on when there is no `ret`/`syscall`. This likely means
   a separate extraction entry point for dispatch-shaped regions rather than
   overloading the reducible-function path, so the existing straight-line
   contract and its tests stay intact.

4. **Extractor table/context/bytecode recovery.** Implement the three stubs in
   `vm_handler_analyzer.py` (`_extract_table_from_block`, `_analyze_vm_context`,
   `_locate_vm_bytecode`) so the spike can round-trip: virtualize the
   interpreter, then recover its table, context, and bytecode and assert the
   recovered VM is equivalent to the original interpreter. This is the
   acceptance harness for the whole effort.

## 4. Risk notes

- **Primary-VM miscompile surface.** Re-virtualizing the interpreter's own
  fetch/decode/dispatch means a single lowering bug corrupts *both* the payload
  execution and the mechanism that executes it, with no independent oracle
  inside the same build. The self-checksum
  (`code_virtualization_region_integrity`) and tracer fold both live in the
  interpreter code; recursing over that code changes what is checksummed, so
  their invariants must be re-derived for the recursive layer, not assumed. A
  miscompiled dispatch jump is far harder to localize than a
  miscompiled arithmetic micro-op, because the failure manifests as the whole
  VM losing its place.

- **Guard relaxations must not leak into the reducible path.** The six guards
  above protect the ordinary straight-line region virtualizer and its
  regression suite. Relaxing them globally would silently admit code the
  current VM cannot correctly lower. The dispatch-shaped path should be a
  separate, opt-in extraction contract with its own guards and its own tests,
  so making recursion possible never weakens the guarantees the non-recursive
  path already ships.

- **Multi-session scope.** This is not a single-commit change. At minimum it is:
  (a) the indirect-jump item + encoder/resolver work, (b) flag-transfer items,
  (c) a dispatch-region extraction contract, and (d) the devirtualization
  recovery harness — each independently testable and each a regression contract
  on its own. Attempting them together would produce an unreviewable change with
  no intermediate green state. A spike should first stand up (d) against a
  hand-built virtualized-interpreter fixture to get an oracle, then attack (a).

## 5. Progress

Built and green (each its own commit, in the doc's recommended order):

- **(d) Devirtualization oracle.** `fixtures/dataset/elf_vm_interp_x86_64` is a hand-built
  computed-goto interpreter fixture (exit 45). The three recovery stubs in
  `vm_handler_analyzer.py` are implemented: `_extract_table_from_block` recovers
  the handler table from the dispatch block's register-indirect jump operand;
  `_locate_vm_bytecode` finds the bytecode region via the virtual program counter
  (the register the one-byte opcode fetch dereferences); `_analyze_vm_context`
  infers the vpc and opcode registers. Covered by
  `tests/integration/test_vm_interpreter_devirt_real.py`.

- **(a) Indirect-jump item.** A register-indirect jump lowers to an `ijmp` item
  (`_classify`, gated behind `allow_computed_jump` so the straight-line contract
  is unchanged) whose runtime target re-enters the VM at the virtualized target
  via a target map (native address -> bytecode offset) baked into the blob. The
  `ijmp` handler, the map, and the encoder emit are in place; a region with no
  computed jump emits no map and is byte-identical.

- **(c) Dispatch-region contract.** `extract_region(..., allow_computed_jump=True)`
  classifies the computed jump and builds the target map, threaded through the
  lowering and junk passes. Opt-in; the straight-line suite (600+ tests) is
  unchanged.

- **Latent bug fixed en route.** The per-handler scratch rename corrupted any
  flag-capture body (it remapped `rax` to r8-r15 across a `lahf`/`ah`, emitting an
  illegal `movzx r10d, ah`); such bodies are now left unrenamed.

**Green — the end-to-end round trip.** Against a register-indirect dispatch fixture
(`fixtures/dataset/elf_vm_interp_reg_x86_64`, exit 45), the whole function extracts into an
`ijmp` region, the interpreter blob assembles, injects, the trampoline is patched,
and the mutated binary — now running a virtualized copy of its own fetch/decode/
dispatch cycle — still emulates to exit 45 across a seed sweep. Covered by
`tests/integration/test_vm_interpreter_recursion_real.py`
(`test_recursively_virtualized_interpreter_preserves_exit_code`).

The bug that blocked it was the "hard to localize" dispatch miscompile §4 warned of,
and it was in the new code, not the VM's value handlers: the `ijmp` target map was
emitted **after** the dispatch table, but `build_region_blob` locates the table as
the last `total*4` bytes of the assembled interpreter (to decrypt it at runtime and
to bound the self-checksum). Data after the table shifted that window, so every
opcode misdecoded and the first computed jump landed in junk. Emitting the map
before the table fixed it. (The value chain — rip-relative table-base `lea`, shift,
add, indexed load — was correct all along, confirmed by isolated round trips.)

The dispatch path is wired into `CodeVirtualizationPass` as the inferred default:
a dispatch-shaped function the reducible path rejects is gathered linearly and
virtualized through the contract. An explicit `virtualize_dispatch: false` override
keeps computed jumps native for debugging and regression reproduction.

- **(b) Flag-transfer items.** A native `pushfq`/`popfq` bracketing the dispatch lowers
  to `fsave`/`frestore` items that save and restore the virtual RFLAGS through the
  vstack — the flags slot and the vstack both persist across `vm_dispatch`, so the flag
  state crosses the computed jump inside the VM's own frame. Gated to the dispatch-region
  contract (the straight-line contract keeps leaving `pushfq`/`popfq` native), and the
  dead-flag analysis counts `fsave` as a flags reader so an op whose flags a following
  `pushfq` saves is not dead-eliminated. Covered by
  `tests/unit/test_code_virtualization_fsave_classify.py`,
  `..._fsave_handler.py`, `..._fsave_flag_liveness.py`, and the load-bearing round trip
  `tests/integration/test_vm_interpreter_flagcross_real.py`
  (`fixtures/dataset/elf_vm_interp_stack_x86_64`, exit 45 — a broken save/restore changes the
  exit code).

Symbolic closure — deliberately not done. The (d) oracle does **not** recover the
recursed layer, and that is the region VM working as designed, not a gap: the region
interpreter's dispatch is a threaded, no-hub, register-indexed computed goto with
XOR-encrypted offsets (`movsxd rax, eax; add rax, r14; jmp rax`, the decode inlined
at every handler tail), whereas the oracle targets an absolute memory-indirect table
(`jmp [table+idx*8]`). So literal recursion is proven **behaviourally** (round-trip
exit-code parity); recovering the recursed layer symbolically would mean teaching the
oracle the region VM's own anti-devirtualization shape — a separate, larger effort.
That resistance is now pinned as an enforced property:
`tests/integration/test_vm_interpreter_recursion_resistance_real.py` asserts the
recursively-virtualized interpreter's structural devirtualization resistance rises
sharply and the recovery oracle cannot reconstruct the region VM's handler set —
without teaching the oracle that shape.
