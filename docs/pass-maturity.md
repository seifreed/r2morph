# Pass Maturity Contract

The release contract is per-pass. A pass is Tier 1 only when native tests,
runtime validation, and the compatibility corpus cover the official Linux ELF
x86-64 target. Every other entry remains experimental until its evidence is
promoted.

| Pass | Status | Target | Current limitation | Evidence |
|---|---|---|---|---|
| NOP insertion | Tier 1 | Linux ELF x86-64 | No official PE/Mach-O contract | `tests/product_smoke`, `tests/integration` |
| Instruction substitution | Tier 1 | Linux ELF x86-64 | Rule coverage is ISA-specific | `tests/product_smoke`, `tests/integration` |
| Register substitution | Tier 1 | Linux ELF x86-64 | Requires proven liveness and ABI preservation | `tests/product_smoke`, `tests/integration` |
| Instruction expansion | Experimental | ELF x86-64 | Wider replacements need more corpus coverage | `README.md` |
| Block reordering | Experimental | ELF x86-64 | Complex indirect control flow is rejected | `tests/integration` |
| Dead code injection | Experimental | ELF x86-64 | Placement depends on available safe regions | `README.md` |
| Control-flow flattening | Experimental | ELF x86-64 | No cross-tool decompiler benchmark | `README.md` |
| Opaque predicates | Experimental | ELF x86-64 | Predicate families are not exhaustive | `README.md` |
| Code virtualization | Experimental | ELF x86-64 | Unsupported functions are conservatively unchanged | `docs/protection-maturity.md` |
| Anti-disassembly | Experimental | ELF x86-64 | No independent review evidence | `README.md` |
| Data-flow mutation | Experimental | ELF x86-64 | Narrow instruction family | `README.md` |
| Short-jump patching | Experimental | ELF x86-64 | Needs more relocation coverage | `README.md` |
| Constant unfolding | Experimental | ELF x86-64 | x86-only transformation rules | `README.md` |
| Code mobility | Experimental | ELF x86-64 | Code-cave geometry is input-dependent | `README.md` |
| Function outlining | Experimental | ELF x86-64 | ABI and exception edges need more evidence | `README.md` |
| API hashing | Experimental | ELF x86-64 | External symbol behavior is environment-dependent | `README.md` |
| Import obfuscation | Experimental | ELF x86-64 | Format-specific import handling | `README.md` |
| Self-modifying code | Experimental | ELF x86-64 | Runtime validation is mandatory and limited | `README.md` |

The machine-readable format and evidence paths are in
[`support-matrix.json`](support-matrix.json). A pass cannot be promoted by a
single fixture or a static disassembly result alone.
