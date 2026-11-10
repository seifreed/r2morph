# Public API and CLI compatibility contract

This contract defines the compatibility surface intended for the 1.0 release.
The current `0.4.0-alpha.3` release remains pre-stable; the contract does not
claim that 1.0 criteria have already been met.

## Python API

The package root is the supported import surface:

```python
from r2morph import Binary, MorphEngine, Pipeline
```

`r2morph.__all__` and the behavior of those exported classes are covered by
`tests/unit/test_public_surface_contract.py`. CI also runs this contract
against the installed wheel on Linux and in the cross-platform package smoke
job. Modules not exported by the package root remain implementation details
unless a later version explicitly promotes them here.

## CLI

The installed `r2morph` command is bound to `r2morph.cli:app`. Its top-level
commands, the `morph`/`mutate` aliases, and the long options of `mutate` are
compatibility surfaces. The regression test for these names is
`tests/unit/test_public_surface_contract.py`, including when CI imports the
installed wheel rather than the source checkout.

The default command, `analyze`, `functions`, `validate`, `diff`, `report`,
`version`, `cache`, and `experimental analyze-enhanced` are listed explicitly
so changes to command routing are reviewed as API changes. The short options
remain aliases for their corresponding long options.

## Compatibility policy for 1.0 and later

- A minor release may add Python exports, commands, options, and report fields.
- A minor release must not remove or change the meaning of a contracted export,
  command, option, or report field.
- A removal or incompatible behavior change requires a deprecation period and a
  major version change. The release notes must identify the replacement and
  migration path.
- JSON and SARIF compatibility is governed by their checked-in schemas and
  schema-version fields; schema changes require the associated contract tests.
- Experimental commands and mutation capabilities are excluded from stability
  guarantees and must remain labeled experimental in help and documentation.

Before 1.0, changes may still revise this contract. The 1.0 release gate must
require this document and its regression tests to match the shipped package.
