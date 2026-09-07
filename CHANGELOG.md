# Changelog

## 0.4.0-alpha.3

- Fixes release artifact download in the isolated PyPI publish job.
- Publishes the same verified ELF x86-64 support contract as alpha.2.

## 0.4.0-alpha.2

- Publishes the current ELF x86-64 virtualization and validation evidence.
- Includes the complete 159-fixture CodeVirtualization corpus result.
- Retains Triton and angr as reproducible analyzer dependencies for the Linux
  x86-64 release target.

## 0.4.0-alpha.1

- Declares Linux ELF x86-64 as the official initial target.
- Adds a versioned support matrix and per-pass maturity contract.
- Adds installed-wheel and `r2morph --version` smoke checks.
- Publishes the reproducible compatibility-corpus contract.
- Removes the unused Triton optional dependency that has no compatible wheel for
  the supported Python 3.12 and 3.13 environments.
- Release automation emits checksums, a CycloneDX SBOM, and build provenance.
