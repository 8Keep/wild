# PE Support In linker-diff

`linker-diff` now dispatches by object format. The existing ELF implementation remains the full
comparison path. PE64 uses a smaller semantic comparator intended to be low-noise while Wild's PE
output is still maturing.

## Current PE Scope

The PE comparator checks:

- COFF machine type
- subsystem
- coarse file characteristics: executable, DLL, large-address-aware, relocs-stripped
- entry point presence
- section names and coarse section flags
- non-empty data-directory presence
- imported DLL/symbol-name sets
- base relocation block/page/entry/type summary

It intentionally ignores:

- exact section RVAs and file offsets
- padding bytes
- timestamps and checksums
- exact `.idata` internal ordering
- byte-for-byte section contents
- instruction-level relocation/relaxation equivalence

## Usage

PE64 files use the same CLI shape as ELF files:

```sh
cargo run -p linker-diff --bin linker-diff -- --ref reference.exe wild.exe
```

The comparator accepts multiple references and uses the existing `--ignore`, `--only`, and
`--display-names` handling. Coverage reporting is currently ELF-only and returns an explicit error
for PE files.

## Next Steps

- Add PE32 support only when there is a test case that needs it.
- Add per-directory detail for exports, resources, exceptions, TLS, and load config as Wild learns
  to emit those structures.
- Add richer import comparison for ordinal imports and duplicate import coalescing.
- Consider section-content comparison only after there is enough PE relocation modeling to avoid
  noisy false positives.
