# kati — initial Zig architecture

## Principle

`kati` is split into two layers:

- `src/kati.zig`: protocol core. No allocator, OS API, thread, global mutable state, GC or managed runtime dependency.
- `src/main.zig`: optional host CLI. It may use Zig standard library and OS facilities.

The protocol header follows the supplied specification: `PBR\x01`, flags, 64-bit schema hash, and LEB128 payload length.

## Compatibility rule

The byte format is part of the public contract. Changes to field encoding, header layout, endianness or varint semantics require a format-version decision.

## Safety policy

- Bounds checked reads/writes.
- Malformed input returns errors; no partial success.
- Varints reject overflow and overlong encodings.
- Reserved header bits are rejected.
- No implicit allocation in the protocol core.
- No hidden mutation.

## Next implementation order

1. Schema AST and `.pbr` text parser.
2. Deterministic field IDs and canonical encoding.
3. Primitive/compound value codec.
4. Schema hash calculation and compatibility checks.
5. Pretty assembler/disassembler.
6. Streaming blocks + checksums.
7. Permissions and mux as separate modules.
8. C ABI and Zig/C++/Rust bindings.
9. Kotlin/Native and TypeScript adapters.

## Schema compiler boundary

`src/schema.zig` is intentionally separate from the protocol core. It parses the textual `.pbr` schema into fixed-capacity structures supplied by the caller and performs no allocation.

The initial grammar supports `@strict`, `config`/`struct`/`buffer`, primitive fields, `array[T]`, `map[K,V]`, and the annotations needed by the first schema milestone: `@required`, `@max(n)`, `@id(n)`, `@compress(name)` and boolean defaults.

Field IDs are explicit with `@id(n)` or deterministic 1-based declaration order. Duplicate IDs and names are rejected. The initial schema hash is FNV-1a over a canonical field sequence and is provisional until v1 format freeze.
