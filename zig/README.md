# kati

A small, strict, binary data format and codec designed around Zig's explicitness and zero-managed-runtime model.

The core compiles with **Zig 0.16.0**. It has no allocator, no OS, no GC. C is the ABI; C++ and Rust bind the same bytes.

## Layout

```text
kati/
├── build.zig
├── build.zig.zon
├── src/           # protocol core (freestanding)
├── tests/
├── docs/
└── examples/
```

## Build

```sh
zig build
zig build test
zig build freestanding
zig build -Doptimize=ReleaseFast
```

CLI:

```sh
zig build run -- version
zig build run -- inspect config.pbr
zig build run -- get schema.pbr config.pbr AppConfig.name
zig build run -- dump config.pbr
```

## Runtime model

The protocol core does not need a JVM, Node, GC or application-managed VM. A hosted CLI may use the operating system. `zig build freestanding` proves the library still compiles with `os_tag = freestanding`.

## Current status (v0.7)

Header codec, checked LEB128, schema parser (config/struct/buffer/union/enum), field IDs, FNV-1a schema hash, value codec, pretty assembler/disassembler, nested named types and enums, dotted path lookup (`AppConfig.limits.cpu`, `endpoints.0`), rwx, record builder, WAL overlays, 64 KiB `none` blocks with CRC32C, mux frames, CLI (`inspect`, `assemble`, `disasm`, `check`, `get`, `dump`).
