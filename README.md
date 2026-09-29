# kati

A compiled, strict stand-in for JSON. The schema lives in the buffer — or hashed beside it. The core is Zig 0.16: no GC, no VM, no allocator. C is the ABI. C++ and Rust bind the same bytes.

```
native/
├── zig/     protocol core (v0.7) — no allocator, no OS
├── c/       freestanding C ABI + CLI
├── cpp/     header-only C++20 guest
└── rust/    no_std guest
```

## Runtime model

“No runtime” means the protocol core does not need a JVM, Node, GC, or application-managed VM. A hosted CLI may use the operating system. The core is a slice in, a header (or a schema) out.

## Wire

```
MAGIC        4 B     50 42 52 01
FLAGS        1 B     bit0 compressed · bit1 encrypted · bit2 schema · bit3 mux · bit4 BE
SCHEMA_HASH  8 B     FNV-1a 64, prefix kati-schema-v1
PAYLOAD_LEN  varint  unsigned LEB128
PAYLOAD      n B     field_id varint · wire u8 · value
```

Field IDs are declaration order unless `@id(n)` is set. Unknown fields skip by wire type unless the record is `@strict`.

## Build

```sh
# C (gcc)
make -C c test
make -C c cli

# C++ (g++ 20, links the C objects)
g++ -std=c++20 -I c/include -I cpp/include cpp/examples/hash.cpp c/src/kati.c -o /tmp/kati-cpp
/tmp/kati-cpp

# Rust (no crates.io)
rustc --edition 2021 --test rust/src/lib.rs --cfg 'feature="std"'

# Zig 0.16.0
cd zig && zig build test
cd zig && zig build freestanding
```

The C, C++, Rust, and TypeScript hosts compute the same FNV-1a for the Zig `AppConfig` fixture: `0x3d742323fdeca80b`.

## Language

See [docs/LANGUAGE.md](docs/LANGUAGE.md). Pretty assembly is the human form of the same record.

```
@strict
config AppConfig {
  name:      string   @required
  version:   u16
  debug:     bool     = false
  endpoints: [string] @max(32)
}
```

```
#PBR 1
.AppConfig {
  name    = "server-a"
  version = 0x0104
}
```

## CLI

```sh
zig build run -- version
zig build run -- inspect config.pbr
zig build run -- assemble schema.pbr app.pretty out.pbr
zig build run -- get schema.pbr config.pbr AppConfig.name
zig build run -- dump config.pbr
```

License: Apache-2.0.
