# kati language

kati is a small, line-oriented language for records. The same source compiles to a typed binary PrettyBuffer and to a human assembly listing.

## Grammar

```
file       := type-def+
type-def   := annot* (config | struct | buffer | union | enum) ident { member* }
member     := field | variant
field      := ident : type annot* [ = literal ]
type       := primitive | [ type ] | array[type] | map<type, type> | map[type, type] | ident
annot      := @ ident [ ( args ) ]
pretty     := #PBR int [ @schema … ] . ident { field-bind* }
field-bind := ident = value
value      := literal | [ value* ] | { ident : value* } | ident { field-bind* } | h"hex" | rwx:octal
```

Newlines separate fields. Commas are optional. Comments are `#` or `//` to end of line, except the pretty marker `#PBR`.

## Records

`config` and `buffer` are roots. `struct` is nested. `union` is a tagged choice: exactly one field is present on the wire.

```
union Packet {
  ping: Ping
  pong: Pong
}

struct Ping { n: u32 }
struct Pong { ok: bool }
```

Pretty uses tag syntax so a union does not look like a map:

```
.Wire {
  packet = ping { n = 1 }
}
```

## Types

Primitives: `i8 i16 i32 i64`, `u8 u16 u32 u64`, `f32 f64`, `bool`, `char`, `string`, `bytes`.

Specials: `rwx`, `timestamp` (unix ms), `duration` (ms), `uuid`, `fn` (opaque executable payload).

Compounds: `[T]` / `array[T]`, `map<K,V>` / `map[K,V]`, named structs, enums, unions.

The Zig core, the C ABI, and the TypeScript host accept both the spec brackets and the Zig `array[]` / `map[]` spellings. They hash to the same tags.

Unions are a tagged choice. Pretty uses `ping { n = 1 }` so a union does not look like a map.

Mux frames (CHID u16, flags, SEQ u32, LEN varint, DATA) are a separate layer. They do not change the PrettyBuffer header.

## Annotations

| Annot | Meaning |
| --- | --- |
| `@strict` | unknown fields are errors |
| `@required` | must be present (or defaulted) |
| `@max(n)` | array length cap |
| `@id(n)` | explicit field id (else 1-based order) |
| `@compress(name)` | payload hint (zstd, lz4, brotli) |
| `@default(lit)` / `= lit` | default |
| `@r @w @x @rw @rx @rwx` | field permissions |

Unspecified permissions are `rwx`. Native hosts refuse writes on `@r` the same way POSIX refuses a 0444 file.

## Hash

FNV-1a 64 over a canonical transcript prefixed by `kati-schema-v1\0`. The algorithm is provisional until v1 freeze. Changing field order, names, types, ids or `required` changes the hash.
