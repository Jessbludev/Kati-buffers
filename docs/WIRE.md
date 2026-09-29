# kati value wire format v1

The `.pbr` header is followed by a payload. This document freezes the first
payload framing used by the Zig core.

Each field is encoded as:

```text
FIELD_ID   varint
WIRE_TYPE  u8
VALUE      wire-type dependent
```

Wire types:

| Value | Type | Encoding |
|---|---:|---|
| unsigned integer / bool | 0 | LEB128 varint |
| signed integer | 0 | ZigZag + LEB128 |
| fixed64 / f64 | 1 | 8-byte little-endian |
| string / bytes / nested payload | 2 | length varint + bytes |
| fixed32 / f32 | 5 | 4-byte little-endian |

Field IDs are positive. Unknown fields can be skipped using their wire type.
The core rejects malformed/truncated values rather than silently recovering.

This is the payload codec, not yet the complete schema compiler or transport
layer. Arrays/maps and nested structs use length-delimited sub-values: a count
varint, then bare items. Mux frames sit beside this:

```text
CHID   u16 LE
FLAGS  u8     FIN SYN RST ACK COMPRESSED
SEQ    u32 LE
LEN    varint
DATA   n B
```

