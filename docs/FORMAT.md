# kati `.pbr` format — working contract

## Header

| Field | Size |
|---|---:|
| MAGIC | 4 bytes |
| FLAGS | 1 byte |
| SCHEMA_HASH | 8 bytes |
| PAYLOAD_LEN | unsigned LEB128 |
| PAYLOAD | `PAYLOAD_LEN` bytes |

MAGIC is `PBR\x01`. Integer fields are little-endian unless the future big-endian flag is explicitly defined.

## Flags

- bit 0: compressed
- bit 1: encrypted
- bit 2: has-schema
- bit 3: has-mux
- bit 4: big-endian
- bits 5–7: reserved and must be zero

## Schema IDs

A field uses `@id(n)` when explicitly assigned. Otherwise its ID is its one-based declaration position. Duplicate or zero IDs are rejected.

## Schema hash

The current implementation uses a provisional FNV-1a 64-bit hash over a canonical schema representation prefixed by `kati-schema-v1`. This algorithm is **not yet the v1 compatibility contract**. The format must not be frozen until the hash algorithm and canonicalization rules are reviewed.
