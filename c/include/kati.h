#ifndef KATI_H
#define KATI_H

/*
 * kati C ABI — the portability handshake.
 *
 * The core is freestanding: no malloc, no stdio, no errno, no threads.
 * Callers own every buffer. Status codes, never exceptions.
 * C++, Rust, Zig, Swift and others bind this header — not Zig internals.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KATI_MAGIC      "PBR\x01"
#define KATI_VERSION    1
#define KATI_MAX_FIELDS 128
#define KATI_NAME_MAX   64

#define KATI_COMPRESSED (1u << 0)
#define KATI_ENCRYPTED  (1u << 1)
#define KATI_HAS_SCHEMA (1u << 2)
#define KATI_HAS_MUX    (1u << 3)
#define KATI_BIG_ENDIAN (1u << 4)

#define KATI_PERM_R   0x4
#define KATI_PERM_W   0x2
#define KATI_PERM_X   0x1
#define KATI_PERM_RW  (KATI_PERM_R | KATI_PERM_W)
#define KATI_PERM_RX  (KATI_PERM_R | KATI_PERM_X)
#define KATI_PERM_WX  (KATI_PERM_W | KATI_PERM_X)
#define KATI_PERM_RWX (KATI_PERM_R | KATI_PERM_W | KATI_PERM_X)

typedef enum kati_status {
    KATI_OK = 0,
    KATI_INVALID_MAGIC = 1,
    KATI_UNSUPPORTED_VERSION = 2,
    KATI_INVALID_FLAGS = 3,
    KATI_TRUNCATED = 4,
    KATI_OVERFLOW = 5,
    KATI_INVALID_VARINT = 6,
    KATI_INVALID_FIELD_ID = 7,
    KATI_INVALID_WIRE = 8,
    KATI_TYPE_MISMATCH = 9,
    KATI_PERM_DENIED = 10,
    KATI_INVALID_TOKEN = 11,
    KATI_EXPECTED = 12,
    KATI_DUPLICATE = 13,
    KATI_UNSUPPORTED_TYPE = 14,
    KATI_EMPTY = 15,
    KATI_NOT_FOUND = 16
} kati_status;

typedef enum kati_wire {
    KATI_WIRE_VARINT  = 0,
    KATI_WIRE_FIXED64 = 1,
    KATI_WIRE_BYTES   = 2,
    KATI_WIRE_FIXED32 = 5
} kati_wire;

/* Must match Zig `schema.Primitive` then the host extras, in order. */
typedef enum kati_prim {
    KATI_I8 = 0,
    KATI_I16 = 1,
    KATI_I32 = 2,
    KATI_I64 = 3,
    KATI_U8 = 4,
    KATI_U16 = 5,
    KATI_U32 = 6,
    KATI_U64 = 7,
    KATI_F32 = 8,
    KATI_F64 = 9,
    KATI_BOOL = 10,
    KATI_CHAR = 11,
    KATI_STRING = 12,
    KATI_BYTES = 13,
    KATI_RWX = 14,
    KATI_TIMESTAMP = 15,
    KATI_DURATION = 16,
    KATI_UUID = 17,
    KATI_FN = 18
} kati_prim;

typedef enum kati_type_kind {
    KATI_TY_PRIM = 0,
    KATI_TY_ARRAY = 1,
    KATI_TY_MAP = 2,
    KATI_TY_NAMED = 3
} kati_type_kind;

typedef struct kati_header {
    uint8_t  flags;
    uint64_t schema_hash;
    uint64_t payload_len;
    size_t   header_len;
} kati_header;

typedef struct kati_field_header {
    uint32_t field_id;
    uint8_t  wire_type;
} kati_field_header;

typedef struct kati_cursor {
    const uint8_t *data;
    size_t len;
    size_t pos;
} kati_cursor;

typedef struct kati_sink {
    uint8_t *data;
    size_t cap;
    size_t pos;
} kati_sink;

typedef struct kati_type {
    kati_type_kind kind;
    kati_prim prim;     /* TY_PRIM */
    kati_prim inner;    /* TY_ARRAY */
    kati_prim key;      /* TY_MAP */
    kati_prim value;    /* TY_MAP */
    char named[KATI_NAME_MAX];
} kati_type;

typedef struct kati_field {
    char name[KATI_NAME_MAX];
    kati_type type;
    int required;
    uint32_t max;
    uint32_t field_id;
    uint8_t perms; /* 0 means unspecified → treat as rwx at the host */
} kati_field;

typedef struct kati_schema {
    char name[KATI_NAME_MAX];
    int strict;
    kati_field fields[KATI_MAX_FIELDS];
    size_t field_count;
    uint64_t schema_hash;
} kati_schema;

const char *kati_status_str(kati_status st);

void kati_cursor_init(kati_cursor *c, const uint8_t *data, size_t len);
void kati_sink_init(kati_sink *s, uint8_t *data, size_t cap);

kati_status kati_put_u8(kati_sink *s, uint8_t v);
kati_status kati_put_bytes(kati_sink *s, const uint8_t *src, size_t n);
kati_status kati_put_u64le(kati_sink *s, uint64_t v);
kati_status kati_put_varint(kati_sink *s, uint64_t v);

kati_status kati_take_u8(kati_cursor *c, uint8_t *out);
kati_status kati_take_bytes(kati_cursor *c, size_t n, const uint8_t **out);
kati_status kati_take_u64le(kati_cursor *c, uint64_t *out);
kati_status kati_take_varint(kati_cursor *c, uint64_t *out);

kati_status kati_encode_header(kati_sink *s, uint8_t flags, uint64_t schema_hash, uint64_t payload_len);
kati_status kati_decode_header(const uint8_t *data, size_t len, kati_header *out);

kati_status kati_write_field_header(kati_sink *s, uint32_t field_id, uint8_t wire);
kati_status kati_read_field_header(kati_cursor *c, kati_field_header *out);
kati_status kati_write_bool(kati_sink *s, int value);
kati_status kati_read_bool(kati_cursor *c, int *out);
kati_status kati_write_unsigned(kati_sink *s, uint64_t value);
kati_status kati_read_unsigned(kati_cursor *c, uint64_t *out);
kati_status kati_write_signed(kati_sink *s, int64_t value);
kati_status kati_read_signed(kati_cursor *c, int64_t *out);
kati_status kati_write_len(kati_sink *s, const uint8_t *bytes, size_t n);
kati_status kati_read_len(kati_cursor *c, const uint8_t **bytes, size_t *n);
kati_status kati_skip_value(kati_cursor *c, uint8_t wire);

kati_status kati_put_u16le(kati_sink *s, uint16_t v);
kati_status kati_put_u32le(kati_sink *s, uint32_t v);
kati_status kati_take_u16le(kati_cursor *c, uint16_t *out);
kati_status kati_take_u32le(kati_cursor *c, uint32_t *out);

#define KATI_MUX_FIN        1u
#define KATI_MUX_SYN        2u
#define KATI_MUX_RST        4u
#define KATI_MUX_ACK        8u
#define KATI_MUX_COMPRESSED 16u

typedef struct kati_mux {
    uint16_t chid;
    uint8_t  flags;
    uint32_t seq;
    const uint8_t *data;
    size_t len;
} kati_mux;

kati_status kati_write_mux(kati_sink *s, uint16_t chid, uint8_t flags, uint32_t seq, const uint8_t *data, size_t n);
kati_status kati_read_mux(kati_cursor *c, kati_mux *out);
kati_status kati_parse_schema(const char *src, kati_schema *out);
uint64_t    kati_hash_schema(const kati_schema *s);
int         kati_can(uint8_t field_perms, uint8_t want);

kati_status kati_payload(const uint8_t *data, size_t len, const uint8_t **out, size_t *n);
int         kati_hash_match(const kati_header *h, uint64_t schema_hash);
kati_status kati_write_packed(kati_sink *s, uint64_t count, const uint8_t *items, size_t n);
kati_status kati_read_packed(kati_cursor *c, uint64_t *count, const uint8_t **items, size_t *n);

uint32_t kati_crc32c(const uint8_t *data, size_t n);
const kati_field *kati_field_by_id(const kati_schema *s, uint32_t id);
const kati_field *kati_field_by_name(const kati_schema *s, const char *name);
kati_status kati_get(const kati_schema *s, const uint8_t *payload, size_t n, const char *path,
                     kati_field_header *fh, const uint8_t **raw, size_t *raw_n);

#ifdef __cplusplus
}
#endif
#endif /* KATI_H */
