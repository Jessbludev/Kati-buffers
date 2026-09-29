#include "kati.h"

/* Freestanding core. No libc. Callers own memory. */

static int eq(const char *a, size_t n, const char *lit) {
    size_t i = 0;
    while (lit[i]) i++;
    if (n != i) return 0;
    for (i = 0; i < n; i++) if (a[i] != lit[i]) return 0;
    return 1;
}

static void copy_name(char *dst, const char *src, size_t n) {
    size_t i = 0;
    if (n >= KATI_NAME_MAX) n = KATI_NAME_MAX - 1;
    for (; i < n; i++) dst[i] = src[i];
    dst[i] = 0;
}

const char *kati_status_str(kati_status st) {
    switch (st) {
        case KATI_OK: return "ok";
        case KATI_INVALID_MAGIC: return "invalid magic";
        case KATI_UNSUPPORTED_VERSION: return "unsupported version";
        case KATI_INVALID_FLAGS: return "invalid flags";
        case KATI_TRUNCATED: return "truncated";
        case KATI_OVERFLOW: return "overflow";
        case KATI_INVALID_VARINT: return "invalid varint";
        case KATI_INVALID_FIELD_ID: return "invalid field id";
        case KATI_INVALID_WIRE: return "invalid wire type";
        case KATI_TYPE_MISMATCH: return "type mismatch";
        case KATI_PERM_DENIED: return "permission denied";
        case KATI_INVALID_TOKEN: return "invalid token";
        case KATI_EXPECTED: return "expected symbol";
        case KATI_DUPLICATE: return "duplicate";
        case KATI_UNSUPPORTED_TYPE: return "unsupported type";
        case KATI_EMPTY: return "empty";
        case KATI_NOT_FOUND: return "not found";
        default: return "error";
    }
}

void kati_cursor_init(kati_cursor *c, const uint8_t *data, size_t len) {
    c->data = data;
    c->len = len;
    c->pos = 0;
}

void kati_sink_init(kati_sink *s, uint8_t *data, size_t cap) {
    s->data = data;
    s->cap = cap;
    s->pos = 0;
}

kati_status kati_put_u8(kati_sink *s, uint8_t v) {
    if (s->pos >= s->cap) return KATI_TRUNCATED;
    s->data[s->pos++] = v;
    return KATI_OK;
}

kati_status kati_put_bytes(kati_sink *s, const uint8_t *src, size_t n) {
    if (n > s->cap - s->pos) return KATI_TRUNCATED;
    for (size_t i = 0; i < n; i++) s->data[s->pos + i] = src[i];
    s->pos += n;
    return KATI_OK;
}

kati_status kati_put_u64le(kati_sink *s, uint64_t v) {
    for (int i = 0; i < 8; i++) {
        kati_status st = kati_put_u8(s, (uint8_t)(v & 0xffu));
        if (st) return st;
        v >>= 8;
    }
    return KATI_OK;
}

kati_status kati_put_varint(kati_sink *s, uint64_t v) {
    while (v >= 0x80) {
        kati_status st = kati_put_u8(s, (uint8_t)((v & 0x7fu) | 0x80u));
        if (st) return st;
        v >>= 7;
    }
    return kati_put_u8(s, (uint8_t)v);
}

kati_status kati_take_u8(kati_cursor *c, uint8_t *out) {
    if (c->pos >= c->len) return KATI_TRUNCATED;
    *out = c->data[c->pos++];
    return KATI_OK;
}

kati_status kati_take_bytes(kati_cursor *c, size_t n, const uint8_t **out) {
    if (n > c->len - c->pos) return KATI_TRUNCATED;
    *out = c->data + c->pos;
    c->pos += n;
    return KATI_OK;
}

kati_status kati_take_u64le(kati_cursor *c, uint64_t *out) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t b;
        kati_status st = kati_take_u8(c, &b);
        if (st) return st;
        v |= ((uint64_t)b) << (8 * i);
    }
    *out = v;
    return KATI_OK;
}

kati_status kati_take_varint(kati_cursor *c, uint64_t *out) {
    uint64_t value = 0;
    unsigned shift = 0;
    for (int count = 0; count < 10; count++) {
        uint8_t b;
        kati_status st = kati_take_u8(c, &b);
        if (st) return st;
        uint64_t part = (uint64_t)(b & 0x7f);
        if (shift >= 64 || (shift == 63 && part > 1)) return KATI_OVERFLOW;
        value |= part << shift;
        if ((b & 0x80) == 0) {
            if (part == 0 && count > 0) return KATI_INVALID_VARINT;
            *out = value;
            return KATI_OK;
        }
        shift += 7;
    }
    return KATI_INVALID_VARINT;
}

kati_status kati_encode_header(kati_sink *s, uint8_t flags, uint64_t schema_hash, uint64_t payload_len) {
    if (flags & 0xe0u) return KATI_INVALID_FLAGS;
    kati_status st;
    st = kati_put_bytes(s, (const uint8_t *)KATI_MAGIC, 4);
    if (st) return st;
    st = kati_put_u8(s, flags);
    if (st) return st;
    st = kati_put_u64le(s, schema_hash);
    if (st) return st;
    return kati_put_varint(s, payload_len);
}

kati_status kati_decode_header(const uint8_t *data, size_t len, kati_header *out) {
    kati_cursor c;
    kati_cursor_init(&c, data, len);
    const uint8_t *magic;
    kati_status st = kati_take_bytes(&c, 4, &magic);
    if (st) return st;
    if (magic[0] != 'P' || magic[1] != 'B' || magic[2] != 'R') return KATI_INVALID_MAGIC;
    if (magic[3] != KATI_VERSION) return KATI_UNSUPPORTED_VERSION;
    uint8_t flags;
    st = kati_take_u8(&c, &flags);
    if (st) return st;
    if (flags & 0xe0u) return KATI_INVALID_FLAGS;
    uint64_t hash, plen;
    st = kati_take_u64le(&c, &hash);
    if (st) return st;
    st = kati_take_varint(&c, &plen);
    if (st) return st;
    out->flags = flags;
    out->schema_hash = hash;
    out->payload_len = plen;
    out->header_len = c.pos;
    return KATI_OK;
}

kati_status kati_write_field_header(kati_sink *s, uint32_t field_id, uint8_t wire) {
    if (field_id == 0) return KATI_INVALID_FIELD_ID;
    if (wire != 0 && wire != 1 && wire != 2 && wire != 5) return KATI_INVALID_WIRE;
    kati_status st = kati_put_varint(s, field_id);
    if (st) return st;
    return kati_put_u8(s, wire);
}

kati_status kati_read_field_header(kati_cursor *c, kati_field_header *out) {
    uint64_t id;
    kati_status st = kati_take_varint(c, &id);
    if (st) return st;
    if (id == 0 || id > 0xffffffffull) return KATI_INVALID_FIELD_ID;
    uint8_t wire;
    st = kati_take_u8(c, &wire);
    if (st) return st;
    if (wire != 0 && wire != 1 && wire != 2 && wire != 5) return KATI_INVALID_WIRE;
    out->field_id = (uint32_t)id;
    out->wire_type = wire;
    return KATI_OK;
}

kati_status kati_write_bool(kati_sink *s, int value) {
    return kati_put_varint(s, value ? 1 : 0);
}

kati_status kati_read_bool(kati_cursor *c, int *out) {
    uint64_t v;
    kati_status st = kati_take_varint(c, &v);
    if (st) return st;
    if (v == 0) {
        *out = 0;
        return KATI_OK;
    }
    if (v == 1) {
        *out = 1;
        return KATI_OK;
    }
    return KATI_TYPE_MISMATCH;
}

kati_status kati_write_unsigned(kati_sink *s, uint64_t value) {
    return kati_put_varint(s, value);
}

kati_status kati_read_unsigned(kati_cursor *c, uint64_t *out) {
    return kati_take_varint(c, out);
}

kati_status kati_write_signed(kati_sink *s, int64_t value) {
    uint64_t u = (uint64_t)value;
    uint64_t encoded = (u << 1) ^ (uint64_t)(value >> 63);
    return kati_put_varint(s, encoded);
}

kati_status kati_read_signed(kati_cursor *c, int64_t *out) {
    uint64_t encoded;
    kati_status st = kati_take_varint(c, &encoded);
    if (st) return st;
    uint64_t value = encoded >> 1;
    uint64_t sign = encoded & 1;
    *out = (int64_t)(value ^ (0ull - sign));
    return KATI_OK;
}

kati_status kati_write_len(kati_sink *s, const uint8_t *bytes, size_t n) {
    kati_status st = kati_put_varint(s, n);
    if (st) return st;
    return kati_put_bytes(s, bytes, n);
}

kati_status kati_read_len(kati_cursor *c, const uint8_t **bytes, size_t *n) {
    uint64_t len;
    kati_status st = kati_take_varint(c, &len);
    if (st) return st;
    if (len > c->len - c->pos) return KATI_TRUNCATED;
    *n = (size_t)len;
    return kati_take_bytes(c, *n, bytes);
}

kati_status kati_skip_value(kati_cursor *c, uint8_t wire) {
    uint64_t tmp;
    uint8_t b;
    const uint8_t *p;
    size_t n;
    switch (wire) {
        case KATI_WIRE_VARINT:
            return kati_take_varint(c, &tmp);
        case KATI_WIRE_FIXED64:
            return kati_take_u64le(c, &tmp);
        case KATI_WIRE_FIXED32:
            if (kati_take_u8(c, &b)) return KATI_TRUNCATED;
            if (kati_take_u8(c, &b)) return KATI_TRUNCATED;
            if (kati_take_u8(c, &b)) return KATI_TRUNCATED;
            return kati_take_u8(c, &b);
        case KATI_WIRE_BYTES:
            return kati_read_len(c, &p, &n);
        default:
            return KATI_INVALID_WIRE;
    }
}

int kati_can(uint8_t field_perms, uint8_t want) {
    uint8_t bits = field_perms ? field_perms : (uint8_t)KATI_PERM_RWX;
    return (bits & want) == want;
}

/* ---------------- schema parser + FNV-1a ---------------- */

typedef enum {
    TK_EOF,
    TK_IDENT,
    TK_NUMBER,
    TK_STRING,
    TK_AT,
    TK_LBRACE,
    TK_RBRACE,
    TK_LBRACKET,
    TK_RBRACKET,
    TK_LPAREN,
    TK_RPAREN,
    TK_LANGLE,
    TK_RANGLE,
    TK_COLON,
    TK_EQUAL,
    TK_COMMA
} tok_kind;

typedef struct {
    tok_kind kind;
    const char *ptr;
    size_t len;
    uint32_t num;
} tok;

typedef struct {
    const char *src;
    size_t len;
    size_t pos;
    int has_pending;
    tok pending;
} parser;

static int is_digit(char c) { return c >= '0' && c <= '9'; }
static int is_ident0(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}
static int is_ident(char c) { return is_ident0(c) || is_digit(c); }

static void skip_ws(parser *p) {
    while (p->pos < p->len) {
        char c = p->src[p->pos];
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
            p->pos++;
            continue;
        }
        if (c == '#') {
            while (p->pos < p->len && p->src[p->pos] != '\n') p->pos++;
            continue;
        }
        if (c == '/' && p->pos + 1 < p->len && p->src[p->pos + 1] == '/') {
            while (p->pos < p->len && p->src[p->pos] != '\n') p->pos++;
            continue;
        }
        return;
    }
}

static kati_status next_tok(parser *p, tok *t) {
    if (p->has_pending) {
        *t = p->pending;
        p->has_pending = 0;
        return KATI_OK;
    }
    skip_ws(p);
    if (p->pos >= p->len) {
        t->kind = TK_EOF;
        t->ptr = p->src + p->pos;
        t->len = 0;
        t->num = 0;
        return KATI_OK;
    }
    const char *s = p->src;
    size_t i = p->pos;
    char c = s[i];
    t->num = 0;
    t->ptr = s + i;
    switch (c) {
        case '@':
            t->kind = TK_AT;
            t->len = 1;
            p->pos = i + 1;
            return KATI_OK;
        case '{':
            t->kind = TK_LBRACE;
            t->len = 1;
            p->pos = i + 1;
            return KATI_OK;
        case '}':
            t->kind = TK_RBRACE;
            t->len = 1;
            p->pos = i + 1;
            return KATI_OK;
        case '[':
            t->kind = TK_LBRACKET;
            t->len = 1;
            p->pos = i + 1;
            return KATI_OK;
        case ']':
            t->kind = TK_RBRACKET;
            t->len = 1;
            p->pos = i + 1;
            return KATI_OK;
        case '(':
            t->kind = TK_LPAREN;
            t->len = 1;
            p->pos = i + 1;
            return KATI_OK;
        case ')':
            t->kind = TK_RPAREN;
            t->len = 1;
            p->pos = i + 1;
            return KATI_OK;
        case '<':
            t->kind = TK_LANGLE;
            t->len = 1;
            p->pos = i + 1;
            return KATI_OK;
        case '>':
            t->kind = TK_RANGLE;
            t->len = 1;
            p->pos = i + 1;
            return KATI_OK;
        case ':':
            t->kind = TK_COLON;
            t->len = 1;
            p->pos = i + 1;
            return KATI_OK;
        case '=':
            t->kind = TK_EQUAL;
            t->len = 1;
            p->pos = i + 1;
            return KATI_OK;
        case ',':
            t->kind = TK_COMMA;
            t->len = 1;
            p->pos = i + 1;
            return KATI_OK;
        case '"': {
            i++;
            size_t start = i;
            while (i < p->len && s[i] != '"') i++;
            if (i >= p->len) return KATI_TRUNCATED;
            t->kind = TK_STRING;
            t->ptr = s + start;
            t->len = i - start;
            p->pos = i + 1;
            return KATI_OK;
        }
        default:
            break;
    }
    if (is_digit(c)) {
        size_t start = i;
        if (c == '0' && i + 1 < p->len && (s[i + 1] == 'x' || s[i + 1] == 'X' || s[i + 1] == 'o' || s[i + 1] == 'b')) {
            i += 2;
            while (i < p->len) {
                char d = s[i];
                int ok = 0;
                if (s[start + 1] == 'x' || s[start + 1] == 'X')
                    ok = is_digit(d) || (d >= 'a' && d <= 'f') || (d >= 'A' && d <= 'F');
                else if (s[start + 1] == 'o')
                    ok = d >= '0' && d <= '7';
                else
                    ok = d == '0' || d == '1';
                if (!ok) break;
                i++;
            }
        } else {
            while (i < p->len && is_digit(s[i])) i++;
        }
        t->kind = TK_NUMBER;
        t->ptr = s + start;
        t->len = i - start;
        uint32_t v = 0;
        for (size_t k = start; k < i; k++) {
            if (s[k] < '0' || s[k] > '9') {
                v = 0;
                break;
            }
            v = v * 10u + (uint32_t)(s[k] - '0');
        }
        t->num = v;
        p->pos = i;
        return KATI_OK;
    }
    if (is_ident0(c)) {
        size_t start = i;
        i++;
        while (i < p->len && is_ident(s[i])) i++;
        t->kind = TK_IDENT;
        t->ptr = s + start;
        t->len = i - start;
        p->pos = i;
        return KATI_OK;
    }
    return KATI_INVALID_TOKEN;
}

static kati_status expect(parser *p, tok_kind kind) {
    tok t;
    kati_status st = next_tok(p, &t);
    if (st) return st;
    return t.kind == kind ? KATI_OK : KATI_EXPECTED;
}

static int prim_of(const char *s, size_t n, kati_prim *out) {
    if (eq(s, n, "i8")) {
        *out = KATI_I8;
        return 1;
    }
    if (eq(s, n, "i16")) {
        *out = KATI_I16;
        return 1;
    }
    if (eq(s, n, "i32")) {
        *out = KATI_I32;
        return 1;
    }
    if (eq(s, n, "i64")) {
        *out = KATI_I64;
        return 1;
    }
    if (eq(s, n, "u8")) {
        *out = KATI_U8;
        return 1;
    }
    if (eq(s, n, "u16")) {
        *out = KATI_U16;
        return 1;
    }
    if (eq(s, n, "u32")) {
        *out = KATI_U32;
        return 1;
    }
    if (eq(s, n, "u64")) {
        *out = KATI_U64;
        return 1;
    }
    if (eq(s, n, "f32")) {
        *out = KATI_F32;
        return 1;
    }
    if (eq(s, n, "f64")) {
        *out = KATI_F64;
        return 1;
    }
    if (eq(s, n, "bool")) {
        *out = KATI_BOOL;
        return 1;
    }
    if (eq(s, n, "char")) {
        *out = KATI_CHAR;
        return 1;
    }
    if (eq(s, n, "string")) {
        *out = KATI_STRING;
        return 1;
    }
    if (eq(s, n, "bytes")) {
        *out = KATI_BYTES;
        return 1;
    }
    if (eq(s, n, "rwx")) {
        *out = KATI_RWX;
        return 1;
    }
    if (eq(s, n, "timestamp")) {
        *out = KATI_TIMESTAMP;
        return 1;
    }
    if (eq(s, n, "duration")) {
        *out = KATI_DURATION;
        return 1;
    }
    if (eq(s, n, "uuid")) {
        *out = KATI_UUID;
        return 1;
    }
    if (eq(s, n, "fn")) {
        *out = KATI_FN;
        return 1;
    }
    return 0;
}

static kati_status parse_type(parser *p, kati_type *ty);

static kati_status parse_type_name(parser *p, kati_type *ty, tok ident) {
    kati_prim pr;
    if (prim_of(ident.ptr, ident.len, &pr)) {
        ty->kind = KATI_TY_PRIM;
        ty->prim = pr;
        ty->named[0] = 0;
        return KATI_OK;
    }
    if (eq(ident.ptr, ident.len, "array")) {
        tok open;
        kati_status st = next_tok(p, &open);
        if (st) return st;
        if (open.kind != TK_LBRACKET && open.kind != TK_LANGLE) return KATI_EXPECTED;
        tok inner;
        st = next_tok(p, &inner);
        if (st) return st;
        if (inner.kind != TK_IDENT) return KATI_EXPECTED;
        kati_prim ip;
        if (!prim_of(inner.ptr, inner.len, &ip)) return KATI_UNSUPPORTED_TYPE;
        tok close;
        st = next_tok(p, &close);
        if (st) return st;
        if (close.kind != TK_RBRACKET && close.kind != TK_RANGLE) return KATI_EXPECTED;
        ty->kind = KATI_TY_ARRAY;
        ty->inner = ip;
        ty->named[0] = 0;
        return KATI_OK;
    }
    if (eq(ident.ptr, ident.len, "map")) {
        tok open;
        kati_status st = next_tok(p, &open);
        if (st) return st;
        if (open.kind != TK_LBRACKET && open.kind != TK_LANGLE) return KATI_EXPECTED;
        tok k, comma, v, close;
        st = next_tok(p, &k);
        if (st) return st;
        st = next_tok(p, &comma);
        if (st) return st;
        st = next_tok(p, &v);
        if (st) return st;
        st = next_tok(p, &close);
        if (st) return st;
        if (k.kind != TK_IDENT || comma.kind != TK_COMMA || v.kind != TK_IDENT) return KATI_EXPECTED;
        if (close.kind != TK_RBRACKET && close.kind != TK_RANGLE) return KATI_EXPECTED;
        kati_prim kp, vp;
        if (!prim_of(k.ptr, k.len, &kp) || !prim_of(v.ptr, v.len, &vp)) return KATI_UNSUPPORTED_TYPE;
        ty->kind = KATI_TY_MAP;
        ty->key = kp;
        ty->value = vp;
        ty->named[0] = 0;
        return KATI_OK;
    }
    ty->kind = KATI_TY_NAMED;
    copy_name(ty->named, ident.ptr, ident.len);
    return KATI_OK;
}

static kati_status parse_type(parser *p, kati_type *ty) {
    tok t;
    kati_status st = next_tok(p, &t);
    if (st) return st;
    if (t.kind == TK_LBRACKET) {
        tok inner;
        st = next_tok(p, &inner);
        if (st) return st;
        if (inner.kind != TK_IDENT) return KATI_EXPECTED;
        kati_prim ip;
        if (!prim_of(inner.ptr, inner.len, &ip)) return KATI_UNSUPPORTED_TYPE;
        st = expect(p, TK_RBRACKET);
        if (st) return st;
        ty->kind = KATI_TY_ARRAY;
        ty->inner = ip;
        ty->named[0] = 0;
        return KATI_OK;
    }
    if (t.kind != TK_IDENT) return KATI_EXPECTED;
    return parse_type_name(p, ty, t);
}

static kati_status skip_paren(parser *p) {
    int depth = 1;
    if (expect(p, TK_LPAREN)) return KATI_EXPECTED;
    while (depth && p->pos < p->len) {
        tok t;
        kati_status st = next_tok(p, &t);
        if (st) return st;
        if (t.kind == TK_LPAREN) depth++;
        if (t.kind == TK_RPAREN) depth--;
        if (t.kind == TK_EOF) return KATI_EXPECTED;
    }
    return KATI_OK;
}

static kati_status skip_literal(parser *p) {
    tok t;
    kati_status st = next_tok(p, &t);
    if (st) return st;
    if (t.kind == TK_IDENT && eq(t.ptr, t.len, "rwx")) {
        tok colon;
        st = next_tok(p, &colon);
        if (st) return st;
        if (colon.kind == TK_COLON) return next_tok(p, &t);
        p->pending = colon;
        p->has_pending = 1;
        return KATI_OK;
    }
    return KATI_OK;
}

static uint64_t fnv_byte(uint64_t h, uint8_t b) {
    return (h ^ (uint64_t)b) * 0x100000001b3ull;
}

static uint64_t fnv_bytes(uint64_t h, const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) h = fnv_byte(h, (uint8_t)s[i]);
    return h;
}

static uint64_t fnv_cstr(uint64_t h, const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    return fnv_bytes(h, s, n);
}

static uint64_t hash_type(uint64_t h, const kati_type *ty) {
    switch (ty->kind) {
        case KATI_TY_PRIM:
            h = fnv_byte(h, 0);
            h = fnv_byte(h, (uint8_t)ty->prim);
            return h;
        case KATI_TY_ARRAY:
            h = fnv_byte(h, 1);
            h = fnv_byte(h, (uint8_t)ty->inner);
            return h;
        case KATI_TY_MAP:
            h = fnv_byte(h, 2);
            h = fnv_byte(h, (uint8_t)ty->key);
            h = fnv_byte(h, (uint8_t)ty->value);
            return h;
        case KATI_TY_NAMED:
            h = fnv_byte(h, 3);
            h = fnv_cstr(h, ty->named);
            return h;
        default:
            return h;
    }
}

uint64_t kati_hash_schema(const kati_schema *s) {
    uint64_t h = 0xcbf29ce484222325ull;
    static const char prefix[] = "kati-schema-v1";
    h = fnv_bytes(h, prefix, sizeof(prefix)); /* includes NUL */
    h = fnv_cstr(h, s->name);
    h = fnv_byte(h, s->strict ? 1 : 0);
    for (size_t i = 0; i < s->field_count; i++) {
        const kati_field *f = &s->fields[i];
        h = fnv_byte(h, 0xff);
        h = fnv_cstr(h, f->name);
        h = hash_type(h, &f->type);
        uint32_t id = f->field_id;
        h = fnv_byte(h, (uint8_t)id);
        h = fnv_byte(h, (uint8_t)(id >> 8));
        h = fnv_byte(h, (uint8_t)(id >> 16));
        h = fnv_byte(h, (uint8_t)(id >> 24));
        h = fnv_byte(h, f->required ? 1 : 0);
    }
    return h;
}

static kati_status assign_ids(kati_schema *s) {
    unsigned used[KATI_MAX_FIELDS];
    for (int i = 0; i < KATI_MAX_FIELDS; i++) used[i] = 0;
    for (size_t i = 0; i < s->field_count; i++) {
        uint32_t id = s->fields[i].field_id ? s->fields[i].field_id : (uint32_t)(i + 1);
        if (id == 0 || id > KATI_MAX_FIELDS) return KATI_INVALID_FIELD_ID;
        if (used[id - 1]) return KATI_DUPLICATE;
        used[id - 1] = 1;
        s->fields[i].field_id = id;
    }
    return KATI_OK;
}

kati_status kati_put_u16le(kati_sink *s, uint16_t v) {
    kati_status st = kati_put_u8(s, (uint8_t)(v & 0xffu));
    if (st) return st;
    return kati_put_u8(s, (uint8_t)(v >> 8));
}

kati_status kati_put_u32le(kati_sink *s, uint32_t v) {
    for (int i = 0; i < 4; i++) {
        kati_status st = kati_put_u8(s, (uint8_t)(v & 0xffu));
        if (st) return st;
        v >>= 8;
    }
    return KATI_OK;
}

kati_status kati_take_u16le(kati_cursor *c, uint16_t *out) {
    uint8_t b0, b1;
    kati_status st = kati_take_u8(c, &b0);
    if (st) return st;
    st = kati_take_u8(c, &b1);
    if (st) return st;
    *out = (uint16_t)b0 | ((uint16_t)b1 << 8);
    return KATI_OK;
}

kati_status kati_take_u32le(kati_cursor *c, uint32_t *out) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        uint8_t b;
        kati_status st = kati_take_u8(c, &b);
        if (st) return st;
        v |= ((uint32_t)b) << (8 * i);
    }
    *out = v;
    return KATI_OK;
}

kati_status kati_write_mux(kati_sink *s, uint16_t chid, uint8_t flags, uint32_t seq, const uint8_t *data, size_t n) {
    if (flags & 0xe0u) return KATI_INVALID_FLAGS;
    kati_status st = kati_put_u16le(s, chid);
    if (st) return st;
    st = kati_put_u8(s, flags);
    if (st) return st;
    st = kati_put_u32le(s, seq);
    if (st) return st;
    return kati_write_len(s, data, n);
}

kati_status kati_read_mux(kati_cursor *c, kati_mux *out) {
    kati_status st = kati_take_u16le(c, &out->chid);
    if (st) return st;
    st = kati_take_u8(c, &out->flags);
    if (st) return st;
    if (out->flags & 0xe0u) return KATI_INVALID_FLAGS;
    st = kati_take_u32le(c, &out->seq);
    if (st) return st;
    return kati_read_len(c, &out->data, &out->len);
}

kati_status kati_parse_schema(const char *src, kati_schema *out) {
    parser p;
    size_t n = 0;
    while (src[n]) n++;
    p.src = src;
    p.len = n;
    p.pos = 0;
    p.has_pending = 0;
    out->name[0] = 0;
    out->strict = 0;
    out->field_count = 0;
    out->schema_hash = 0;

    for (;;) {
        tok t;
        kati_status st = next_tok(&p, &t);
        if (st) return st;
        if (t.kind == TK_EOF) break;
        if (t.kind == TK_AT) {
            tok name;
            st = next_tok(&p, &name);
            if (st) return st;
            if (name.kind != TK_IDENT) return KATI_EXPECTED;
            if (eq(name.ptr, name.len, "strict")) {
                out->strict = 1;
                continue;
            }
            if (eq(name.ptr, name.len, "perms")) {
                st = skip_paren(&p);
                if (st) return st;
                continue;
            }
            return KATI_INVALID_TOKEN;
        }
        if (t.kind != TK_IDENT) return KATI_EXPECTED;
        if (eq(t.ptr, t.len, "enum")) {
            /* Skip enum body; root records follow. */
            tok ename, brace;
            st = next_tok(&p, &ename);
            if (st) return st;
            st = next_tok(&p, &brace);
            if (st) return st;
            int depth = 1;
            while (depth) {
                tok x;
                st = next_tok(&p, &x);
                if (st) return st;
                if (x.kind == TK_LBRACE) depth++;
                if (x.kind == TK_RBRACE) depth--;
                if (x.kind == TK_EOF) return KATI_EXPECTED;
            }
            continue;
        }
        if (!(eq(t.ptr, t.len, "config") || eq(t.ptr, t.len, "struct") || eq(t.ptr, t.len, "buffer") ||
              eq(t.ptr, t.len, "union")))
            return KATI_EXPECTED;
        tok name;
        st = next_tok(&p, &name);
        if (st) return st;
        if (name.kind != TK_IDENT) return KATI_EXPECTED;
        copy_name(out->name, name.ptr, name.len);
        st = expect(&p, TK_LBRACE);
        if (st) return st;
        out->field_count = 0;
        for (;;) {
            tok f;
            st = next_tok(&p, &f);
            if (st) return st;
            if (f.kind == TK_RBRACE) break;
            if (f.kind != TK_IDENT) return KATI_EXPECTED;
            if (out->field_count == KATI_MAX_FIELDS) return KATI_OVERFLOW;
            for (size_t i = 0; i < out->field_count; i++) {
                size_t ln = 0;
                while (out->fields[i].name[ln]) ln++;
                if (eq(f.ptr, f.len, out->fields[i].name)) return KATI_DUPLICATE;
            }
            st = expect(&p, TK_COLON);
            if (st) return st;
            kati_field *field = &out->fields[out->field_count];
            copy_name(field->name, f.ptr, f.len);
            field->required = 0;
            field->max = 0;
            field->field_id = 0;
            field->perms = 0;
            st = parse_type(&p, &field->type);
            if (st) return st;
            for (;;) {
                tok a;
                st = next_tok(&p, &a);
                if (st) return st;
                if (a.kind == TK_AT) {
                    tok an;
                    st = next_tok(&p, &an);
                    if (st) return st;
                    if (an.kind != TK_IDENT) return KATI_EXPECTED;
                    if (eq(an.ptr, an.len, "required"))
                        field->required = 1;
                    else if (eq(an.ptr, an.len, "r"))
                        field->perms |= KATI_PERM_R;
                    else if (eq(an.ptr, an.len, "w"))
                        field->perms |= KATI_PERM_W;
                    else if (eq(an.ptr, an.len, "x"))
                        field->perms |= KATI_PERM_X;
                    else if (eq(an.ptr, an.len, "rw"))
                        field->perms = KATI_PERM_RW;
                    else if (eq(an.ptr, an.len, "rx"))
                        field->perms = KATI_PERM_RX;
                    else if (eq(an.ptr, an.len, "wx"))
                        field->perms = KATI_PERM_WX;
                    else if (eq(an.ptr, an.len, "rwx"))
                        field->perms = KATI_PERM_RWX;
                    else if (eq(an.ptr, an.len, "max") || eq(an.ptr, an.len, "id")) {
                        st = expect(&p, TK_LPAREN);
                        if (st) return st;
                        tok num;
                        st = next_tok(&p, &num);
                        if (st) return st;
                        if (num.kind != TK_NUMBER) return KATI_EXPECTED;
                        st = expect(&p, TK_RPAREN);
                        if (st) return st;
                        if (eq(an.ptr, an.len, "id"))
                            field->field_id = num.num;
                        else
                            field->max = num.num;
                    } else if (eq(an.ptr, an.len, "compress") || eq(an.ptr, an.len, "default")) {
                        st = skip_paren(&p);
                        if (st) return st;
                    } else
                        return KATI_INVALID_TOKEN;
                    continue;
                }
                if (a.kind == TK_EQUAL) {
                    st = skip_literal(&p);
                    if (st) return st;
                    continue;
                }
                if (a.kind == TK_COMMA) break;
                if (a.kind == TK_RBRACE) {
                    p.pending = a;
                    p.has_pending = 1;
                    break;
                }
                if (a.kind == TK_IDENT) {
                    p.pending = a;
                    p.has_pending = 1;
                    break;
                }
                return KATI_EXPECTED;
            }
            out->field_count++;
        }
        st = assign_ids(out);
        if (st) return st;
        out->schema_hash = kati_hash_schema(out);
        /* Keep the last config/buffer/union as root; structs before it are nested types. */
    }
    if (out->name[0] == 0) return KATI_EMPTY;
    return KATI_OK;
}

kati_status kati_payload(const uint8_t *data, size_t len, const uint8_t **out, size_t *n) {
    kati_header h;
    kati_status st = kati_decode_header(data, len, &h);
    if (st) return st;
    if (h.header_len > len) return KATI_TRUNCATED;
    if (h.payload_len > (uint64_t)(len - h.header_len)) return KATI_TRUNCATED;
    *out = data + h.header_len;
    *n = (size_t)h.payload_len;
    return KATI_OK;
}

int kati_hash_match(const kati_header *h, uint64_t schema_hash) {
    return h && h->schema_hash == schema_hash;
}

kati_status kati_write_packed(kati_sink *s, uint64_t count, const uint8_t *items, size_t n) {
    uint64_t v = count;
    size_t leb = 1;
    while (v >= 0x80) {
        v >>= 7;
        leb++;
    }
    kati_status st = kati_put_varint(s, leb + n);
    if (st) return st;
    st = kati_put_varint(s, count);
    if (st) return st;
    return kati_put_bytes(s, items, n);
}

kati_status kati_read_packed(kati_cursor *c, uint64_t *count, const uint8_t **items, size_t *n) {
    const uint8_t *blob;
    size_t len = 0;
    kati_status st = kati_read_len(c, &blob, &len);
    if (st) return st;
    kati_cursor inner;
    kati_cursor_init(&inner, blob, len);
    st = kati_take_varint(&inner, count);
    if (st) return st;
    *items = blob + inner.pos;
    *n = len - inner.pos;
    return KATI_OK;
}

uint32_t kati_crc32c(const uint8_t *data, size_t n) {
    uint32_t crc = 0xffffffffu;
    size_t i;
    for (i = 0; i < n; i++) {
        crc ^= data[i];
        int b;
        for (b = 0; b < 8; b++) {
            crc = (crc & 1u) ? (crc >> 1) ^ 0x82F63B78u : (crc >> 1);
        }
    }
    return crc ^ 0xffffffffu;
}

static int name_eq(const char *a, const char *b) {
    size_t i = 0;
    while (a[i] && b[i]) {
        if (a[i] != b[i]) return 0;
        i++;
    }
    return a[i] == 0 && b[i] == 0;
}

const kati_field *kati_field_by_id(const kati_schema *s, uint32_t id) {
    size_t i;
    if (!s) return 0;
    for (i = 0; i < s->field_count; i++) {
        if (s->fields[i].field_id == id) return &s->fields[i];
    }
    return 0;
}

const kati_field *kati_field_by_name(const kati_schema *s, const char *name) {
    size_t i;
    if (!s || !name) return 0;
    for (i = 0; i < s->field_count; i++) {
        if (name_eq(s->fields[i].name, name)) return &s->fields[i];
    }
    return 0;
}

kati_status kati_get(const kati_schema *s, const uint8_t *payload, size_t n, const char *path,
                     kati_field_header *fh, const uint8_t **raw, size_t *raw_n) {
    const char *name;
    size_t i;
    kati_cursor c;
    if (!s || !payload || !path || !fh || !raw || !raw_n) return KATI_EXPECTED;
    name = path;
    /* Allow Schema.field as well as field. */
    {
        size_t nlen = 0;
        while (s->name[nlen]) nlen++;
        if (nlen && path[nlen] == '.') {
            int match = 1;
            for (i = 0; i < nlen; i++) {
                if (path[i] != s->name[i]) {
                    match = 0;
                    break;
                }
            }
            if (match) name = path + nlen + 1;
        }
    }
    for (i = 0; name[i]; i++) {
        if (name[i] == '.') return KATI_UNSUPPORTED_TYPE;
    }
    kati_cursor_init(&c, payload, n);
    while (c.pos < c.len) {
        kati_field_header hdr;
        size_t vstart;
        kati_status st = kati_read_field_header(&c, &hdr);
        if (st) return st;
        vstart = c.pos;
        st = kati_skip_value(&c, hdr.wire_type);
        if (st) return st;
        {
            const kati_field *f = kati_field_by_id(s, hdr.field_id);
            if (f && name_eq(f->name, name)) {
                if (!kati_can(f->perms, KATI_PERM_R)) return KATI_PERM_DENIED;
                *fh = hdr;
                *raw = payload + vstart;
                *raw_n = c.pos - vstart;
                return KATI_OK;
            }
        }
    }
    return KATI_NOT_FOUND;
}

