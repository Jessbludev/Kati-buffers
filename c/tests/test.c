#include "kati.h"

#include <stdio.h>
#include <string.h>

static int fails;

static void expect(int cond, const char *msg) {
    if (!cond) {
        fprintf(stderr, "FAIL %s\n", msg);
        fails++;
    }
}

static const char *APPCONFIG =
    "@strict\n"
    "config AppConfig {\n"
    "    name: string @required\n"
    "    version: u16\n"
    "    debug: bool = false\n"
    "    endpoints: array[string] @max(32)\n"
    "    limits: map[string,u32]\n"
    "    payload: bytes @compress(zstd)\n"
    "}\n";

int main(void) {
    uint8_t buf[64];
    kati_sink s;
    kati_sink_init(&s, buf, sizeof buf);
    expect(kati_encode_header(&s, KATI_HAS_SCHEMA, 0x8af3c1d2ull, 1234) == KATI_OK, "encode header");
    kati_header h;
    expect(kati_decode_header(buf, s.pos, &h) == KATI_OK, "decode header");
    expect(h.flags == KATI_HAS_SCHEMA, "flag has-schema");
    expect(h.schema_hash == 0x8af3c1d2ull, "hash");
    expect(h.payload_len == 1234, "payload len");

    buf[0] = 'X';
    expect(kati_decode_header(buf, s.pos, &h) == KATI_INVALID_MAGIC, "bad magic");

    kati_sink_init(&s, buf, sizeof buf);
    kati_encode_header(&s, KATI_HAS_SCHEMA, 1, 1);
    buf[4] |= 0xe0;
    expect(kati_decode_header(buf, s.pos, &h) == KATI_INVALID_FLAGS, "reserved flags");

    const uint64_t values[] = {0, 1, 127, 128, 255, 16384, ~0ull};
    for (size_t i = 0; i < sizeof values / sizeof values[0]; i++) {
        kati_sink_init(&s, buf, sizeof buf);
        expect(kati_put_varint(&s, values[i]) == KATI_OK, "varint write");
        kati_cursor c;
        kati_cursor_init(&c, buf, s.pos);
        uint64_t got = 0;
        expect(kati_take_varint(&c, &got) == KATI_OK, "varint read");
        expect(got == values[i], "varint roundtrip");
    }

    const int64_t signed_v[] = {-1000, -1, 0, 1, 1000};
    for (size_t i = 0; i < sizeof signed_v / sizeof signed_v[0]; i++) {
        kati_sink_init(&s, buf, sizeof buf);
        expect(kati_write_signed(&s, signed_v[i]) == KATI_OK, "signed write");
        kati_cursor c;
        kati_cursor_init(&c, buf, s.pos);
        int64_t got = 0;
        expect(kati_read_signed(&c, &got) == KATI_OK, "signed read");
        expect(got == signed_v[i], "zigzag roundtrip");
    }

    kati_sink_init(&s, buf, sizeof buf);
    expect(kati_write_field_header(&s, 7, KATI_WIRE_BYTES) == KATI_OK, "field hdr");
    kati_write_len(&s, (const uint8_t *)"ok", 2);
    kati_cursor c;
    kati_cursor_init(&c, buf, s.pos);
    kati_field_header fh;
    expect(kati_read_field_header(&c, &fh) == KATI_OK, "read field hdr");
    expect(fh.field_id == 7 && fh.wire_type == KATI_WIRE_BYTES, "field hdr values");
    const uint8_t *bytes;
    size_t n = 0;
    expect(kati_read_len(&c, &bytes, &n) == KATI_OK && n == 2 && bytes[0] == 'o', "bytes");

    kati_schema schema;
    kati_status st = kati_parse_schema(APPCONFIG, &schema);
    expect(st == KATI_OK, "parse AppConfig");
    expect(strcmp(schema.name, "AppConfig") == 0, "name");
    expect(schema.strict == 1, "strict");
    expect(schema.field_count == 6, "six fields");
    expect(schema.fields[0].field_id == 1 && schema.fields[0].required == 1, "name field");
    expect(schema.fields[3].max == 32, "@max");
    expect(schema.schema_hash == 0x3d742323fdeca80bull, "FNV-1a matches Zig/TS host");

    st = kati_parse_schema("config X { a: u8 @id(7) b: u8 @id(7) }", &schema);
    expect(st == KATI_DUPLICATE, "duplicate id");

    expect(kati_can(KATI_PERM_R, KATI_PERM_R) == 1, "can r");
    expect(kati_can(KATI_PERM_R, KATI_PERM_W) == 0, "cannot w");
    expect(kati_can(0, KATI_PERM_RWX) == 1, "unspecified is rwx");

    {
        const char *spec =
            "@strict\n"
            "config AppConfig {\n"
            "    name: string @required\n"
            "    version: u16\n"
            "    debug: bool = false\n"
            "    endpoints: [string] @max(32)\n"
            "    limits: map<string, u32>\n"
            "    payload: bytes @compress(zstd)\n"
            "}\n";
        kati_schema spec_schema;
        expect(kati_parse_schema(spec, &spec_schema) == KATI_OK, "parse spec spelling");
        expect(spec_schema.schema_hash == 0x3d742323fdeca80bull, "spec spelling hashes identically");
    }

    {
        uint8_t mbuf[64];
        kati_sink ms;
        kati_sink_init(&ms, mbuf, sizeof mbuf);
        expect(kati_write_mux(&ms, 7, KATI_MUX_SYN | KATI_MUX_ACK, 42, (const uint8_t *)"hi", 2) == KATI_OK, "mux write");
        kati_cursor mc;
        kati_cursor_init(&mc, mbuf, ms.pos);
        kati_mux frame;
        expect(kati_read_mux(&mc, &frame) == KATI_OK, "mux read");
        expect(frame.chid == 7 && frame.seq == 42 && frame.len == 2 && frame.data[0] == 'h', "mux values");
        expect((frame.flags & KATI_MUX_SYN) && (frame.flags & KATI_MUX_ACK), "mux flags");
    }

    {
        uint8_t over[2] = {0x80, 0x00};
        kati_cursor oc;
        kati_cursor_init(&oc, over, 2);
        uint64_t got = 0;
        expect(kati_take_varint(&oc, &got) == KATI_INVALID_VARINT, "overlong varint");
    }

    {
        uint8_t pbuf[32];
        kati_sink ps;
        kati_sink_init(&ps, pbuf, sizeof pbuf);
        const uint8_t items[] = {1, 2, 3};
        expect(kati_write_packed(&ps, 3, items, 3) == KATI_OK, "packed write");
        kati_cursor pc;
        kati_cursor_init(&pc, pbuf, ps.pos);
        uint64_t count = 0;
        const uint8_t *got_items = 0;
        size_t got_n = 0;
        expect(kati_read_packed(&pc, &count, &got_items, &got_n) == KATI_OK, "packed read");
        expect(count == 3 && got_n == 3 && got_items[0] == 1, "packed values");
    }

    {
        uint8_t hbuf[32];
        kati_sink hs;
        kati_sink_init(&hs, hbuf, sizeof hbuf);
        kati_encode_header(&hs, 0, 0x11, 3);
        hbuf[hs.pos] = 'a';
        hbuf[hs.pos + 1] = 'b';
        hbuf[hs.pos + 2] = 'c';
        const uint8_t *pay = 0;
        size_t pn = 0;
        expect(kati_payload(hbuf, hs.pos + 3, &pay, &pn) == KATI_OK && pn == 3 && pay[0] == 'a', "payload slice");
        kati_header hh;
        kati_decode_header(hbuf, hs.pos, &hh);
        expect(kati_hash_match(&hh, 0x11) == 1, "hash match");
        expect(kati_hash_match(&hh, 0x22) == 0, "hash mismatch");
    }

    expect(kati_crc32c((const uint8_t *)"123456789", 9) == 0xe3069283u, "crc32c vector");
    expect(kati_crc32c((const uint8_t *)"", 0) == 0, "crc32c empty");

    {
        kati_schema s;
        expect(kati_parse_schema("config X { name: string @required version: u16 }", &s) == KATI_OK, "get schema");
        uint8_t pbuf[32];
        kati_sink ps;
        kati_sink_init(&ps, pbuf, sizeof pbuf);
        kati_write_field_header(&ps, 1, KATI_WIRE_BYTES);
        kati_write_len(&ps, (const uint8_t *)"kati", 4);
        kati_write_field_header(&ps, 2, KATI_WIRE_VARINT);
        kati_write_unsigned(&ps, 7);
        kati_field_header fh;
        const uint8_t *raw = 0;
        size_t rn = 0;
        expect(kati_get(&s, pbuf, ps.pos, "name", &fh, &raw, &rn) == KATI_OK, "get name");
        expect(fh.field_id == 1 && rn > 0, "get name hdr");
        expect(kati_get(&s, pbuf, ps.pos, "X.version", &fh, &raw, &rn) == KATI_OK, "get X.version");
        expect(kati_field_by_name(&s, "version") && kati_field_by_name(&s, "version")->field_id == 2, "by name");
        expect(kati_get(&s, pbuf, ps.pos, "missing", &fh, &raw, &rn) == KATI_NOT_FOUND, "get missing");
    }

    if (fails) {
        fprintf(stderr, "%d failed\n", fails);
        return 1;
    }
    puts("ok");
    return 0;
}
