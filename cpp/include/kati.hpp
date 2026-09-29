#pragma once
#include "kati.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>

namespace kati {

enum class status : int {
    ok = KATI_OK,
    invalid_magic = KATI_INVALID_MAGIC,
    unsupported_version = KATI_UNSUPPORTED_VERSION,
    invalid_flags = KATI_INVALID_FLAGS,
    truncated = KATI_TRUNCATED,
    overflow = KATI_OVERFLOW,
    invalid_varint = KATI_INVALID_VARINT,
    invalid_field_id = KATI_INVALID_FIELD_ID,
    invalid_wire = KATI_INVALID_WIRE,
    type_mismatch = KATI_TYPE_MISMATCH,
    perm_denied = KATI_PERM_DENIED,
    invalid_token = KATI_INVALID_TOKEN,
    expected = KATI_EXPECTED,
    duplicate = KATI_DUPLICATE,
    unsupported_type = KATI_UNSUPPORTED_TYPE,
    empty = KATI_EMPTY,
    not_found = KATI_NOT_FOUND,
};

inline const char *to_string(status st) {
    return kati_status_str(static_cast<kati_status>(st));
}

template <class T>
struct result {
    status st{status::ok};
    T value{};
    explicit operator bool() const { return st == status::ok; }
    T &operator*() { return value; }
    const T &operator*() const { return value; }
};

enum class access : std::uint8_t {
    r = KATI_PERM_R,
    w = KATI_PERM_W,
    x = KATI_PERM_X,
    rw = KATI_PERM_RW,
    rx = KATI_PERM_RX,
    rwx = KATI_PERM_RWX,
};

enum class wire : std::uint8_t {
    varint = KATI_WIRE_VARINT,
    fixed64 = KATI_WIRE_FIXED64,
    bytes = KATI_WIRE_BYTES,
    fixed32 = KATI_WIRE_FIXED32,
};

struct flags {
    static constexpr std::uint8_t none = 0;
    static constexpr std::uint8_t compressed = KATI_COMPRESSED;
    static constexpr std::uint8_t encrypted = KATI_ENCRYPTED;
    static constexpr std::uint8_t has_schema = KATI_HAS_SCHEMA;
    static constexpr std::uint8_t has_mux = KATI_HAS_MUX;
    static constexpr std::uint8_t big_endian = KATI_BIG_ENDIAN;
};

struct mux_bits {
    static constexpr std::uint8_t fin = KATI_MUX_FIN;
    static constexpr std::uint8_t syn = KATI_MUX_SYN;
    static constexpr std::uint8_t rst = KATI_MUX_RST;
    static constexpr std::uint8_t ack = KATI_MUX_ACK;
    static constexpr std::uint8_t compressed = KATI_MUX_COMPRESSED;
};

struct header {
    std::uint8_t flag_bits{};
    std::uint64_t schema_hash{};
    std::uint64_t payload_len{};
    std::size_t header_len{};
};

struct field_header {
    std::uint32_t field_id{};
    wire type{wire::varint};
};

struct mux_frame {
    std::uint16_t chid{};
    std::uint8_t flag_bits{};
    std::uint32_t seq{};
    std::span<const std::byte> data{};
};

class sink {
    kati_sink raw_{};

public:
    sink(std::span<std::byte> out) {
        kati_sink_init(&raw_, reinterpret_cast<std::uint8_t *>(out.data()), out.size());
    }
    std::size_t pos() const { return raw_.pos; }
    status u8(std::uint8_t v) { return static_cast<status>(kati_put_u8(&raw_, v)); }
    status u16le(std::uint16_t v) { return static_cast<status>(kati_put_u16le(&raw_, v)); }
    status u32le(std::uint32_t v) { return static_cast<status>(kati_put_u32le(&raw_, v)); }
    status u64le(std::uint64_t v) { return static_cast<status>(kati_put_u64le(&raw_, v)); }
    status varint(std::uint64_t v) { return static_cast<status>(kati_put_varint(&raw_, v)); }
    status bytes(std::span<const std::byte> src) {
        return static_cast<status>(kati_put_bytes(&raw_, reinterpret_cast<const std::uint8_t *>(src.data()), src.size()));
    }
    status field(std::uint32_t id, wire w) {
        return static_cast<status>(kati_write_field_header(&raw_, id, static_cast<std::uint8_t>(w)));
    }
    status signed_(std::int64_t v) { return static_cast<status>(kati_write_signed(&raw_, v)); }
    status unsigned_(std::uint64_t v) { return static_cast<status>(kati_write_unsigned(&raw_, v)); }
    status len(std::span<const std::byte> src) {
        return static_cast<status>(kati_write_len(&raw_, reinterpret_cast<const std::uint8_t *>(src.data()), src.size()));
    }
    status mux(std::uint16_t chid, std::uint8_t bits, std::uint32_t seq, std::span<const std::byte> data) {
        return static_cast<status>(kati_write_mux(&raw_, chid, bits, seq,
                                                  reinterpret_cast<const std::uint8_t *>(data.data()), data.size()));
    }
    kati_sink *raw() { return &raw_; }
};

class cursor {
    kati_cursor raw_{};

public:
    cursor(std::span<const std::byte> in) {
        kati_cursor_init(&raw_, reinterpret_cast<const std::uint8_t *>(in.data()), in.size());
    }
    std::size_t pos() const { return raw_.pos; }
    bool done() const { return raw_.pos >= raw_.len; }

    result<std::uint8_t> u8() {
        result<std::uint8_t> r;
        std::uint8_t v{};
        r.st = static_cast<status>(kati_take_u8(&raw_, &v));
        r.value = v;
        return r;
    }
    result<field_header> field() {
        kati_field_header fh{};
        result<field_header> r;
        r.st = static_cast<status>(kati_read_field_header(&raw_, &fh));
        if (r) r.value = field_header{fh.field_id, static_cast<wire>(fh.wire_type)};
        return r;
    }
    result<std::int64_t> signed_() {
        result<std::int64_t> r;
        r.st = static_cast<status>(kati_read_signed(&raw_, &r.value));
        return r;
    }
    result<std::uint64_t> unsigned_() {
        result<std::uint64_t> r;
        r.st = static_cast<status>(kati_read_unsigned(&raw_, &r.value));
        return r;
    }
    result<std::span<const std::byte>> len() {
        const std::uint8_t *p{};
        std::size_t n{};
        result<std::span<const std::byte>> r;
        r.st = static_cast<status>(kati_read_len(&raw_, &p, &n));
        if (r) r.value = std::span<const std::byte>(reinterpret_cast<const std::byte *>(p), n);
        return r;
    }
    status skip(wire w) { return static_cast<status>(kati_skip_value(&raw_, static_cast<std::uint8_t>(w))); }
    result<mux_frame> mux() {
        kati_mux m{};
        result<mux_frame> r;
        r.st = static_cast<status>(kati_read_mux(&raw_, &m));
        if (r) {
            r.value = mux_frame{m.chid, m.flags, m.seq,
                                std::span<const std::byte>(reinterpret_cast<const std::byte *>(m.data), m.len)};
        }
        return r;
    }
};

inline result<header> decode_header(std::span<const std::byte> bytes) {
    kati_header raw{};
    const auto st = kati_decode_header(reinterpret_cast<const std::uint8_t *>(bytes.data()), bytes.size(), &raw);
    result<header> out;
    out.st = static_cast<status>(st);
    if (st == KATI_OK) {
        out.value = header{raw.flags, raw.schema_hash, raw.payload_len, raw.header_len};
    }
    return out;
}

inline result<std::size_t> encode_header(std::span<std::byte> out, std::uint8_t flag_bits, std::uint64_t hash,
                                        std::uint64_t payload_len) {
    kati_sink raw;
    kati_sink_init(&raw, reinterpret_cast<std::uint8_t *>(out.data()), out.size());
    const auto st = kati_encode_header(&raw, flag_bits, hash, payload_len);
    result<std::size_t> r;
    r.st = static_cast<status>(st);
    r.value = raw.pos;
    return r;
}

class view {
    std::span<const std::byte> bytes_{};
    header hdr_{};

public:
    view() = default;
    explicit view(std::span<const std::byte> b, header h) : bytes_(b), hdr_(h) {}
    static result<view> open(std::span<const std::byte> bytes) {
        auto h = decode_header(bytes);
        result<view> r;
        r.st = h.st;
        if (h) r.value = view{bytes, *h};
        return r;
    }

    const header &hdr() const { return hdr_; }

    std::span<const std::byte> payload() const {
        return bytes_.subspan(hdr_.header_len, static_cast<std::size_t>(hdr_.payload_len));
    }

    cursor fields() const { return cursor{payload()}; }

    bool can(access want) const { return kati_can(KATI_PERM_RWX, static_cast<std::uint8_t>(want)) != 0; }
};

inline bool can(std::uint8_t field_perms, access want) {
    return kati_can(field_perms, static_cast<std::uint8_t>(want)) != 0;
}

inline bool hash_match(const header &h, std::uint64_t schema_hash) {
    kati_header raw{h.flag_bits, h.schema_hash, h.payload_len, h.header_len};
    return kati_hash_match(&raw, schema_hash) != 0;
}

inline result<std::span<const std::byte>> payload_of(std::span<const std::byte> bytes) {
    const std::uint8_t *p{};
    std::size_t n{};
    result<std::span<const std::byte>> r;
    r.st = static_cast<status>(kati_payload(reinterpret_cast<const std::uint8_t *>(bytes.data()), bytes.size(), &p, &n));
    if (r) r.value = std::span<const std::byte>(reinterpret_cast<const std::byte *>(p), n);
    return r;
}

inline result<kati_schema> parse_schema(std::string_view src) {
    result<kati_schema> r;
    if (src.size() + 1 > 4096) {
        r.st = status::overflow;
        return r;
    }
    char buf[4096];
    for (std::size_t i = 0; i < src.size(); i++) buf[i] = src[i];
    buf[src.size()] = 0;
    r.st = static_cast<status>(kati_parse_schema(buf, &r.value));
    return r;
}

inline uint32_t crc32c(std::span<const std::byte> bytes) {
    return kati_crc32c(reinterpret_cast<const std::uint8_t *>(bytes.data()), bytes.size());
}

struct field_view {
    field_header hdr{};
    std::span<const std::byte> raw{};
};

inline result<field_view> get(const kati_schema &schema, std::span<const std::byte> payload, std::string_view path) {
    result<field_view> r;
    if (path.size() + 1 > 256) {
        r.st = status::overflow;
        return r;
    }
    char name[256];
    for (std::size_t i = 0; i < path.size(); i++) name[i] = path[i];
    name[path.size()] = 0;
    kati_field_header fh{};
    const std::uint8_t *raw = nullptr;
    std::size_t n = 0;
    r.st = static_cast<status>(kati_get(&schema, reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size(),
                                        name, &fh, &raw, &n));
    if (r) {
        r.value.hdr = field_header{fh.field_id, static_cast<wire>(fh.wire_type)};
        r.value.raw = std::span<const std::byte>(reinterpret_cast<const std::byte *>(raw), n);
    }
    return r;
}

} // namespace kati
