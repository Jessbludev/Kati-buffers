//! kati: zero-runtime .pbr core.
//! The core intentionally avoids allocators, OS APIs, threads and global state.
//! It is suitable for static linking, embedded targets and language bindings.
//! Zig 0.16.0: no primitive-shadowing methods; CLI uses `std.process.Init`.

const io = @import("io.zig");

pub const Error = io.Error || error{
    InvalidMagic,
    UnsupportedVersion,
    InvalidFlags,
    InvalidHeader,
    HashMismatch,
} || block.Error;

pub const MAGIC = "PBR\x01";
pub const VERSION: u8 = 1;
pub const LIB_VERSION = "0.7.0";
pub const schema = @import("schema.zig");
pub const value = @import("value.zig");
pub const mux = @import("mux.zig");
pub const pretty = @import("pretty.zig");
pub const rwx = @import("rwx.zig");
pub const crc = @import("crc.zig");
pub const block = @import("block.zig");
pub const record = @import("record.zig");
pub const path = @import("path.zig");
pub const wal = @import("wal.zig");

pub const Flags = packed struct(u8) {
    compressed: bool = false,
    encrypted: bool = false,
    has_schema: bool = false,
    has_mux: bool = false,
    big_endian: bool = false,
    reserved: u3 = 0,
};

pub const Header = struct {
    flags: Flags,
    schema_hash: u64,
    payload_len: u64,
    header_len: usize,
};

pub const Writer = io.Writer;
pub const Reader = io.Reader;

pub fn encodeHeader(out: []u8, flags: Flags, schema_hash: u64, payload_len: u64) Error!usize {
    var w = Writer.init(out);
    try w.bytes(MAGIC);
    try w.byte(@bitCast(flags));
    if (flags.big_endian) try w.u64be(schema_hash) else try w.u64le(schema_hash);
    try w.varint(payload_len);
    return w.pos;
}

pub fn decodeHeader(data: []const u8) Error!Header {
    var r = Reader.init(data);
    const magic = try r.bytes(4);
    if (!std_mem_eql(u8, magic, MAGIC)) return error.InvalidMagic;
    const version = magic[3];
    if (version != VERSION) return error.UnsupportedVersion;
    const flags = @as(Flags, @bitCast(try r.byte()));
    if (flags.reserved != 0) return error.InvalidFlags;
    const schema_hash = if (flags.big_endian) try r.u64be() else try r.u64le();
    const payload_len = try r.varint();
    return .{
        .flags = flags,
        .schema_hash = schema_hash,
        .payload_len = payload_len,
        .header_len = r.pos,
    };
}

pub fn payloadOf(data: []const u8, h: Header) Error![]const u8 {
    if (h.header_len > data.len) return error.InvalidHeader;
    const rest = data.len - h.header_len;
    if (h.payload_len > rest) return error.InvalidHeader;
    const n: usize = @intCast(h.payload_len);
    return data[h.header_len .. h.header_len + n];
}

pub fn encodeDocument(out: []u8, flags: Flags, schema_hash: u64, payload: []const u8) Error!usize {
    const n = try encodeHeader(out, flags, schema_hash, payload.len);
    if (n + payload.len > out.len) return error.Truncated;
    @memcpy(out[n .. n + payload.len], payload);
    return n + payload.len;
}

/// Wrap `payload` in 64 KiB none-blocks and set FLAGS.compressed.
pub fn encodeCompressedNone(out: []u8, schema_hash: u64, payload: []const u8) Error!usize {
    var framed: usize = 0;
    var i: usize = 0;
    while (i < payload.len) {
        const n = @min(block.SIZE, payload.len - i);
        framed += 1 + io.lebSize(n) + io.lebSize(n) + 4 + n;
        i += n;
    }
    const flags = Flags{ .compressed = true };
    const hn = try encodeHeader(out, flags, schema_hash, framed);
    var w = Writer.init(out[hn..]);
    try block.writeAllNone(&w, payload);
    if (w.pos != framed) return error.InvalidHeader;
    return hn + w.pos;
}

/// Header payload, transparently inflating `none` compressed blocks into `scratch`.
pub fn unwrap(data: []const u8, scratch: []u8) Error![]const u8 {
    const h = try decodeHeader(data);
    const payload = try payloadOf(data, h);
    if (!h.flags.compressed) return payload;
    var r = Reader.init(payload);
    const n = try block.readAllNone(&r, scratch);
    return scratch[0..n];
}

pub fn checkHash(h: Header, s: schema.Struct) bool {
    return h.schema_hash == s.schema_hash;
}

pub fn requireHash(h: Header, s: schema.Struct) Error!void {
    if (!checkHash(h, s)) return error.HashMismatch;
}

fn std_mem_eql(comptime T: type, a: []const T, b: []const T) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (x != y) return false;
    return true;
}

test "header roundtrip" {
    var buf: [32]u8 = undefined;
    const flags = Flags{ .has_schema = true };
    const n = try encodeHeader(&buf, flags, 0x8af3c1d2, 1234);
    const h = try decodeHeader(buf[0..n]);
    try @import("std").testing.expectEqual(flags, h.flags);
    try @import("std").testing.expectEqual(@as(u64, 0x8af3c1d2), h.schema_hash);
    try @import("std").testing.expectEqual(@as(u64, 1234), h.payload_len);
}

test "big-endian header hash" {
    var buf: [32]u8 = undefined;
    const flags = Flags{ .big_endian = true };
    const n = try encodeHeader(&buf, flags, 0x0102030405060708, 1);
    const h = try decodeHeader(buf[0..n]);
    try @import("std").testing.expectEqual(@as(u64, 0x0102030405060708), h.schema_hash);
    try @import("std").testing.expect(buf[5] == 0x01 and buf[12] == 0x08);
}

test "varint boundaries" {
    var buf: [16]u8 = undefined;
    const values = [_]u64{ 0, 1, 127, 128, 255, 16384, std_math_max_u64() };
    for (values) |v| {
        var w = Writer.init(&buf);
        try w.varint(v);
        var r = Reader.init(buf[0..w.pos]);
        try @import("std").testing.expectEqual(v, try r.varint());
    }
}

test "document payload slice" {
    var buf: [64]u8 = undefined;
    const n = try encodeDocument(&buf, .{}, 0, "abc");
    const h = try decodeHeader(buf[0..n]);
    try @import("std").testing.expectEqualStrings("abc", try payloadOf(buf[0..n], h));
}

test "compressed none unwrap" {
    const std = @import("std");
    var buf: [128]u8 = undefined;
    const n = try encodeCompressedNone(&buf, 0x11, "hello kati");
    const h = try decodeHeader(buf[0..n]);
    try std.testing.expect(h.flags.compressed);
    var scratch: [32]u8 = undefined;
    try std.testing.expectEqualStrings("hello kati", try unwrap(buf[0..n], &scratch));
}

test "schema hash mismatch" {
    const std = @import("std");
    var buf: [32]u8 = undefined;
    const n = try encodeHeader(&buf, .{}, 1, 0);
    const h = try decodeHeader(buf[0..n]);
    const s = schema.Struct{ .name = "X", .strict = false, .fields = &.{}, .schema_hash = 2 };
    try std.testing.expect(!checkHash(h, s));
    try std.testing.expectError(error.HashMismatch, requireHash(h, s));
}

fn std_math_max_u64() u64 {
    return ~@as(u64, 0);
}
