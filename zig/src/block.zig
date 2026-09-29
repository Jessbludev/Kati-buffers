//! 64 KiB streaming blocks with CRC32C.
//! Present when the document FLAGS.compressed bit is set.
//!
//!   ALGO     u8      0 none · 1 lz4 · 2 zstd · 3 brotli
//!   RAW_LEN  varint  uncompressed size
//!   COMP_LEN varint  stored size
//!   CRC32C   u32le   of uncompressed bytes
//!   DATA     n B     COMP_LEN bytes
//!
//! v0.5 implements `none` fully. Other algorithms are reserved and rejected
//! so a later host can plug a compressor without changing the frame.

const io = @import("io.zig");
const crc = @import("crc.zig");

pub const Error = io.Error || error{ InvalidBlock, Checksum, UnsupportedAlgo };

pub const SIZE: usize = 64 * 1024;

pub const Algo = enum(u8) {
    none = 0,
    lz4 = 1,
    zstd = 2,
    brotli = 3,
};

pub const Frame = struct {
    algo: Algo,
    raw_len: u64,
    crc: u32,
    data: []const u8,
};

pub fn write(w: *io.Writer, algo: Algo, raw: []const u8, stored: []const u8) Error!void {
    if (algo != .none) return error.UnsupportedAlgo;
    if (stored.len != raw.len) return error.InvalidBlock;
    try w.byte(@intFromEnum(algo));
    try w.varint(raw.len);
    try w.varint(stored.len);
    try w.u32le(crc.crc32c(raw));
    try w.bytes(stored);
}

pub fn writeNone(w: *io.Writer, raw: []const u8) Error!void {
    try write(w, .none, raw, raw);
}

pub fn writeAllNone(w: *io.Writer, raw: []const u8) Error!void {
    var i: usize = 0;
    while (i < raw.len) {
        const n = @min(SIZE, raw.len - i);
        try writeNone(w, raw[i .. i + n]);
        i += n;
    }
}

pub fn read(r: *io.Reader) Error!Frame {
    const raw_algo = try r.byte();
    const algo: Algo = switch (raw_algo) {
        0 => .none,
        1 => .lz4,
        2 => .zstd,
        3 => .brotli,
        else => return error.UnsupportedAlgo,
    };
    const raw_len = try r.varint();
    const comp_len = try r.varint();
    const sum = try r.u32le();
    if (comp_len > @as(u64, r.remaining())) return error.Truncated;
    const data = try r.bytes(@intCast(comp_len));
    if (algo == .none) {
        if (raw_len != comp_len) return error.InvalidBlock;
        if (crc.crc32c(data) != sum) return error.Checksum;
    } else return error.UnsupportedAlgo;
    return .{ .algo = algo, .raw_len = raw_len, .crc = sum, .data = data };
}

pub fn readAllNone(r: *io.Reader, out: []u8) Error!usize {
    var pos: usize = 0;
    while (!r.atEnd()) {
        const f = try read(r);
        if (pos + f.data.len > out.len) return error.Truncated;
        @memcpy(out[pos .. pos + f.data.len], f.data);
        pos += f.data.len;
    }
    return pos;
}

test "none block roundtrip" {
    const std = @import("std");
    var buf: [64]u8 = undefined;
    var w = io.Writer.init(&buf);
    try writeNone(&w, "payload");
    var r = io.Reader.init(buf[0..w.pos]);
    const f = try read(&r);
    try std.testing.expectEqual(Algo.none, f.algo);
    try std.testing.expectEqualStrings("payload", f.data);
    try std.testing.expectEqual(crc.crc32c("payload"), f.crc);
}

test "corrupt crc is rejected" {
    const std = @import("std");
    var buf: [64]u8 = undefined;
    var w = io.Writer.init(&buf);
    try writeNone(&w, "payload");
    buf[w.pos - 1] ^= 0xff;
    var r = io.Reader.init(buf[0..w.pos]);
    try std.testing.expectError(error.Checksum, read(&r));
}
