//! Logical streams over one byte pipe.
//!
//! Frame layout (little-endian):
//!   CHID  u16     logical channel 0…65535
//!   FLAGS u8      FIN SYN RST ACK COMPRESSED; bits 5–7 reserved and rejected
//!   SEQ   u32     per-channel sequence
//!   LEN   varint  payload length
//!   DATA  n B     opaque bytes, often a PrettyBuffer
//!
//! No allocator. The caller owns `w.out` and `r.data`. A host may map channels
//! onto sockets; the core only frames bytes.

const io = @import("io.zig");

pub const Error = io.Error || error{ InvalidMux };

pub const FIN: u8 = 1;
pub const SYN: u8 = 2;
pub const RST: u8 = 4;
pub const ACK: u8 = 8;
pub const COMPRESSED: u8 = 16;

pub const Frame = struct {
    chid: u16,
    flags: u8,
    seq: u32,
    data: []const u8,
};

pub fn write(w: *io.Writer, chid: u16, flags: u8, seq: u32, data: []const u8) Error!void {
    if (flags & 0b1110_0000 != 0) return error.InvalidMux;
    try w.u16le(chid);
    try w.byte(flags);
    try w.u32le(seq);
    try w.varint(data.len);
    try w.bytes(data);
}

pub fn read(r: *io.Reader) Error!Frame {
    const chid = try r.u16le();
    const flags = try r.byte();
    if (flags & 0b1110_0000 != 0) return error.InvalidMux;
    const seq = try r.u32le();
    const n = try r.varint();
    if (n > @as(u64, r.remaining())) return error.Truncated;
    const data = try r.bytes(@intCast(n));
    return .{ .chid = chid, .flags = flags, .seq = seq, .data = data };
}

test "mux frame roundtrip" {
    var buf: [32]u8 = undefined;
    var w = io.Writer.init(&buf);
    try write(&w, 7, SYN | ACK, 42, "hi");
    var r = io.Reader.init(buf[0..w.pos]);
    const f = try read(&r);
    try @import("std").testing.expectEqual(@as(u16, 7), f.chid);
    try @import("std").testing.expectEqual(SYN | ACK, f.flags);
    try @import("std").testing.expectEqual(@as(u32, 42), f.seq);
    try @import("std").testing.expectEqualStrings("hi", f.data);
}
