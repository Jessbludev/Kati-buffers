//! Deterministic .pbr value wire codec.
//! This layer defines payload framing for scalar values and length-delimited
//! values. It deliberately does not allocate and does not depend on the OS.

const io = @import("io.zig");

pub const Error = io.Error || error{
    InvalidWireType,
    InvalidFieldId,
    InvalidLength,
    TypeMismatch,
};

pub const WireType = enum(u8) {
    varint = 0,
    fixed64 = 1,
    bytes = 2,
    fixed32 = 5,
};

pub const FieldHeader = struct {
    field_id: u32,
    wire_type: WireType,
};

pub fn writeFieldHeader(w: *io.Writer, field_id: u32, wire_type: WireType) Error!void {
    if (field_id == 0) return error.InvalidFieldId;
    try w.varint(field_id);
    try w.byte(@intFromEnum(wire_type));
}

pub fn readFieldHeader(r: *io.Reader) Error!FieldHeader {
    const raw_id = try r.varint();
    if (raw_id == 0 or raw_id > 0xffffffff) return error.InvalidFieldId;
    const raw_type = try r.byte();
    const wire_type: WireType = switch (raw_type) {
        0 => .varint,
        1 => .fixed64,
        2 => .bytes,
        5 => .fixed32,
        else => return error.InvalidWireType,
    };
    return .{ .field_id = @intCast(raw_id), .wire_type = wire_type };
}

pub fn writeBool(w: *io.Writer, value: bool) Error!void {
    try w.varint(if (value) 1 else 0);
}

pub fn readBool(r: *io.Reader) Error!bool {
    const value = try r.varint();
    return switch (value) {
        0 => false,
        1 => true,
        else => error.TypeMismatch,
    };
}

pub fn writeUnsigned(w: *io.Writer, value: u64) Error!void {
    try w.varint(value);
}

pub fn readUnsigned(r: *io.Reader) Error!u64 {
    return r.varint();
}

pub fn writeSigned(w: *io.Writer, value: i64) Error!void {
    const encoded = (@as(u64, @bitCast(value)) << 1) ^ @as(u64, @bitCast(value >> 63));
    try w.varint(encoded);
}

pub fn readSigned(r: *io.Reader) Error!i64 {
    const encoded = try r.varint();
    const value = encoded >> 1;
    const sign = encoded & 1;
    return @bitCast(value ^ (0 -% sign));
}

pub fn writeFixed32(w: *io.Writer, value: u32) Error!void {
    try w.byte(@truncate(value));
    try w.byte(@truncate(value >> 8));
    try w.byte(@truncate(value >> 16));
    try w.byte(@truncate(value >> 24));
}

pub fn readFixed32(r: *io.Reader) Error!u32 {
    const b0 = try r.byte();
    const b1 = try r.byte();
    const b2 = try r.byte();
    const b3 = try r.byte();
    return @as(u32, b0) | (@as(u32, b1) << 8) | (@as(u32, b2) << 16) | (@as(u32, b3) << 24);
}

pub fn writeFixed64(w: *io.Writer, value: u64) Error!void {
    try w.u64le(value);
}

pub fn readFixed64(r: *io.Reader) Error!u64 {
    return r.u64le();
}

pub fn writeF32(w: *io.Writer, value: f32) Error!void {
    try writeFixed32(w, @bitCast(value));
}

pub fn readF32(r: *io.Reader) Error!f32 {
    return @bitCast(try readFixed32(r));
}

pub fn writeF64(w: *io.Writer, value: f64) Error!void {
    try writeFixed64(w, @bitCast(value));
}

pub fn readF64(r: *io.Reader) Error!f64 {
    return @bitCast(try readFixed64(r));
}

pub fn writeBytes(w: *io.Writer, bytes: []const u8) Error!void {
    try w.varint(bytes.len);
    try w.bytes(bytes);
}

pub fn readBytes(r: *io.Reader) Error![]const u8 {
    const length = try r.varint();
    if (length > @as(u64, r.remaining())) return error.InvalidLength;
    return r.bytes(@intCast(length));
}

pub const Packed = struct {
    count: u64,
    items: []const u8,
};

/// Length-delimited packed sequence used by arrays and maps:
///   BYTES  = varint(len) || ( varint(count) || item* )
pub fn writePacked(w: *io.Writer, count: u64, items: []const u8) Error!void {
    const n = io.lebSize(count) + items.len;
    try w.varint(n);
    try w.varint(count);
    try w.bytes(items);
}

pub fn readPacked(r: *io.Reader) Error!Packed {
    const blob = try readBytes(r);
    var inner = io.Reader.init(blob);
    const count = try inner.varint();
    return .{ .count = count, .items = blob[inner.pos..] };
}

pub fn writeNested(w: *io.Writer, payload: []const u8) Error!void {
    try writeBytes(w, payload);
}

pub fn readNested(r: *io.Reader) Error![]const u8 {
    return readBytes(r);
}

pub fn writeChar(w: *io.Writer, codepoint: u32) Error!void {
    try w.varint(codepoint);
}

pub fn readChar(r: *io.Reader) Error!u32 {
    const v = try r.varint();
    if (v > 0x10ffff) return error.TypeMismatch;
    return @intCast(v);
}

pub fn writeUuid(w: *io.Writer, uuid: []const u8) Error!void {
    if (uuid.len != 16) return error.InvalidLength;
    try writeBytes(w, uuid);
}

pub fn readUuid(r: *io.Reader) Error![]const u8 {
    const b = try readBytes(r);
    if (b.len != 16) return error.InvalidLength;
    return b;
}

pub fn writeTimestamp(w: *io.Writer, unix_ms: i64) Error!void {
    try writeSigned(w, unix_ms);
}

pub fn readTimestamp(r: *io.Reader) Error!i64 {
    return readSigned(r);
}

pub fn writeDuration(w: *io.Writer, ms: i64) Error!void {
    try writeSigned(w, ms);
}

pub fn readDuration(r: *io.Reader) Error!i64 {
    return readSigned(r);
}

pub fn skipValue(r: *io.Reader, wire_type: WireType) Error!void {
    switch (wire_type) {
        .varint => _ = try r.varint(),
        .fixed64 => _ = try r.u64le(),
        .fixed32 => _ = try readFixed32(r),
        .bytes => _ = try readBytes(r),
    }
}

test "field header roundtrip" {
    var buf: [16]u8 = undefined;
    var w = io.Writer.init(&buf);
    try writeFieldHeader(&w, 7, .bytes);
    var r = io.Reader.init(buf[0..w.pos]);
    const h = try readFieldHeader(&r);
    try @import("std").testing.expectEqual(@as(u32, 7), h.field_id);
    try @import("std").testing.expectEqual(WireType.bytes, h.wire_type);
}

test "signed zigzag roundtrip" {
    const std = @import("std");
    const values = [_]i64{ -9223372036854775807, -1000, -1, 0, 1, 1000, 9223372036854775807, std.math.minInt(i64) };
    var buf: [16]u8 = undefined;
    for (values) |value| {
        var w = io.Writer.init(&buf);
        try writeSigned(&w, value);
        var r = io.Reader.init(buf[0..w.pos]);
        try std.testing.expectEqual(value, try readSigned(&r));
    }
}

test "bool is canonical" {
    var buf: [8]u8 = undefined;
    var w = io.Writer.init(&buf);
    try writeBool(&w, true);
    var r = io.Reader.init(buf[0..w.pos]);
    try @import("std").testing.expect(try readBool(&r));
}

test "f32 f64 roundtrip" {
    const std = @import("std");
    var buf: [16]u8 = undefined;
    {
        var w = io.Writer.init(&buf);
        try writeF32(&w, 1.5);
        var r = io.Reader.init(buf[0..w.pos]);
        try std.testing.expectEqual(@as(f32, 1.5), try readF32(&r));
    }
    {
        var w = io.Writer.init(&buf);
        try writeF64(&w, -2.25);
        var r = io.Reader.init(buf[0..w.pos]);
        try std.testing.expectEqual(@as(f64, -2.25), try readF64(&r));
    }
}

test "packed array count" {
    const std = @import("std");
    var items: [16]u8 = undefined;
    var iw = io.Writer.init(&items);
    try writeBytes(&iw, "a.io");
    try writeBytes(&iw, "b.io");
    var buf: [32]u8 = undefined;
    var w = io.Writer.init(&buf);
    try writePacked(&w, 2, items[0..iw.pos]);
    var r = io.Reader.init(buf[0..w.pos]);
    const p = try readPacked(&r);
    try std.testing.expectEqual(@as(u64, 2), p.count);
    var ir = io.Reader.init(p.items);
    try std.testing.expectEqualStrings("a.io", try readBytes(&ir));
    try std.testing.expectEqualStrings("b.io", try readBytes(&ir));
}

test "uuid is sixteen bytes" {
    const std = @import("std");
    var buf: [32]u8 = undefined;
    var w = io.Writer.init(&buf);
    const id = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    try writeUuid(&w, &id);
    var r = io.Reader.init(buf[0..w.pos]);
    try std.testing.expectEqual(@as(usize, 16), (try readUuid(&r)).len);
    w = io.Writer.init(&buf);
    try std.testing.expectError(error.InvalidLength, writeUuid(&w, "short"));
}

