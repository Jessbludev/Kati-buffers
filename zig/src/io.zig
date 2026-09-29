//! Allocator-free byte reader/writer primitives used by the .pbr core.
//! Zig 0.16: methods must not shadow primitive types, so a single byte is `byte`.
//! Shift amounts for `u64` are `u6` (0…63); a `u7` shift is a compile error.

pub const Error = error{ Truncated, InvalidVarint, Overflow, NonCanonicalVarint };

pub fn lebSize(value: u64) usize {
    var v = value;
    var n: usize = 1;
    while (v >= 0x80) {
        v >>= 7;
        n += 1;
    }
    return n;
}

pub const Writer = struct {
    out: []u8,
    pos: usize = 0,

    pub fn init(out: []u8) Writer {
        return .{ .out = out };
    }
    fn put(self: *Writer, value: u8) Error!void {
        if (self.pos >= self.out.len) return error.Truncated;
        self.out[self.pos] = value;
        self.pos += 1;
    }
    pub fn remaining(self: Writer) usize {
        return self.out.len - self.pos;
    }
    pub fn bytes(self: *Writer, src: []const u8) Error!void {
        if (src.len > self.out.len - self.pos) return error.Truncated;
        @memcpy(self.out[self.pos .. self.pos + src.len], src);
        self.pos += src.len;
    }
    pub fn byte(self: *Writer, value: u8) Error!void {
        try self.put(value);
    }
    pub fn u16le(self: *Writer, value: u16) Error!void {
        try self.put(@truncate(value));
        try self.put(@truncate(value >> 8));
    }
    pub fn u16be(self: *Writer, value: u16) Error!void {
        try self.put(@truncate(value >> 8));
        try self.put(@truncate(value));
    }
    pub fn u32le(self: *Writer, value: u32) Error!void {
        var i: u3 = 0;
        while (i < 4) : (i += 1) try self.put(@truncate(value >> (@as(u5, i) * 8)));
    }
    pub fn u32be(self: *Writer, value: u32) Error!void {
        var i: u3 = 0;
        while (i < 4) : (i += 1) try self.put(@truncate(value >> ((3 - @as(u5, i)) * 8)));
    }
    pub fn u64le(self: *Writer, value: u64) Error!void {
        var i: u6 = 0;
        while (i < 8) : (i += 1) try self.put(@truncate(value >> (i * 8)));
    }
    pub fn u64be(self: *Writer, value: u64) Error!void {
        var i: u6 = 0;
        while (i < 8) : (i += 1) try self.put(@truncate(value >> ((7 - i) * 8)));
    }
    pub fn varint(self: *Writer, value: u64) Error!void {
        var v = value;
        while (v >= 0x80) {
            try self.put(@as(u8, @truncate(v)) | 0x80);
            v >>= 7;
        }
        try self.put(@truncate(v));
    }
};

pub const Reader = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn init(data: []const u8) Reader {
        return .{ .data = data };
    }
    pub fn remaining(self: Reader) usize {
        return self.data.len - self.pos;
    }
    pub fn atEnd(self: Reader) bool {
        return self.pos >= self.data.len;
    }
    pub fn byte(self: *Reader) Error!u8 {
        return self.take();
    }
    fn take(self: *Reader) Error!u8 {
        if (self.pos >= self.data.len) return error.Truncated;
        const v = self.data[self.pos];
        self.pos += 1;
        return v;
    }
    pub fn bytes(self: *Reader, len: usize) Error![]const u8 {
        if (len > self.data.len - self.pos) return error.Truncated;
        const s = self.data[self.pos .. self.pos + len];
        self.pos += len;
        return s;
    }
    pub fn u16le(self: *Reader) Error!u16 {
        const b0 = try self.take();
        const b1 = try self.take();
        return @as(u16, b0) | (@as(u16, b1) << 8);
    }
    pub fn u16be(self: *Reader) Error!u16 {
        const b0 = try self.take();
        const b1 = try self.take();
        return (@as(u16, b0) << 8) | @as(u16, b1);
    }
    pub fn u32le(self: *Reader) Error!u32 {
        var value: u32 = 0;
        var i: u3 = 0;
        while (i < 4) : (i += 1) value |= @as(u32, try self.take()) << (@as(u5, i) * 8);
        return value;
    }
    pub fn u32be(self: *Reader) Error!u32 {
        var value: u32 = 0;
        var i: u3 = 0;
        while (i < 4) : (i += 1) value |= @as(u32, try self.take()) << ((3 - @as(u5, i)) * 8);
        return value;
    }
    pub fn u64le(self: *Reader) Error!u64 {
        var value: u64 = 0;
        var i: u6 = 0;
        while (i < 8) : (i += 1) value |= @as(u64, try self.take()) << (i * 8);
        return value;
    }
    pub fn u64be(self: *Reader) Error!u64 {
        var value: u64 = 0;
        var i: u6 = 0;
        while (i < 8) : (i += 1) value |= @as(u64, try self.take()) << ((7 - i) * 8);
        return value;
    }
    pub fn varint(self: *Reader) Error!u64 {
        var value: u64 = 0;
        var shift: u6 = 0;
        var count: u8 = 0;
        while (true) {
            if (count == 10) return error.InvalidVarint;
            const last = try self.take();
            const part: u64 = last & 0x7f;
            if (shift == 63 and part > 1) return error.Overflow;
            value |= part << shift;
            if ((last & 0x80) == 0) {
                if (part == 0 and count > 0) return error.NonCanonicalVarint;
                return value;
            }
            if (shift >= 63) return error.Overflow;
            shift += 7;
            count += 1;
        }
    }
};

test "overlong varint is rejected" {
    const std = @import("std");
    var r = Reader.init(&[_]u8{ 0x80, 0x00 });
    try std.testing.expectError(error.NonCanonicalVarint, r.varint());
}

test "canonical zero is accepted" {
    const std = @import("std");
    var r = Reader.init(&[_]u8{0x00});
    try std.testing.expectEqual(@as(u64, 0), try r.varint());
}

test "u64 max uses ten bytes" {
    const std = @import("std");
    var buf: [16]u8 = undefined;
    var w = Writer.init(&buf);
    try w.varint(~@as(u64, 0));
    try std.testing.expectEqual(@as(usize, 10), w.pos);
    var r = Reader.init(buf[0..w.pos]);
    try std.testing.expectEqual(~@as(u64, 0), try r.varint());
}

test "eleventh varint byte overflows" {
    const std = @import("std");
    var r = Reader.init(&[_]u8{
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
    });
    try std.testing.expectError(error.Overflow, r.varint());
}
