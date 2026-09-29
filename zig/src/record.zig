//! Schema-guided payload walk and typed builder. No allocator.
//! Unknown fields skip by wire type unless the record is `@strict`.

const io = @import("io.zig");
const schema = @import("schema.zig");
const value = @import("value.zig");
const rwx = @import("rwx.zig");

pub const Error = io.Error || value.Error || error{
    UnknownField,
    MissingField,
    MaxExceeded,
    PermDenied,
};

pub const Item = struct {
    field_id: u32,
    wire: value.WireType,
    field: ?schema.Field,
    header_start: usize,
    value_start: usize,
    value_end: usize,
    raw: []const u8,
};

pub fn wireOf(ty: schema.Type) value.WireType {
    return switch (ty) {
        .array, .map => .bytes,
        .named => |n| if (n.kind == .enum_) .varint else .bytes,
        .primitive => |p| switch (p) {
            .f32 => .fixed32,
            .f64 => .fixed64,
            .string, .bytes, .uuid, .fn_ => .bytes,
            else => .varint,
        },
    };
}

pub fn rangeUnsigned(p: schema.Primitive, v: u64) Error!void {
    const max: u64 = switch (p) {
        .u8, .char => 0xff,
        .u16 => 0xffff,
        .u32 => 0xffffffff,
        .u64 => ~@as(u64, 0),
        .rwx => 0o777,
        .bool => 1,
        else => return,
    };
    if (v > max) return error.Overflow;
}

pub fn rangeSigned(p: schema.Primitive, v: i64) Error!void {
    const min: i64, const max: i64 = switch (p) {
        .i8 => .{ -128, 127 },
        .i16 => .{ -32768, 32767 },
        .i32 => .{ -2147483648, 2147483647 },
        .i64, .timestamp, .duration => return,
        else => return error.TypeMismatch,
    };
    if (v < min or v > max) return error.Overflow;
}

pub fn skipBare(r: *io.Reader, ty: schema.Type) Error!void {
    switch (ty) {
        .array, .map => _ = try value.readBytes(r),
        .named => |n| {
            if (n.kind == .enum_) {
                _ = try value.readUnsigned(r);
            } else _ = try value.readBytes(r);
        },
        .primitive => |p| switch (p) {
            .f32 => _ = try value.readF32(r),
            .f64 => _ = try value.readF64(r),
            .string, .bytes, .uuid, .fn_ => _ = try value.readBytes(r),
            .i8, .i16, .i32, .i64, .timestamp, .duration => _ = try value.readSigned(r),
            .bool => _ = try value.readBool(r),
            else => _ = try value.readUnsigned(r),
        },
    }
}

pub fn findById(s: schema.Struct, id: u32) ?schema.Field {
    for (s.fields) |f| {
        if (f.field_id == id) return f;
    }
    return null;
}

pub fn findByName(s: schema.Struct, name: []const u8) ?schema.Field {
    for (s.fields) |f| {
        if (eql(f.name, name)) return f;
    }
    return null;
}

pub fn next(r: *io.Reader, s: schema.Struct) Error!?Item {
    if (r.atEnd()) return null;
    const header_start = r.pos;
    const h = try value.readFieldHeader(r);
    const value_start = r.pos;
    const field = findById(s, h.field_id);
    if (field) |f| {
        const expected = wireOf(f.ty);
        if (h.wire_type != expected) return error.TypeMismatch;
        try value.skipValue(r, h.wire_type);
        if (f.ann.max) |max| {
            if (f.ty == .array) {
                var inner = io.Reader.init(r.data[value_start..r.pos]);
                const packed_bytes = try value.readBytes(&inner);
                var pr = io.Reader.init(packed_bytes);
                const count = try pr.varint();
                if (count > max) return error.MaxExceeded;
            }
        }
    } else {
        if (s.strict) return error.UnknownField;
        try value.skipValue(r, h.wire_type);
    }
    return .{
        .field_id = h.field_id,
        .wire = h.wire_type,
        .field = field,
        .header_start = header_start,
        .value_start = value_start,
        .value_end = r.pos,
        .raw = r.data[value_start..r.pos],
    };
}

pub fn walk(s: schema.Struct, payload: []const u8, views: []Item) Error!usize {
    var r = io.Reader.init(payload);
    var n: usize = 0;
    var seen: [schema.MAX_FIELDS]bool = [_]bool{false} ** schema.MAX_FIELDS;
    while (try next(&r, s)) |item| {
        if (n >= views.len) return error.Overflow;
        views[n] = item;
        n += 1;
        if (item.field_id > 0 and item.field_id <= schema.MAX_FIELDS) {
            seen[item.field_id - 1] = true;
        }
    }
    try requirePresent(s, seen);
    return n;
}

pub fn requirePresent(s: schema.Struct, seen: [schema.MAX_FIELDS]bool) Error!void {
    for (s.fields) |f| {
        if (!f.ann.required) continue;
        if (f.field_id == 0 or f.field_id > schema.MAX_FIELDS) return error.InvalidFieldId;
        if (!seen[f.field_id - 1]) return error.MissingField;
    }
}

pub fn writeField(w: *io.Writer, f: schema.Field, payload: []const u8) Error!void {
    try value.writeFieldHeader(w, f.field_id, wireOf(f.ty));
    try w.bytes(payload);
}

/// Typed payload builder. Fields are emitted in call order. `finish`
/// rejects missing `@required` fields and `@r`-only writes.
pub const Builder = struct {
    w: io.Writer,
    s: schema.Struct,
    seen: [schema.MAX_FIELDS]bool = [_]bool{false} ** schema.MAX_FIELDS,

    pub fn init(out: []u8, s: schema.Struct) Builder {
        return .{ .w = io.Writer.init(out), .s = s };
    }

    pub fn pos(self: Builder) usize {
        return self.w.pos;
    }

    pub fn payload(self: Builder) []const u8 {
        return self.w.out[0..self.w.pos];
    }

    fn begin(self: *Builder, name: []const u8) Error!schema.Field {
        const f = findByName(self.s, name) orelse return error.UnknownField;
        if (!rwx.canWrite(f.ann.perms)) return error.PermDenied;
        if (f.field_id > 0 and f.field_id <= schema.MAX_FIELDS) {
            self.seen[f.field_id - 1] = true;
        }
        try value.writeFieldHeader(&self.w, f.field_id, wireOf(f.ty));
        return f;
    }

    pub fn putBool(self: *Builder, name: []const u8, v: bool) Error!void {
        const f = try self.begin(name);
        switch (f.ty) {
            .primitive => |p| if (p != .bool) return error.TypeMismatch,
            else => return error.TypeMismatch,
        }
        try value.writeBool(&self.w, v);
    }

    pub fn putUnsigned(self: *Builder, name: []const u8, v: u64) Error!void {
        const f = try self.begin(name);
        switch (f.ty) {
            .primitive => |p| try rangeUnsigned(p, v),
            .named => |n| if (n.kind != .enum_) return error.TypeMismatch,
            else => return error.TypeMismatch,
        }
        try value.writeUnsigned(&self.w, v);
    }

    pub fn putSigned(self: *Builder, name: []const u8, v: i64) Error!void {
        const f = try self.begin(name);
        switch (f.ty) {
            .primitive => |p| try rangeSigned(p, v),
            else => return error.TypeMismatch,
        }
        try value.writeSigned(&self.w, v);
    }

    pub fn putString(self: *Builder, name: []const u8, v: []const u8) Error!void {
        const f = try self.begin(name);
        switch (f.ty) {
            .primitive => |p| switch (p) {
                .string, .bytes, .fn_ => {},
                else => return error.TypeMismatch,
            },
            else => return error.TypeMismatch,
        }
        try value.writeBytes(&self.w, v);
    }

    pub fn putBytes(self: *Builder, name: []const u8, v: []const u8) Error!void {
        try self.putString(name, v);
    }

    pub fn putPacked(self: *Builder, name: []const u8, count: u64, items: []const u8) Error!void {
        const f = try self.begin(name);
        switch (f.ty) {
            .array => |p| {
                _ = p;
                if (f.ann.max) |max| {
                    if (count > max) return error.MaxExceeded;
                }
            },
            .map => {},
            else => return error.TypeMismatch,
        }
        try value.writePacked(&self.w, count, items);
    }

    pub fn putNested(self: *Builder, name: []const u8, inner: []const u8) Error!void {
        const f = try self.begin(name);
        switch (f.ty) {
            .named => |n| if (n.kind == .enum_) return error.TypeMismatch,
            else => return error.TypeMismatch,
        }
        try value.writeBytes(&self.w, inner);
    }

    pub fn finish(self: *Builder) Error![]const u8 {
        try requirePresent(self.s, self.seen);
        return self.payload();
    }
};

fn eql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (x != y) return false;
    return true;
}

test "walk required and skip unknown" {
    const std = @import("std");
    const src = "config X { name: string @required extra: u16 }";
    var p = schema.Parser.init(src);
    const s = try p.parse();

    var buf: [64]u8 = undefined;
    var w = io.Writer.init(&buf);
    try value.writeFieldHeader(&w, 1, .bytes);
    try value.writeBytes(&w, "ok");
    try value.writeFieldHeader(&w, 9, .varint);
    try value.writeUnsigned(&w, 7);

    var views: [8]Item = undefined;
    try std.testing.expectError(error.UnknownField, walk(.{
        .name = s.name,
        .strict = true,
        .fields = s.fields,
        .schema_hash = s.schema_hash,
    }, buf[0..w.pos], &views));

    const n = try walk(s, buf[0..w.pos], &views);
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqual(@as(u32, 1), views[0].field_id);
    try std.testing.expect(views[0].field != null);
    try std.testing.expect(views[1].field == null);
}

test "builder writes required fields" {
    const std = @import("std");
    var p = schema.Parser.init("config X { name: string @required version: u16 }");
    const s = try p.parse();
    var buf: [64]u8 = undefined;
    var b = Builder.init(&buf, s);
    try b.putString("name", "kati");
    try b.putUnsigned("version", 7);
    const body = try b.finish();
    try std.testing.expectEqualStrings("kati", blk: {
        var r = io.Reader.init(body);
        _ = try value.readFieldHeader(&r);
        break :blk try value.readBytes(&r);
    });
}

test "builder rejects read-only write" {
    const std = @import("std");
    var p = schema.Parser.init("buffer S { readme: string @r }");
    const s = try p.parse();
    var buf: [32]u8 = undefined;
    var b = Builder.init(&buf, s);
    try std.testing.expectError(error.PermDenied, b.putString("readme", "no"));
}

test "u16 overflow is rejected" {
    const std = @import("std");
    try std.testing.expectError(error.Overflow, rangeUnsigned(.u16, 70000));
    try rangeUnsigned(.u16, 0xffff);
    try rangeSigned(.i8, -128);
    try std.testing.expectError(error.Overflow, rangeSigned(.i8, 128));
}
