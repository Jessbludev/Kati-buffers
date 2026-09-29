//! C-like field lookup: `pbr_read(buf, "AppConfig.name", &out)`.
//! Dotted paths walk nested named payloads, packed maps and array indices.
//! No allocator. `@r`/`@x` bits are enforced on every step.

const io = @import("io.zig");
const schema = @import("schema.zig");
const record = @import("record.zig");
const value = @import("value.zig");
const rwx = @import("rwx.zig");

pub const Error = record.Error || error{ NoSuchField, InvalidPath, UnsupportedType };

pub const MAX_PARTS: usize = 8;

pub const View = struct {
    field: ?schema.Field = null,
    item: record.Item,
    ty: schema.Type,
};

fn docOf(s: schema.Struct) schema.Doc {
    return .{ .defs = &.{}, .root = s };
}

fn split(path: []const u8, parts: *[MAX_PARTS][]const u8) Error!usize {
    if (path.len == 0) return error.InvalidPath;
    var n: usize = 0;
    var i: usize = 0;
    while (i < path.len) {
        if (path[i] == '.') return error.InvalidPath;
        var j = i;
        while (j < path.len and path[j] != '.') j += 1;
        if (n == MAX_PARTS) return error.Overflow;
        parts[n] = path[i..j];
        n += 1;
        if (j == path.len) break;
        i = j + 1;
        if (i == path.len) return error.InvalidPath;
    }
    return n;
}

fn isIndex(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}

fn parseIndex(s: []const u8) ?u64 {
    if (!isIndex(s)) return null;
    var v: u64 = 0;
    for (s) |c| {
        const d: u64 = c - '0';
        if (v > (~@as(u64, 0) - d) / 10) return null;
        v = v * 10 + d;
    }
    return v;
}

fn top(s: schema.Struct, payload: []const u8, name: []const u8) Error!record.Item {
    var r = io.Reader.init(payload);
    while (try record.next(&r, s)) |item| {
        if (item.field) |f| {
            if (eql(f.name, name)) {
                if (!rwx.canRead(f.ann.perms)) return error.PermDenied;
                return item;
            }
        }
    }
    return error.NoSuchField;
}

fn mapGet(m: schema.Type, raw: []const u8, key: []const u8) Error!record.Item {
    const mv = switch (m) {
        .map => |pair| pair,
        else => return error.TypeMismatch,
    };
    var r = io.Reader.init(raw);
    const blob = try value.readBytes(&r);
    var ir = io.Reader.init(blob);
    const count = try ir.varint();
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const ks = ir.pos;
        switch (mv.key) {
            .string => {
                const k = try value.readBytes(&ir);
                const vs = ir.pos;
                try record.skipBare(&ir, .{ .primitive = mv.value });
                if (eql(k, key)) {
                    return .{
                        .field_id = 0,
                        .wire = record.wireOf(.{ .primitive = mv.value }),
                        .field = null,
                        .header_start = ks,
                        .value_start = vs,
                        .value_end = ir.pos,
                        .raw = ir.data[vs..ir.pos],
                    };
                }
            },
            else => return error.UnsupportedType,
        }
    }
    return error.NoSuchField;
}

fn arrayGet(inner: schema.Primitive, raw: []const u8, index: u64) Error!record.Item {
    var r = io.Reader.init(raw);
    const blob = try value.readBytes(&r);
    var ir = io.Reader.init(blob);
    const count = try ir.varint();
    if (index >= count) return error.NoSuchField;
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const vs = ir.pos;
        try record.skipBare(&ir, .{ .primitive = inner });
        if (i == index) {
            return .{
                .field_id = 0,
                .wire = record.wireOf(.{ .primitive = inner }),
                .field = null,
                .header_start = vs,
                .value_start = vs,
                .value_end = ir.pos,
                .raw = ir.data[vs..ir.pos],
            };
        }
    }
    return error.NoSuchField;
}

pub fn at(doc: schema.Doc, payload: []const u8, path: []const u8) Error!View {
    var parts: [MAX_PARTS][]const u8 = undefined;
    const n = try split(path, &parts);
    var idx: usize = 0;
    if (n > 1 and eql(parts[0], doc.root.name)) idx = 1;
    if (idx >= n) return error.InvalidPath;

    var current_s = doc.root;
    var current_payload = payload;

    while (idx + 1 < n) : (idx += 1) {
        const part = parts[idx];
        if (isIndex(part)) return error.InvalidPath;
        const item = try top(current_s, current_payload, part);
        const f = item.field orelse return error.NoSuchField;
        const rest = n - idx - 1;
        switch (f.ty) {
            .named => |named| {
                if (named.kind == .enum_) return error.InvalidPath;
                const d = doc.find(named.name) orelse return error.UnsupportedType;
                current_s = d.asStruct();
                var r = io.Reader.init(item.raw);
                current_payload = value.readBytes(&r) catch return error.TypeMismatch;
            },
            .map => {
                if (rest != 1) return error.InvalidPath;
                const found = try mapGet(f.ty, item.raw, parts[idx + 1]);
                return .{ .field = f, .item = found, .ty = .{ .primitive = f.ty.map.value } };
            },
            .array => |inner| {
                if (rest != 1) return error.InvalidPath;
                const index = parseIndex(parts[idx + 1]) orelse return error.InvalidPath;
                const found = try arrayGet(inner, item.raw, index);
                return .{ .field = f, .item = found, .ty = .{ .primitive = inner } };
            },
            .primitive => return error.InvalidPath,
        }
    }

    const last = parts[n - 1];
    if (isIndex(last)) return error.InvalidPath;
    const item = try top(current_s, current_payload, last);
    const f = item.field orelse return error.NoSuchField;
    return .{ .field = f, .item = item, .ty = f.ty };
}

pub fn get(s: schema.Struct, payload: []const u8, name: []const u8) Error!?record.Item {
    const v = at(docOf(s), payload, name) catch |e| switch (e) {
        error.NoSuchField => return null,
        else => return e,
    };
    return v.item;
}

pub fn getRequired(s: schema.Struct, payload: []const u8, name: []const u8) Error!record.Item {
    return (try get(s, payload, name)) orelse error.NoSuchField;
}

pub fn string(s: schema.Struct, payload: []const u8, name: []const u8) Error![]const u8 {
    return stringDoc(docOf(s), payload, name);
}

pub fn stringDoc(doc: schema.Doc, payload: []const u8, name: []const u8) Error![]const u8 {
    const v = try at(doc, payload, name);
    var r = io.Reader.init(v.item.raw);
    return value.readBytes(&r) catch error.TypeMismatch;
}

pub fn unsigned(s: schema.Struct, payload: []const u8, name: []const u8) Error!u64 {
    return unsignedDoc(docOf(s), payload, name);
}

pub fn unsignedDoc(doc: schema.Doc, payload: []const u8, name: []const u8) Error!u64 {
    const v = try at(doc, payload, name);
    var r = io.Reader.init(v.item.raw);
    return value.readUnsigned(&r) catch error.TypeMismatch;
}

pub fn boolean(s: schema.Struct, payload: []const u8, name: []const u8) Error!bool {
    return booleanDoc(docOf(s), payload, name);
}

pub fn booleanDoc(doc: schema.Doc, payload: []const u8, name: []const u8) Error!bool {
    const v = try at(doc, payload, name);
    var r = io.Reader.init(v.item.raw);
    return value.readBool(&r) catch error.TypeMismatch;
}

pub fn bytes(s: schema.Struct, payload: []const u8, name: []const u8) Error![]const u8 {
    return string(s, payload, name);
}

pub fn signed(s: schema.Struct, payload: []const u8, name: []const u8) Error!i64 {
    return signedDoc(docOf(s), payload, name);
}

pub fn signedDoc(doc: schema.Doc, payload: []const u8, name: []const u8) Error!i64 {
    const v = try at(doc, payload, name);
    var r = io.Reader.init(v.item.raw);
    return value.readSigned(&r) catch error.TypeMismatch;
}

fn eql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (x != y) return false;
    return true;
}

test "lookup by name" {
    const std = @import("std");
    var p = schema.Parser.init("config X { name: string @required version: u16 }");
    const s = try p.parse();
    var buf: [32]u8 = undefined;
    var w = io.Writer.init(&buf);
    try value.writeFieldHeader(&w, 1, .bytes);
    try value.writeBytes(&w, "kati");
    try value.writeFieldHeader(&w, 2, .varint);
    try value.writeUnsigned(&w, 7);
    try std.testing.expectEqualStrings("kati", try string(s, buf[0..w.pos], "name"));
    try std.testing.expectEqualStrings("kati", try string(s, buf[0..w.pos], "X.name"));
    try std.testing.expectEqual(@as(u64, 7), try unsigned(s, buf[0..w.pos], "version"));
    try std.testing.expectError(error.NoSuchField, getRequired(s, buf[0..w.pos], "missing"));
}

test "execute-only field cannot be read" {
    const std = @import("std");
    var p = schema.Parser.init("buffer S { hook: bytes @x }");
    const s = try p.parse();
    var buf: [16]u8 = undefined;
    var w = io.Writer.init(&buf);
    try value.writeFieldHeader(&w, 1, .bytes);
    try value.writeBytes(&w, "fn");
    try std.testing.expectError(error.PermDenied, string(s, buf[0..w.pos], "hook"));
}
