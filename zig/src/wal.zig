//! Write-ahead log of field patches. No allocator, no OS.
//!
//!   MAGIC        "WAL\x01"   4 bytes
//!   SCHEMA_HASH  u64le
//!   COUNT        varint
//!   ENTRY*       field_id varint · wire u8 · value
//!
//! `apply` rebuilds a payload: snapshot fields, last-write-wins from the log,
//! emitted in schema declaration order.

const io = @import("io.zig");
const schema = @import("schema.zig");
const value = @import("value.zig");
const record = @import("record.zig");

pub const Error = io.Error || value.Error || record.Error || error{ InvalidWal, HashMismatch };

pub const MAGIC = "WAL\x01";

pub const Entry = struct {
    field_id: u32,
    wire: value.WireType,
    raw: []const u8,
};

pub fn write(w: *io.Writer, schema_hash: u64, entries: []const Entry) Error!void {
    try w.bytes(MAGIC);
    try w.u64le(schema_hash);
    try w.varint(entries.len);
    for (entries) |e| {
        try value.writeFieldHeader(w, e.field_id, e.wire);
        try w.bytes(e.raw);
    }
}

pub fn readHeader(r: *io.Reader) Error!struct { schema_hash: u64, count: u64 } {
    const magic = try r.bytes(4);
    if (magic.len != 4 or magic[0] != 'W' or magic[1] != 'A' or magic[2] != 'L' or magic[3] != 1) {
        return error.InvalidWal;
    }
    const hash = try r.u64le();
    const count = try r.varint();
    return .{ .schema_hash = hash, .count = count };
}

pub fn next(r: *io.Reader) Error!Entry {
    const start = r.pos;
    const h = try value.readFieldHeader(r);
    const value_start = r.pos;
    try value.skipValue(r, h.wire_type);
    _ = start;
    return .{
        .field_id = h.field_id,
        .wire = h.wire_type,
        .raw = r.data[value_start..r.pos],
    };
}

pub fn apply(s: schema.Struct, snapshot: []const u8, wal_bytes: []const u8, out: []u8) Error!usize {
    var wr = io.Reader.init(wal_bytes);
    const hdr = try readHeader(&wr);
    if (hdr.schema_hash != s.schema_hash) return error.HashMismatch;

    var latest: [schema.MAX_FIELDS]?Entry = [_]?Entry{null} ** schema.MAX_FIELDS;
    var snap = io.Reader.init(snapshot);
    while (try record.next(&snap, s)) |item| {
        if (item.field_id > 0 and item.field_id <= schema.MAX_FIELDS) {
            latest[item.field_id - 1] = .{
                .field_id = item.field_id,
                .wire = item.wire,
                .raw = item.raw,
            };
        }
    }
    var i: u64 = 0;
    while (i < hdr.count) : (i += 1) {
        const e = try next(&wr);
        if (e.field_id == 0 or e.field_id > schema.MAX_FIELDS) return error.InvalidFieldId;
        latest[e.field_id - 1] = e;
    }

    var w = io.Writer.init(out);
    for (s.fields) |f| {
        if (f.field_id == 0 or f.field_id > schema.MAX_FIELDS) continue;
        const e = latest[f.field_id - 1] orelse {
            if (f.ann.required) return error.MissingField;
            continue;
        };
        try value.writeFieldHeader(&w, f.field_id, e.wire);
        try w.bytes(e.raw);
    }
    return w.pos;
}

test "wal overlays a field" {
    const std = @import("std");
    var p = schema.Parser.init("config X { name: string @required debug: bool }");
    const s = try p.parse();

    var snap: [32]u8 = undefined;
    var w = io.Writer.init(&snap);
    try value.writeFieldHeader(&w, 1, .bytes);
    try value.writeBytes(&w, "old");
    try value.writeFieldHeader(&w, 2, .varint);
    try value.writeBool(&w, false);
    const snap_n = w.pos;

    var patch_val: [8]u8 = undefined;
    var pw = io.Writer.init(&patch_val);
    try value.writeBytes(&pw, "new");
    const entries = [_]Entry{.{ .field_id = 1, .wire = .bytes, .raw = patch_val[0..pw.pos] }};

    var wal_buf: [64]u8 = undefined;
    var ww = io.Writer.init(&wal_buf);
    try write(&ww, s.schema_hash, &entries);

    var out: [64]u8 = undefined;
    const n = try apply(s, snap[0..snap_n], wal_buf[0..ww.pos], &out);
    var r = io.Reader.init(out[0..n]);
    const a = try value.readFieldHeader(&r);
    try std.testing.expectEqual(@as(u32, 1), a.field_id);
    try std.testing.expectEqualStrings("new", try value.readBytes(&r));
}
