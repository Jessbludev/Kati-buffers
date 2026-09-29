const std = @import("std");
const kati = @import("kati");

test "manual AppConfig encode path wal compress" {
    const src =
        \\@strict
        \\config AppConfig {
        \\    name: string @required
        \\    version: u16
        \\    debug: bool = false
        \\    endpoints: array[string] @max(32)
        \\}
    ;
    var parser = kati.schema.Parser.init(src);
    const schema = try parser.parse();

    var payload: [128]u8 = undefined;
    var w = kati.Writer.init(&payload);
    try kati.value.writeFieldHeader(&w, 1, .bytes);
    try kati.value.writeBytes(&w, "server-a");
    try kati.value.writeFieldHeader(&w, 2, .varint);
    try kati.value.writeUnsigned(&w, 0x0104);
    try kati.value.writeFieldHeader(&w, 3, .varint);
    try kati.value.writeBool(&w, false);

    var items: [32]u8 = undefined;
    var iw = kati.Writer.init(&items);
    try kati.value.writeBytes(&iw, "a.io");
    try kati.value.writeBytes(&iw, "b.io");
    try kati.value.writeFieldHeader(&w, 4, .bytes);
    try kati.value.writePacked(&w, 2, items[0..iw.pos]);

    const body = payload[0..w.pos];
    try std.testing.expectEqualStrings("server-a", try kati.path.string(schema, body, "name"));
    try std.testing.expectEqual(@as(u64, 0x0104), try kati.path.unsigned(schema, body, "version"));
    try std.testing.expect(!(try kati.path.boolean(schema, body, "debug")));

    var patch: [16]u8 = undefined;
    var pw = kati.Writer.init(&patch);
    try kati.value.writeBool(&pw, true);
    const entries = [_]kati.wal.Entry{.{ .field_id = 3, .wire = .varint, .raw = patch[0..pw.pos] }};
    var wal_buf: [64]u8 = undefined;
    var ww = kati.Writer.init(&wal_buf);
    try kati.wal.write(&ww, schema.schema_hash, &entries);
    var patched: [128]u8 = undefined;
    const pn = try kati.wal.apply(schema, body, wal_buf[0..ww.pos], &patched);
    try std.testing.expect(try kati.path.boolean(schema, patched[0..pn], "debug"));

    var doc: [256]u8 = undefined;
    const n = try kati.encodeCompressedNone(&doc, schema.schema_hash, patched[0..pn]);
    const h = try kati.decodeHeader(doc[0..n]);
    try kati.requireHash(h, schema);
    var scratch: [128]u8 = undefined;
    const raw = try kati.unwrap(doc[0..n], &scratch);
    try std.testing.expectEqualStrings("server-a", try kati.path.string(schema, raw, "name"));
}
