const std = @import("std");
const kati = @import("kati");

test "strict unknown field is rejected" {
    const src = "@strict\nconfig X { name: string @required }";
    var p = kati.schema.Parser.init(src);
    const s = try p.parse();
    var buf: [32]u8 = undefined;
    var w = kati.Writer.init(&buf);
    try kati.value.writeFieldHeader(&w, 9, .varint);
    try kati.value.writeUnsigned(&w, 1);
    var views: [4]kati.record.Item = undefined;
    try std.testing.expectError(error.UnknownField, kati.record.walk(s, buf[0..w.pos], &views));
}

test "missing required field" {
    const src = "config X { name: string @required version: u16 }";
    var p = kati.schema.Parser.init(src);
    const s = try p.parse();
    var buf: [32]u8 = undefined;
    var w = kati.Writer.init(&buf);
    try kati.value.writeFieldHeader(&w, 2, .varint);
    try kati.value.writeUnsigned(&w, 3);
    var views: [4]kati.record.Item = undefined;
    try std.testing.expectError(error.MissingField, kati.record.walk(s, buf[0..w.pos], &views));
}

test "rwx bits" {
    try std.testing.expect(kati.rwx.canRead(kati.rwx.R));
    try std.testing.expect(!kati.rwx.canWrite(kati.rwx.R));
    try std.testing.expect(kati.rwx.canWrite(0));
}

test "compressed none blocks wrap a payload" {
    var buf: [128]u8 = undefined;
    var w = kati.Writer.init(&buf);
    try kati.block.writeAllNone(&w, "hello kati");
    var r = kati.Reader.init(buf[0..w.pos]);
    var out: [32]u8 = undefined;
    const n = try kati.block.readAllNone(&r, &out);
    try std.testing.expectEqualStrings("hello kati", out[0..n]);
}
