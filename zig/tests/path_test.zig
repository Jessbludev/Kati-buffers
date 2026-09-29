const std = @import("std");
const kati = @import("kati");

test "dotted map and array paths" {
    const src =
        \\@strict
        \\config AppConfig {
        \\    name: string @required
        \\    endpoints: array[string] @max(32)
        \\    limits: map[string, u32]
        \\}
    ;
    var parser = kati.schema.Parser.init(src);
    const schema = try parser.parse();

    var items: [32]u8 = undefined;
    var iw = kati.Writer.init(&items);
    try kati.value.writeBytes(&iw, "a.io");
    try kati.value.writeBytes(&iw, "b.io");

    var map_items: [32]u8 = undefined;
    var mw = kati.Writer.init(&map_items);
    try kati.value.writeBytes(&mw, "cpu");
    try kati.value.writeUnsigned(&mw, 4);
    try kati.value.writeBytes(&mw, "ram");
    try kati.value.writeUnsigned(&mw, 16);

    var buf: [128]u8 = undefined;
    var b = kati.record.Builder.init(&buf, schema);
    try b.putString("name", "server-a");
    try b.putPacked("endpoints", 2, items[0..iw.pos]);
    try b.putPacked("limits", 2, map_items[0..mw.pos]);
    const body = try b.finish();

    try std.testing.expectEqualStrings("server-a", try kati.path.string(schema, body, "AppConfig.name"));
    try std.testing.expectEqualStrings("b.io", try kati.path.string(schema, body, "endpoints.1"));
    try std.testing.expectEqual(@as(u64, 4), try kati.path.unsigned(schema, body, "limits.cpu"));
    try std.testing.expectEqual(@as(u64, 16), try kati.path.unsigned(schema, body, "limits.ram"));
}

test "nested struct path" {
    const src =
        \\struct Inner { n: i32 }
        \\config Root { child: Inner name: string @required }
    ;
    var parser = kati.schema.Parser.init(src);
    const doc = try parser.parseDoc();
    var asm_ = kati.pretty.Assembler.init(".Root { child = { n = -7 } name = \"x\" }");
    try asm_.parse();
    var bin: [256]u8 = undefined;
    const n = try asm_.encodeDoc(doc, &bin);
    const h = try kati.decodeHeader(bin[0..n]);
    const payload = try kati.payloadOf(bin[0..n], h);
    try std.testing.expectEqual(@as(i64, -7), try kati.path.signedDoc(doc, payload, "child.n"));
    try std.testing.expectEqualStrings("x", try kati.path.stringDoc(doc, payload, "Root.name"));
}
