const std = @import("std");
const kati = @import("kati");

const schema_src =
    \\@strict
    \\config AppConfig {
    \\    name: string @required
    \\    version: u16
    \\    debug: bool = false
    \\    endpoints: array[string] @max(32)
    \\}
;

const pretty_src =
    \\#PBR 1
    \\.AppConfig {
    \\  name = "server-a"
    \\  version = 0x0104
    \\  debug = false
    \\  endpoints = ["a.io", "b.io"]
    \\}
;

test "assemble then walk and disassemble" {
    var parser = kati.schema.Parser.init(schema_src);
    const schema = try parser.parse();
    var asm_ = kati.pretty.Assembler.init(pretty_src);
    try asm_.parse();
    var bin: [1024]u8 = undefined;
    const n = try asm_.encode(schema, &bin);
    const h = try kati.decodeHeader(bin[0..n]);
    try std.testing.expectEqual(schema.schema_hash, h.schema_hash);
    const payload = try kati.payloadOf(bin[0..n], h);

    var views: [8]kati.record.Item = undefined;
    const count = try kati.record.walk(schema, payload, &views);
    try std.testing.expectEqual(@as(usize, 4), count);
    try std.testing.expectEqualStrings("name", views[0].field.?.name);

    var text: [1024]u8 = undefined;
    const m = try kati.pretty.disassemble(schema, payload, &text);
    try std.testing.expect(std.mem.indexOf(u8, text[0..m], "server-a") != null);
    try std.testing.expect(std.mem.indexOf(u8, text[0..m], "a.io") != null);
}

test "default bool is captured" {
    var p = kati.schema.Parser.init(schema_src);
    const s = try p.parse();
    try std.testing.expectEqual(@as(?bool, false), s.fields[2].ann.default_bool);
}

test "union encodes exactly one variant" {
    const src = "union Packet { ping: u32 pong: bool }";
    var parser = kati.schema.Parser.init(src);
    const schema = try parser.parse();
    try std.testing.expectEqual(kati.schema.Kind.union_, schema.kind);
    var asm_ = kati.pretty.Assembler.init(".Packet { ping = 7 }");
    try asm_.parse();
    var bin: [256]u8 = undefined;
    const n = try asm_.encode(schema, &bin);
    const h = try kati.decodeHeader(bin[0..n]);
    const payload = try kati.payloadOf(bin[0..n], h);
    var r = kati.Reader.init(payload);
    const fh = try kati.value.readFieldHeader(&r);
    try std.testing.expectEqual(@as(u32, 1), fh.field_id);
    try std.testing.expectEqual(@as(u64, 7), try kati.value.readUnsigned(&r));
    try std.testing.expect(r.atEnd());
}

test "omitted bool default is written" {
    var parser = kati.schema.Parser.init(schema_src);
    const schema = try parser.parse();
    var asm_ = kati.pretty.Assembler.init(
        \\#PBR 1
        \\.AppConfig {
        \\  name = "server-a"
        \\}
    );
    try asm_.parse();
    var bin: [256]u8 = undefined;
    const n = try asm_.encode(schema, &bin);
    const h = try kati.decodeHeader(bin[0..n]);
    const payload = try kati.payloadOf(bin[0..n], h);
    try std.testing.expect(!(try kati.path.boolean(schema, payload, "debug")));
}

test "nested struct and enum roundtrip" {
    const src =
        \\enum Color { red = 1 green blue }
        \\struct Point { x: i16 y: i16 }
        \\config Draw { color: Color origin: Point name: string @required }
    ;
    var parser = kati.schema.Parser.init(src);
    const doc = try parser.parseDoc();
    var asm_ = kati.pretty.Assembler.init(".Draw { color = green origin = { x = -2 y = 9 } name = \"dot\" }");
    try asm_.parse();
    var bin: [512]u8 = undefined;
    const n = try asm_.encodeDoc(doc, &bin);
    const h = try kati.decodeHeader(bin[0..n]);
    const payload = try kati.payloadOf(bin[0..n], h);
    try std.testing.expectEqual(@as(u64, 2), try kati.path.unsigned(doc.root, payload, "color"));
    try std.testing.expectEqual(@as(i64, -2), try kati.path.signedDoc(doc, payload, "origin.x"));
    var text: [512]u8 = undefined;
    const m = try kati.pretty.disassembleDoc(doc, payload, &text);
    try std.testing.expect(std.mem.indexOf(u8, text[0..m], "green") != null);
    try std.testing.expect(std.mem.indexOf(u8, text[0..m], "-2") != null);
}

test "hex field id parses" {
    var p = kati.schema.Parser.init("config X { a: u8 @id(0x10) }");
    const s = try p.parse();
    try std.testing.expectEqual(@as(u32, 16), s.fields[0].field_id);
}
