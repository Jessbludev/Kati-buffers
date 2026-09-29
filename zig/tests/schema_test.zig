const std = @import("std");
const schema = @import("kati").schema;

test "parse strict config" {
    const source =
        "@strict\nconfig AppConfig {\n" ++
        "  name: string @required\n" ++
        "  version: u16\n" ++
        "  debug: bool = false\n" ++
        "  endpoints: array[string] @max(32)\n" ++
        "}\n";
    var p = schema.Parser.init(source);
    const s = try p.parse();
    try std.testing.expectEqualStrings("AppConfig", s.name);
    try std.testing.expect(s.strict);
    try std.testing.expectEqual(@as(usize, 4), s.fields.len);
    try std.testing.expectEqual(@as(u32, 1), s.fields[0].field_id);
    try std.testing.expect(s.fields[0].ann.required);
    try std.testing.expectEqual(@as(?u32, 32), s.fields[3].ann.max);
    try std.testing.expectEqual(@as(?bool, false), s.fields[2].ann.default_bool);
}

test "duplicate explicit field id is rejected" {
    const source = "config X { a: u8 @id(7) b: u8 @id(7) }";
    var p = schema.Parser.init(source);
    try std.testing.expectError(error.DuplicateFieldId, p.parse());
}

test "spec brackets and angle maps hash like Zig spelling" {
    const zig_src =
        "@strict\nconfig AppConfig {\n" ++
        "    name: string @required\n" ++
        "    version: u16\n" ++
        "    debug: bool = false\n" ++
        "    endpoints: array[string] @max(32)\n" ++
        "    limits: map[string,u32]\n" ++
        "    payload: bytes @compress(zstd)\n" ++
        "}\n";
    const spec_src =
        "@strict\nconfig AppConfig {\n" ++
        "    name: string @required\n" ++
        "    version: u16\n" ++
        "    debug: bool = false\n" ++
        "    endpoints: [string] @max(32)\n" ++
        "    limits: map<string, u32>\n" ++
        "    payload: bytes @compress(zstd)\n" ++
        "}\n";
    var a = schema.Parser.init(zig_src);
    var b = schema.Parser.init(spec_src);
    const sa = try a.parse();
    const sb = try b.parse();
    try std.testing.expectEqual(sa.schema_hash, sb.schema_hash);
    try std.testing.expectEqual(@as(u64, 0x3d742323fdeca80b), sa.schema_hash);
}

test "comma-optional fields and rwx" {
    const source =
        "buffer Secure {\n" ++
        "  readme: string @r\n" ++
        "  writes: bytes @rw\n" ++
        "}\n";
    var p = schema.Parser.init(source);
    const s = try p.parse();
    try std.testing.expectEqual(@as(usize, 2), s.fields.len);
    try std.testing.expectEqual(@as(u8, 0b100), s.fields[0].ann.perms);
    try std.testing.expectEqual(@as(u8, 0b110), s.fields[1].ann.perms);
}

test "enum variants and union kind" {
    const source =
        \\enum Color { red = 1 green blue }
        \\union Packet { ping: u32 pong: bool }
    ;
    var p = schema.Parser.init(source);
    const doc = try p.parseDoc();
    try std.testing.expectEqual(@as(usize, 2), doc.defs.len);
    try std.testing.expectEqual(schema.Kind.union_, doc.root.kind);
    try std.testing.expectEqualStrings("Packet", doc.root.name);
    const color = doc.find("Color").?;
    try std.testing.expectEqual(schema.Kind.enum_, color.kind);
    try std.testing.expectEqual(@as(u32, 1), color.fields[0].field_id);
    try std.testing.expectEqual(@as(u32, 2), color.fields[1].field_id);
    try std.testing.expectEqualStrings("green", color.fields[1].name);
}

test "default annotations and hex id" {
    const source =
        \\config X {
        \\  debug: bool = false
        \\  mode: rwx @default(0o644)
        \\  tagged: u8 @id(0x10)
        \\  delta: i16 = -3
        \\}
    ;
    var p = schema.Parser.init(source);
    const s = try p.parse();
    try std.testing.expectEqual(@as(?bool, false), s.fields[0].ann.default_bool);
    try std.testing.expectEqual(@as(?u64, 0o644), s.fields[1].ann.default_uint);
    try std.testing.expectEqual(@as(u32, 16), s.fields[2].field_id);
    try std.testing.expectEqual(@as(?i64, -3), s.fields[3].ann.default_sint);
}
