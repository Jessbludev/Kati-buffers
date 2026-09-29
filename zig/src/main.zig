const std = @import("std");
const kati = @import("kati");

pub fn main(init: std.process.Init) !void {
    var it = std.process.Args.Iterator.init(init.minimal.args);
    _ = it.next();
    const command = it.next() orelse {
        usage();
        return;
    };

    if (std.mem.eql(u8, command, "schema-hash")) {
        const path = it.next() orelse return usage_error("missing schema file");
        try schemaHash(init, path);
        return;
    }
    if (std.mem.eql(u8, command, "assemble") or std.mem.eql(u8, command, "compile") or std.mem.eql(u8, command, "asm")) {
        const schema_path = it.next() orelse return usage_error("missing schema file");
        const pretty_path = it.next() orelse return usage_error("missing pretty file");
        try assemble(init, schema_path, pretty_path);
        return;
    }
    if (std.mem.eql(u8, command, "disasm")) {
        const schema_path = it.next() orelse return usage_error("missing schema file");
        const bin_path = it.next() orelse return usage_error("missing binary file");
        try disasm(init, schema_path, bin_path);
        return;
    }
    if (std.mem.eql(u8, command, "check")) {
        const schema_path = it.next() orelse return usage_error("missing schema file");
        const bin_path = it.next() orelse return usage_error("missing binary file");
        try check(init, schema_path, bin_path);
        return;
    }
    if (std.mem.eql(u8, command, "get")) {
        const schema_path = it.next() orelse return usage_error("missing schema file");
        const bin_path = it.next() orelse return usage_error("missing binary file");
        const field_path = it.next() orelse return usage_error("missing field path");
        try getField(init, schema_path, bin_path, field_path);
        return;
    }
    if (std.mem.eql(u8, command, "dump")) {
        const path = it.next() orelse return usage_error("missing file");
        try dump(init, path);
        return;
    }
    if (std.mem.eql(u8, command, "hash")) {
        const path = it.next() orelse return usage_error("missing schema file");
        try schemaHash(init, path);
        return;
    }
    if (std.mem.eql(u8, command, "inspect")) {
        const path = it.next() orelse return usage_error("missing file");
        try inspect(init, path);
        return;
    }
    if (std.mem.eql(u8, command, "version")) {
        var buf: [128]u8 = undefined;
        var w = std.Io.File.stdout().writer(init.io, &buf);
        try w.interface.print("kati {s} (pbr v{d})\n", .{ kati.LIB_VERSION, kati.VERSION });
        try w.interface.flush();
        return;
    }
    if (std.mem.eql(u8, command, "help")) {
        usage();
        return;
    }
    return usage_error("unknown command");
}

fn readFile(init: std.process.Init, path: []const u8, limit: usize) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(init.io, path, init.gpa, .limited(limit));
}

fn schemaHash(init: std.process.Init, path: []const u8) !void {
    const source = try readFile(init, path, 1024 * 1024);
    defer init.gpa.free(source);
    var parser = kati.schema.Parser.init(source);
    const schema = try parser.parse();
    var buf: [256]u8 = undefined;
    var w = std.Io.File.stdout().writer(init.io, &buf);
    try w.interface.print("schema: {s}\nhash: 0x{x:0>16}\nfields: {d}\nstrict: {}\n", .{
        schema.name, schema.schema_hash, schema.fields.len, schema.strict,
    });
    try w.interface.flush();
}

fn assemble(init: std.process.Init, schema_path: []const u8, pretty_path: []const u8) !void {
    const schema_src = try readFile(init, schema_path, 1024 * 1024);
    defer init.gpa.free(schema_src);
    const pretty_src = try readFile(init, pretty_path, 1024 * 1024);
    defer init.gpa.free(pretty_src);
    var parser = kati.schema.Parser.init(schema_src);
    const doc = try parser.parseDoc();
    var asm_ = kati.pretty.Assembler.init(pretty_src);
    try asm_.parse();
    var out: [64 * 1024]u8 = undefined;
    const n = try asm_.encodeDoc(doc, &out);
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writer(init.io, &buf);
    try w.interface.writeAll(out[0..n]);
    try w.interface.flush();
}

fn disasm(init: std.process.Init, schema_path: []const u8, bin_path: []const u8) !void {
    const schema_src = try readFile(init, schema_path, 1024 * 1024);
    defer init.gpa.free(schema_src);
    const data = try readFile(init, bin_path, 64 * 1024 * 1024);
    defer init.gpa.free(data);
    var parser = kati.schema.Parser.init(schema_src);
    const doc = try parser.parseDoc();
    const h = try kati.decodeHeader(data);
    try kati.requireHash(h, doc.root);
    var scratch: [64 * 1024]u8 = undefined;
    const payload = try kati.unwrap(data, &scratch);
    var text: [64 * 1024]u8 = undefined;
    const n = try kati.pretty.disassembleDoc(doc, payload, &text);
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writer(init.io, &buf);
    try w.interface.writeAll(text[0..n]);
    try w.interface.flush();
}

fn check(init: std.process.Init, schema_path: []const u8, bin_path: []const u8) !void {
    const schema_src = try readFile(init, schema_path, 1024 * 1024);
    defer init.gpa.free(schema_src);
    const data = try readFile(init, bin_path, 64 * 1024 * 1024);
    defer init.gpa.free(data);
    var parser = kati.schema.Parser.init(schema_src);
    const schema = try parser.parse();
    const h = try kati.decodeHeader(data);
    var buf: [256]u8 = undefined;
    var w = std.Io.File.stdout().writer(init.io, &buf);
    if (kati.checkHash(h, schema)) {
        try w.interface.print("ok {s} 0x{x:0>16}\n", .{ schema.name, schema.schema_hash });
        try w.interface.flush();
        return;
    }
    try w.interface.print("mismatch schema=0x{x:0>16} file=0x{x:0>16}\n", .{ schema.schema_hash, h.schema_hash });
    try w.interface.flush();
    return error.HashMismatch;
}

fn inspect(init: std.process.Init, path: []const u8) !void {
    const data = try readFile(init, path, 64 * 1024 * 1024);
    defer init.gpa.free(data);
    const h = try kati.decodeHeader(data);
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writer(init.io, &buf);
    const out = &w.interface;
    try out.print("format: PBR v{d}\nlib: {s}\nflags: 0x{x:0>2}\nschema_hash: 0x{x:0>16}\npayload_len: {d}\nheader_len: {d}\n", .{
        kati.VERSION, kati.LIB_VERSION, @as(u8, @bitCast(h.flags)), h.schema_hash, h.payload_len, h.header_len,
    });
    const payload = try kati.payloadOf(data, h);
    if (h.flags.compressed) {
        try out.print("blocks:\n", .{});
        var r = kati.Reader.init(payload);
        var i: usize = 0;
        while (!r.atEnd()) : (i += 1) {
            const b = try kati.block.read(&r);
            try out.print("  [{d}] algo={s} raw={d} comp={d} crc=0x{x:0>8}\n", .{
                i, @tagName(b.algo), b.raw_len, b.data.len, b.crc,
            });
        }
    } else {
        try out.print("fields:\n", .{});
        var r = kati.Reader.init(payload);
        while (!r.atEnd()) {
            const start = r.pos;
            const fh = try kati.value.readFieldHeader(&r);
            try kati.value.skipValue(&r, fh.wire_type);
            try out.print("  id={d} wire={s} size={d}\n", .{
                fh.field_id, @tagName(fh.wire_type), r.pos - start,
            });
        }
    }
    try out.flush();
}

fn getField(init: std.process.Init, schema_path: []const u8, bin_path: []const u8, field_path: []const u8) !void {
    const schema_src = try readFile(init, schema_path, 1024 * 1024);
    defer init.gpa.free(schema_src);
    const data = try readFile(init, bin_path, 64 * 1024 * 1024);
    defer init.gpa.free(data);
    var parser = kati.schema.Parser.init(schema_src);
    const doc = try parser.parseDoc();
    const h = try kati.decodeHeader(data);
    try kati.requireHash(h, doc.root);
    var scratch: [64 * 1024]u8 = undefined;
    const payload = try kati.unwrap(data, &scratch);
    const view = try kati.path.at(doc, payload, field_path);
    var text: [4096]u8 = undefined;
    const n = try kati.pretty.formatValueDoc(doc, view.ty, view.item.raw, &text);
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writer(init.io, &buf);
    try w.interface.writeAll(text[0..n]);
    try w.interface.writeAll("\n");
    try w.interface.flush();
}

fn dump(init: std.process.Init, path: []const u8) !void {
    const data = try readFile(init, path, 64 * 1024 * 1024);
    defer init.gpa.free(data);
    const h = try kati.decodeHeader(data);
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writer(init.io, &buf);
    const out = &w.interface;
    try out.print("# {d} bytes  header {d}  payload {d}  hash 0x{x:0>16}\n", .{
        data.len, h.header_len, h.payload_len, h.schema_hash,
    });
    const digits = "0123456789abcdef";
    var i: usize = 0;
    while (i < data.len) {
        try out.print("{x:0>8}  ", .{i});
        var col: usize = 0;
        while (col < 16) : (col += 1) {
            if (i + col < data.len) {
                const b = data[i + col];
                const pair = [_]u8{ digits[b >> 4], digits[b & 0xf] };
                try out.writeAll(&pair);
                try out.writeByte(' ');
            } else {
                try out.writeAll("   ");
            }
            if (col == 7) try out.writeByte(' ');
        }
        try out.writeAll(" |");
        col = 0;
        while (col < 16 and i + col < data.len) : (col += 1) {
            const b = data[i + col];
            try out.writeByte(if (b >= 0x20 and b < 0x7f) b else '.');
        }
        try out.writeAll("|\n");
        i += 16;
    }
    try out.flush();
}

fn usage_error(msg: []const u8) !void {
    std.log.err("{s}", .{msg});
    usage();
    return error.InvalidUsage;
}

fn usage() void {
    std.debug.print(
        \\kati — .pbr tool
        \\
        \\Usage:
        \\  kati version
        \\  kati inspect <file.pbr>
        \\  kati dump    <file.pbr>
        \\  kati schema-hash <schema.pbr>
        \\  kati hash    <schema.pbr>
        \\  kati assemble <schema.pbr> <pretty.pbr>
        \\  kati compile  <schema.pbr> <pretty.pbr>
        \\  kati disasm   <schema.pbr> <file.pbr>
        \\  kati check    <schema.pbr> <file.pbr>
        \\  kati get      <schema.pbr> <file.pbr> <path>
        \\
    , .{});
}
