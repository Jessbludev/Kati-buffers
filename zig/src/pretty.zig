//! Pretty assembler: `#PBR` text → typed payload, no allocator.
//! Nested maps/arrays of primitives are enough for the AppConfig dialect.

const io = @import("io.zig");
const schema = @import("schema.zig");
const value = @import("value.zig");
const record = @import("record.zig");

pub const Error = io.Error || schema.Error || value.Error || record.Error || error{
    InvalidPretty, HexOdd,
};

pub const MAX_NODES: usize = 256;

pub const Kind = enum { none, bool_, uint, string, hex, array, map };

pub const Node = struct {
    kind: Kind = .none,
    u: u64 = 0,
    b: bool = false,
    neg: bool = false,
    text: []const u8 = "",
    start: u16 = 0,
    count: u16 = 0,
};

pub const Slot = struct {
    name: []const u8 = "",
    node: u16 = 0,
    next: u16 = 0xffff,
};

const TokenKind = enum {
    eof, ident, number, string, at, dot,
    lbrace, rbrace, lbracket, rbracket, colon, equal, comma,
};
const Token = struct { kind: TokenKind, text: []const u8, uint: u64 = 0, neg: bool = false };

pub const Assembler = struct {
    source: []const u8,
    pos: usize = 0,
    pending: ?Token = null,
    nodes: [MAX_NODES]Node = undefined,
    slots: [MAX_NODES]Slot = undefined,
    ncount: usize = 0,
    scount: usize = 0,
    root_name: []const u8 = "",
    root: u16 = 0,
    defs: []const schema.Def = &.{},

    pub fn init(source: []const u8) Assembler {
        return .{ .source = source };
    }

    pub fn parse(self: *Assembler) Error!void {
        var t = try self.take();
        if (t.kind == .ident and eq(t.text, "PBR")) {
            if ((try self.peek()).kind == .number) _ = try self.take();
            t = try self.take();
        }
        while (t.kind == .at) {
            _ = try self.take();
            while (true) {
                const n = try self.peek();
                if (n.kind != .ident) break;
                _ = try self.take();
                if ((try self.peek()).kind == .equal) {
                    _ = try self.take();
                    _ = try self.take();
                }
            }
            t = try self.take();
        }
        if (t.kind == .dot) {
            const n = try self.take();
            if (n.kind != .ident) return error.InvalidPretty;
            self.root_name = n.text;
            t = try self.take();
        }
        if (t.kind != .lbrace) return error.InvalidPretty;
        self.pending = t;
        self.root = try self.parseValue();
    }

    fn parseValue(self: *Assembler) Error!u16 {
        const t = try self.take();
        if (t.kind == .string) return self.push(.{ .kind = .string, .text = t.text });
        if (t.kind == .number) return self.push(.{ .kind = .uint, .u = t.uint, .neg = t.neg });
        if (t.kind == .ident) {
            if (eq(t.text, "true")) return self.push(.{ .kind = .bool_, .b = true });
            if (eq(t.text, "false")) return self.push(.{ .kind = .bool_, .b = false });
            if (eq(t.text, "h") or eq(t.text, "hex")) {
                const s = try self.take();
                if (s.kind != .string) return error.InvalidPretty;
                return self.push(.{ .kind = .hex, .text = s.text });
            }
            if (eq(t.text, "f32") or eq(t.text, "f64")) {
                if ((try self.peek()).kind == .colon) _ = try self.take();
                const n = try self.take();
                if (n.kind != .number) return error.InvalidPretty;
                return self.push(.{ .kind = .uint, .u = n.uint });
            }
            if (eq(t.text, "rwx")) {
                if ((try self.peek()).kind == .colon) _ = try self.take();
                const n = try self.take();
                if (n.kind != .number) return error.InvalidPretty;
                const mode = parseOctal(n.text) orelse n.uint;
                return self.push(.{ .kind = .uint, .u = mode });
            }
            if ((try self.peek()).kind == .lbrace) {
                const inner = try self.parseValue();
                const slot_i = try self.pushSlot(.{ .name = t.text, .node = inner });
                return self.push(.{ .kind = .map, .start = slot_i, .count = 1 });
            }
            return self.push(.{ .kind = .string, .text = t.text });
        }
        if (t.kind == .lbracket) {
            var start: u16 = 0xffff;
            var prev: u16 = 0xffff;
            var count: u16 = 0;
            while ((try self.peek()).kind != .rbracket and (try self.peek()).kind != .eof) {
                const v = try self.parseValue();
                const slot_i = try self.pushSlot(.{ .name = "", .node = v });
                if (count == 0) start = slot_i else self.slots[prev].next = slot_i;
                prev = slot_i;
                count += 1;
                if ((try self.peek()).kind == .comma) _ = try self.take();
            }
            try self.expect(.rbracket);
            return self.push(.{ .kind = .array, .start = start, .count = count });
        }
        if (t.kind == .lbrace) {
            var start: u16 = 0xffff;
            var prev: u16 = 0xffff;
            var count: u16 = 0;
            while ((try self.peek()).kind != .rbrace and (try self.peek()).kind != .eof) {
                const k = try self.take();
                if (k.kind != .ident and k.kind != .string) return error.InvalidPretty;
                const sep = try self.take();
                if (sep.kind != .equal and sep.kind != .colon) return error.InvalidPretty;
                const v = try self.parseValue();
                const slot_i = try self.pushSlot(.{ .name = k.text, .node = v });
                if (count == 0) start = slot_i else self.slots[prev].next = slot_i;
                prev = slot_i;
                count += 1;
                if ((try self.peek()).kind == .comma) _ = try self.take();
            }
            try self.expect(.rbrace);
            return self.push(.{ .kind = .map, .start = start, .count = count });
        }
        return error.InvalidPretty;
    }

    fn push(self: *Assembler, n: Node) Error!u16 {
        if (self.ncount >= MAX_NODES) return error.TooManyFields;
        const i: u16 = @intCast(self.ncount);
        self.nodes[self.ncount] = n;
        self.ncount += 1;
        return i;
    }

    fn pushSlot(self: *Assembler, s: Slot) Error!u16 {
        if (self.scount >= MAX_NODES) return error.TooManyFields;
        const i: u16 = @intCast(self.scount);
        self.slots[self.scount] = s;
        self.scount += 1;
        return i;
    }

    fn slotAt(self: *Assembler, start: u16, index: u16) Slot {
        var s = start;
        var i: u16 = 0;
        while (i < index) : (i += 1) s = self.slots[s].next;
        return self.slots[s];
    }

    fn lookup(self: *Assembler, rec: u16, name: []const u8) ?u16 {
        const n = self.nodes[rec];
        if (n.kind != .map or n.count == 0) return null;
        var s = n.start;
        var i: u16 = 0;
        while (i < n.count) : (i += 1) {
            const slot = self.slots[s];
            if (eq(slot.name, name)) return slot.node;
            s = slot.next;
        }
        return null;
    }

    fn findDef(self: *Assembler, name: []const u8) ?schema.Def {
        for (self.defs) |d| {
            if (eq(d.name, name)) return d;
        }
        return null;
    }

    fn unwrapNamed(self: *Assembler, node: u16, type_name: []const u8) u16 {
        const n = self.nodes[node];
        if (n.kind == .map and n.count == 1) {
            const slot = self.slots[n.start];
            if (eq(slot.name, type_name)) return slot.node;
        }
        return node;
    }

    fn writeEnum(self: *Assembler, w: *io.Writer, type_name: []const u8, node: u16) Error!void {
        const def = self.findDef(type_name) orelse return error.UnsupportedType;
        const n = self.nodes[node];
        if (n.kind == .uint) {
            if (n.neg) return error.TypeMismatch;
            try value.writeUnsigned(w, n.u);
            return;
        }
        if (n.kind != .string) return error.TypeMismatch;
        for (def.fields) |v| {
            if (eq(v.name, n.text)) {
                try value.writeUnsigned(w, v.field_id);
                return;
            }
        }
        return error.TypeMismatch;
    }

    fn writeDefault(self: *Assembler, w: *io.Writer, f: schema.Field) Error!bool {
        if (f.ann.default_bool) |b| {
            try value.writeFieldHeader(w, f.field_id, .varint);
            try value.writeBool(w, b);
            return true;
        }
        if (f.ann.default_string) |s| {
            try value.writeFieldHeader(w, f.field_id, record.wireOf(f.ty));
            switch (f.ty) {
                .named => |named| {
                    if (named.kind != .enum_) return error.TypeMismatch;
                    const def = self.findDef(named.name) orelse return error.UnsupportedType;
                    for (def.fields) |v| {
                        if (eq(v.name, s)) {
                            try value.writeUnsigned(w, v.field_id);
                            return true;
                        }
                    }
                    return error.TypeMismatch;
                },
                .primitive => |p| switch (p) {
                    .string, .bytes, .fn_ => try value.writeBytes(w, s),
                    else => return error.TypeMismatch,
                },
                else => return error.TypeMismatch,
            }
            return true;
        }
        if (f.ann.default_sint) |i| {
            try value.writeFieldHeader(w, f.field_id, .varint);
            switch (f.ty) {
                .primitive => |p| try record.rangeSigned(p, i),
                else => return error.TypeMismatch,
            }
            try value.writeSigned(w, i);
            return true;
        }
        if (f.ann.default_uint) |u| {
            try value.writeFieldHeader(w, f.field_id, record.wireOf(f.ty));
            switch (f.ty) {
                .primitive => |p| {
                    try record.rangeUnsigned(p, u);
                    switch (p) {
                        .f32 => try value.writeF32(w, @bitCast(@as(u32, @truncate(u)))),
                        .f64 => try value.writeF64(w, @bitCast(u)),
                        .i8, .i16, .i32, .i64, .timestamp, .duration => {
                            try record.rangeSigned(p, @intCast(u));
                            try value.writeSigned(w, @intCast(u));
                        },
                        else => try value.writeUnsigned(w, u),
                    }
                },
                .named => |named| {
                    if (named.kind != .enum_) return error.TypeMismatch;
                    try value.writeUnsigned(w, u);
                },
                else => return error.TypeMismatch,
            }
            return true;
        }
        return false;
    }

    pub fn encode(self: *Assembler, s: schema.Struct, out: []u8) Error!usize {
        return self.encodeInto(s, &.{}, out);
    }

    pub fn encodeDoc(self: *Assembler, doc: schema.Doc, out: []u8) Error!usize {
        return self.encodeInto(doc.root, doc.defs, out);
    }

    fn encodeInto(self: *Assembler, s: schema.Struct, defs: []const schema.Def, out: []u8) Error!usize {
        self.defs = defs;
        var payload: [64 * 1024]u8 = undefined;
        var pw = io.Writer.init(&payload);
        try self.encodeStruct(&pw, s, self.root);
        var w = io.Writer.init(out);
        const n = encodeHeader(&w, s.schema_hash, pw.pos) catch return error.Truncated;
        _ = n;
        try w.bytes(payload[0..pw.pos]);
        return w.pos;
    }

    fn encodeStruct(self: *Assembler, w: *io.Writer, s: schema.Struct, rec: u16) Error!void {
        if (s.kind == .union_) {
            var chosen: ?schema.Field = null;
            var node: u16 = 0;
            for (s.fields) |f| {
                if (self.lookup(rec, f.name)) |n| {
                    if (chosen != null) return error.TypeMismatch;
                    chosen = f;
                    node = n;
                }
            }
            const f = chosen orelse return error.MissingField;
            try value.writeFieldHeader(w, f.field_id, record.wireOf(f.ty));
            try self.writeBare(w, f.ty, node);
            return;
        }
        for (s.fields) |f| {
            const node = self.lookup(rec, f.name) orelse {
                if (try self.writeDefault(w, f)) continue;
                if (f.ann.required) return error.MissingField;
                continue;
            };
            try value.writeFieldHeader(w, f.field_id, record.wireOf(f.ty));
            try self.writeBare(w, f.ty, node);
        }
    }

    fn writeBare(self: *Assembler, w: *io.Writer, ty: schema.Type, node: u16) Error!void {
        const n = self.nodes[node];
        switch (ty) {
            .array => |inner| {
                if (n.kind != .array) return error.TypeMismatch;
                var inner_buf: [2048]u8 = undefined;
                var iw = io.Writer.init(&inner_buf);
                try iw.varint(n.count);
                var i: u16 = 0;
                while (i < n.count) : (i += 1) {
                    try self.writeBare(&iw, .{ .primitive = inner }, self.slotAt(n.start, i).node);
                }
                try value.writeBytes(w, inner_buf[0..iw.pos]);
            },
            .map => |m| {
                if (n.kind != .map) return error.TypeMismatch;
                var inner_buf: [2048]u8 = undefined;
                var iw = io.Writer.init(&inner_buf);
                try iw.varint(n.count);
                var i: u16 = 0;
                while (i < n.count) : (i += 1) {
                    const slot = self.slotAt(n.start, i);
                    switch (m.key) {
                        .string => try value.writeBytes(&iw, slot.name),
                        else => return error.UnsupportedType,
                    }
                    try self.writeBare(&iw, .{ .primitive = m.value }, slot.node);
                }
                try value.writeBytes(w, inner_buf[0..iw.pos]);
            },
            .named => |named| {
                const node_unwrapped = self.unwrapNamed(node, named.name);
                if (named.kind == .enum_) {
                    try self.writeEnum(w, named.name, node_unwrapped);
                    return;
                }
                const def = self.findDef(named.name) orelse return error.UnsupportedType;
                var inner_buf: [4096]u8 = undefined;
                var iw = io.Writer.init(&inner_buf);
                try self.encodeStruct(&iw, def.asStruct(), node_unwrapped);
                try value.writeBytes(w, inner_buf[0..iw.pos]);
            },
            .primitive => |p| try self.writePrim(w, p, node),
        }
    }

    fn writePrim(self: *Assembler, w: *io.Writer, p: schema.Primitive, node: u16) Error!void {
        const n = self.nodes[node];
        switch (p) {
            .bool => {
                if (n.kind != .bool_) return error.TypeMismatch;
                try value.writeBool(w, n.b);
            },
            .string => {
                const text = switch (n.kind) {
                    .string => n.text,
                    else => return error.TypeMismatch,
                };
                try value.writeBytes(w, text);
            },
            .bytes, .fn_, .uuid => {
                if (n.kind == .hex) {
                    var tmp: [256]u8 = undefined;
                    const m = try decodeHex(n.text, &tmp);
                    try value.writeBytes(w, tmp[0..m]);
                    return;
                }
                if (n.kind == .string) {
                    try value.writeBytes(w, n.text);
                    return;
                }
                return error.TypeMismatch;
            },
            .f32 => {
                if (n.kind != .uint) return error.TypeMismatch;
                try value.writeF32(w, @bitCast(@as(u32, @truncate(n.u))));
            },
            .f64 => {
                if (n.kind != .uint) return error.TypeMismatch;
                try value.writeF64(w, @bitCast(n.u));
            },
            .i8, .i16, .i32, .i64, .timestamp, .duration => {
                if (n.kind != .uint) return error.TypeMismatch;
                var v: i64 = 0;
                if (n.u > 9223372036854775807) return error.Overflow;
                v = @intCast(n.u);
                if (n.neg) v = -v;
                try record.rangeSigned(p, v);
                try value.writeSigned(w, v);
            },
            else => {
                if (n.neg) return error.TypeMismatch;
                if (n.kind == .uint) {
                    try record.rangeUnsigned(p, n.u);
                    try value.writeUnsigned(w, n.u);
                    return;
                }
                if (n.kind == .bool_) {
                    try value.writeUnsigned(w, if (n.b) 1 else 0);
                    return;
                }
                return error.TypeMismatch;
            },
        }
    }

    fn encodeHeader(w: *io.Writer, hash: u64, payload_len: usize) io.Error!usize {
        try w.bytes("PBR\x01");
        try w.byte(0);
        try w.u64le(hash);
        try w.varint(payload_len);
        return w.pos;
    }

    fn peek(self: *Assembler) Error!Token {
        const t = try self.take();
        self.pending = t;
        return t;
    }

    fn expect(self: *Assembler, kind: TokenKind) Error!void {
        if ((try self.take()).kind != kind) return error.InvalidPretty;
    }

    fn take(self: *Assembler) Error!Token {
        if (self.pending) |t| {
            self.pending = null;
            return t;
        }
        while (self.pos < self.source.len) {
            const c = self.source[self.pos];
            if (c == ' ' or c == '\n' or c == '\r' or c == '\t') {
                self.pos += 1;
                continue;
            }
            if (c == '#' and self.pos + 4 <= self.source.len and eq(self.source[self.pos .. self.pos + 4], "#PBR")) {
                self.pos += 1;
                const start = self.pos;
                self.pos += 3;
                return .{ .kind = .ident, .text = self.source[start..self.pos] };
            }
            if (c == '#' or (c == '/' and self.pos + 1 < self.source.len and self.source[self.pos + 1] == '/')) {
                while (self.pos < self.source.len and self.source[self.pos] != '\n') self.pos += 1;
                continue;
            }
            break;
        }
        if (self.pos >= self.source.len) return .{ .kind = .eof, .text = "" };
        const start = self.pos;
        const c = self.source[self.pos];
        self.pos += 1;
        return switch (c) {
            '@' => .{ .kind = .at, .text = self.source[start..self.pos] },
            '.' => .{ .kind = .dot, .text = self.source[start..self.pos] },
            '{' => .{ .kind = .lbrace, .text = self.source[start..self.pos] },
            '}' => .{ .kind = .rbrace, .text = self.source[start..self.pos] },
            '[' => .{ .kind = .lbracket, .text = self.source[start..self.pos] },
            ']' => .{ .kind = .rbracket, .text = self.source[start..self.pos] },
            ':' => .{ .kind = .colon, .text = self.source[start..self.pos] },
            '=' => .{ .kind = .equal, .text = self.source[start..self.pos] },
            ',' => .{ .kind = .comma, .text = self.source[start..self.pos] },
            '-' => blk: {
                if (self.pos >= self.source.len or !isDigit(self.source[self.pos])) return error.InvalidToken;
                const num_start = self.pos;
                while (self.pos < self.source.len and isDigit(self.source[self.pos])) self.pos += 1;
                const text = self.source[num_start..self.pos];
                break :blk .{ .kind = .number, .text = text, .uint = parseDec(text), .neg = true };
            },
            '"' => blk: {
                while (self.pos < self.source.len and self.source[self.pos] != '"') self.pos += 1;
                if (self.pos >= self.source.len) return error.UnexpectedEof;
                self.pos += 1;
                break :blk .{ .kind = .string, .text = self.source[start + 1 .. self.pos - 1] };
            },
            '0'...'9' => blk: {
                if (c == '0' and self.pos < self.source.len) {
                    const p = self.source[self.pos];
                    if (p == 'x' or p == 'X' or p == 'o' or p == 'b') {
                        self.pos += 1;
                        while (self.pos < self.source.len and isHexish(self.source[self.pos], p)) self.pos += 1;
                        const text = self.source[start..self.pos];
                        break :blk .{ .kind = .number, .text = text, .uint = parsePrefixed(text) };
                    }
                }
                while (self.pos < self.source.len and isDigit(self.source[self.pos])) self.pos += 1;
                const text = self.source[start..self.pos];
                break :blk .{ .kind = .number, .text = text, .uint = parseDec(text) };
            },
            'a'...'z', 'A'...'Z', '_' => blk: {
                while (self.pos < self.source.len and isIdent(self.source[self.pos])) self.pos += 1;
                break :blk .{ .kind = .ident, .text = self.source[start..self.pos] };
            },
            else => return error.InvalidToken,
        };
    }
};

pub fn disassemble(s: schema.Struct, payload: []const u8, out: []u8) Error!usize {
    return disassembleInto(s, &.{}, payload, out);
}

pub fn disassembleDoc(doc: schema.Doc, payload: []const u8, out: []u8) Error!usize {
    return disassembleInto(doc.root, doc.defs, payload, out);
}

pub fn formatValue(ty: schema.Type, raw: []const u8, out: []u8) Error!usize {
    var pos: usize = 0;
    try writePrettyValue(&pos, out, ty, raw, &.{});
    return pos;
}

pub fn formatValueDoc(doc: schema.Doc, ty: schema.Type, raw: []const u8, out: []u8) Error!usize {
    var pos: usize = 0;
    try writePrettyValue(&pos, out, ty, raw, doc.defs);
    return pos;
}

fn disassembleInto(s: schema.Struct, defs: []const schema.Def, payload: []const u8, out: []u8) Error!usize {
    var pos: usize = 0;
    try append(&pos, out, "#PBR 1\n@schema hash=0x");
    try appendHex64(&pos, out, s.schema_hash);
    try append(&pos, out, "\n.");
    try append(&pos, out, s.name);
    try append(&pos, out, " {\n");
    var r = io.Reader.init(payload);
    while (try record.next(&r, s)) |item| {
        if (item.field) |f| {
            try append(&pos, out, "  ");
            try append(&pos, out, f.name);
            try append(&pos, out, " = ");
            try writePrettyValue(&pos, out, f.ty, item.raw, defs);
            try append(&pos, out, "\n");
        }
    }
    try append(&pos, out, "}\n");
    return pos;
}

fn writePrettyValue(pos: *usize, out: []u8, ty: schema.Type, raw: []const u8, defs: []const schema.Def) Error!void {
    var r = io.Reader.init(raw);
    switch (ty) {
        .array => |inner| {
            const packed_bytes = try value.readBytes(&r);
            var ir = io.Reader.init(packed_bytes);
            const count = try ir.varint();
            try append(pos, out, "[");
            var i: u64 = 0;
            while (i < count) : (i += 1) {
                if (i != 0) try append(pos, out, ", ");
                const start = ir.pos;
                try skipBare(&ir, .{ .primitive = inner });
                try writePrettyValue(pos, out, .{ .primitive = inner }, ir.data[start..ir.pos], defs);
            }
            try append(pos, out, "]");
        },
        .map => |m| {
            const packed_bytes = try value.readBytes(&r);
            var ir = io.Reader.init(packed_bytes);
            const count = try ir.varint();
            try append(pos, out, "{ ");
            var i: u64 = 0;
            while (i < count) : (i += 1) {
                if (i != 0) try append(pos, out, ", ");
                const ks = ir.pos;
                try skipBare(&ir, .{ .primitive = m.key });
                try writePrettyValue(pos, out, .{ .primitive = m.key }, ir.data[ks..ir.pos], defs);
                try append(pos, out, ": ");
                const vs = ir.pos;
                try skipBare(&ir, .{ .primitive = m.value });
                try writePrettyValue(pos, out, .{ .primitive = m.value }, ir.data[vs..ir.pos], defs);
            }
            try append(pos, out, " }");
        },
        .named => |named| {
            if (named.kind == .enum_) {
                const v = try value.readUnsigned(&r);
                for (defs) |d| {
                    if (!eq(d.name, named.name)) continue;
                    for (d.fields) |f| {
                        if (f.field_id == v) {
                            try append(pos, out, f.name);
                            return;
                        }
                    }
                }
                try appendDec(pos, out, v);
                return;
            }
            const inner = try value.readBytes(&r);
            var def: ?schema.Def = null;
            for (defs) |d| {
                if (eq(d.name, named.name)) {
                    def = d;
                    break;
                }
            }
            if (def) |d| {
                try append(pos, out, "{");
                var ir = io.Reader.init(inner);
                const st = d.asStruct();
                var first = true;
                while (try record.next(&ir, st)) |item| {
                    if (item.field) |f| {
                        if (!first) try append(pos, out, ",");
                        first = false;
                        try append(pos, out, " ");
                        try append(pos, out, f.name);
                        try append(pos, out, " = ");
                        try writePrettyValue(pos, out, f.ty, item.raw, defs);
                    }
                }
                try append(pos, out, " }");
                return;
            }
            try append(pos, out, "h\"");
            try appendHex(pos, out, inner);
            try append(pos, out, "\"");
        },
        .primitive => |p| try writePrettyPrim(pos, out, p, &r),
    }
}

fn skipBare(r: *io.Reader, ty: schema.Type) Error!void {
    try record.skipBare(r, ty);
}

fn writePrettyPrim(pos: *usize, out: []u8, p: schema.Primitive, r: *io.Reader) Error!void {
    switch (p) {
        .bool => try append(pos, out, if (try value.readBool(r)) "true" else "false"),
        .string => {
            try append(pos, out, "\"");
            try append(pos, out, try value.readBytes(r));
            try append(pos, out, "\"");
        },
        .bytes, .fn_, .uuid => {
            try append(pos, out, "h\"");
            try appendHex(pos, out, try value.readBytes(r));
            try append(pos, out, "\"");
        },
        .f32 => {
            try append(pos, out, "f32:0x");
            try appendHex32(pos, out, @bitCast(try value.readF32(r)));
        },
        .f64 => {
            try append(pos, out, "f64:0x");
            try appendHex64(pos, out, @bitCast(try value.readF64(r)));
        },
        .i8, .i16, .i32, .i64, .timestamp, .duration => {
            const v = try value.readSigned(r);
            if (v < 0) try append(pos, out, "-");
            const mag: u64 = if (v < 0) @as(u64, @bitCast(-%v)) else @as(u64, @intCast(v));
            try appendDec(pos, out, mag);
        },
        .rwx => {
            try append(pos, out, "rwx:");
            try appendOctal(pos, out, try value.readUnsigned(r));
        },
        else => try appendDec(pos, out, try value.readUnsigned(r)),
    }
}

fn append(pos: *usize, out: []u8, s: []const u8) Error!void {
    if (pos.* + s.len > out.len) return error.Truncated;
    @memcpy(out[pos.* .. pos.* + s.len], s);
    pos.* += s.len;
}

fn appendDec(pos: *usize, out: []u8, v: u64) Error!void {
    if (v == 0) return append(pos, out, "0");
    var tmp: [20]u8 = undefined;
    var n: usize = 0;
    var x = v;
    while (x > 0) {
        tmp[n] = @intCast('0' + (x % 10));
        x /= 10;
        n += 1;
    }
    var i: usize = n;
    while (i > 0) {
        i -= 1;
        try append(pos, out, tmp[i .. i + 1]);
    }
}

fn appendOctal(pos: *usize, out: []u8, v: u64) Error!void {
    var tmp: [8]u8 = undefined;
    var n: usize = 0;
    var x = v;
    if (x == 0) return append(pos, out, "0");
    while (x > 0) : (n += 1) {
        tmp[n] = @intCast('0' + (x & 7));
        x >>= 3;
    }
    var i: usize = n;
    while (i > 0) {
        i -= 1;
        try append(pos, out, tmp[i .. i + 1]);
    }
}

fn appendHex(pos: *usize, out: []u8, bytes: []const u8) Error!void {
    const digits = "0123456789abcdef";
    for (bytes) |b| {
        const pair = [_]u8{ digits[b >> 4], digits[b & 0xf] };
        try append(pos, out, &pair);
    }
}

fn appendHex32(pos: *usize, out: []u8, v: u32) Error!void {
    const digits = "0123456789abcdef";
    var tmp: [8]u8 = undefined;
    var i: usize = 8;
    var x = v;
    while (i > 0) {
        i -= 1;
        tmp[i] = digits[x & 0xf];
        x >>= 4;
    }
    try append(pos, out, &tmp);
}

fn appendHex64(pos: *usize, out: []u8, v: u64) Error!void {
    const digits = "0123456789abcdef";
    var tmp: [16]u8 = undefined;
    var i: usize = 16;
    var x = v;
    while (i > 0) {
        i -= 1;
        tmp[i] = digits[x & 0xf];
        x >>= 4;
    }
    try append(pos, out, &tmp);
}

fn decodeHex(text: []const u8, out: []u8) Error!usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i < text.len) {
        const c = text[i];
        if (c == ' ' or c == '\n') {
            i += 1;
            continue;
        }
        if (i + 1 >= text.len) return error.HexOdd;
        const hi = hexVal(text[i]) orelse return error.InvalidPretty;
        const lo = hexVal(text[i + 1]) orelse return error.InvalidPretty;
        if (n >= out.len) return error.Truncated;
        out[n] = (hi << 4) | lo;
        n += 1;
        i += 2;
    }
    return n;
}

fn hexVal(c: u8) ?u8 {
    if (c >= '0' and c <= '9') return c - '0';
    if (c >= 'a' and c <= 'f') return c - 'a' + 10;
    if (c >= 'A' and c <= 'F') return c - 'A' + 10;
    return null;
}

fn parseOctal(s: []const u8) ?u64 {
    if (s.len < 3 or s.len > 4) return null;
    var v: u64 = 0;
    for (s) |c| {
        if (c < '0' or c > '7') return null;
        v = (v << 3) | (c - '0');
    }
    return v;
}

fn parseDec(s: []const u8) u64 {
    var v: u64 = 0;
    for (s) |c| v = v * 10 + (c - '0');
    return v;
}

fn parsePrefixed(s: []const u8) u64 {
    if (s.len < 3 or s[0] != '0') return parseDec(s);
    const p = s[1];
    var v: u64 = 0;
    if (p == 'x' or p == 'X') {
        for (s[2..]) |c| v = (v << 4) | (hexVal(c) orelse 0);
        return v;
    }
    if (p == 'o') {
        for (s[2..]) |c| v = (v << 3) | (c - '0');
        return v;
    }
    if (p == 'b') {
        for (s[2..]) |c| v = (v << 1) | (c - '0');
        return v;
    }
    return parseDec(s);
}

fn isHexish(c: u8, p: u8) bool {
    if (p == 'x' or p == 'X') return hexVal(c) != null;
    if (p == 'o') return c >= '0' and c <= '7';
    return c == '0' or c == '1';
}
fn isDigit(c: u8) bool {
    return c >= '0' and c <= '9';
}
fn isIdent(c: u8) bool {
    return isDigit(c) or c == '_' or (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z');
}
fn eq(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (x != y) return false;
    return true;
}
