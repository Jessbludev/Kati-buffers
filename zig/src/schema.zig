//! Textual .pbr schema parser.
//! Host/compiler layer: fixed-capacity, no allocator and no OS dependency.
//! Accepts both spec spelling (`[string]`, `map<K,V>`) and Zig spelling (`array[]`, `map[]`).

pub const Error = error{
    UnexpectedEof, InvalidToken, InvalidIdentifier, InvalidNumber,
    ExpectedIdentifier, ExpectedType, ExpectedSymbol, ExpectedKeyword,
    TooManyFields, FieldIdOutOfRange, DuplicateFieldId, DuplicateFieldName,
    UnknownAnnotation, InvalidAnnotation, UnsupportedType, Empty,
};

pub const MAX_FIELDS: usize = 128;

pub const Primitive = enum {
    i8, i16, i32, i64, u8, u16, u32, u64,
    f32, f64, bool, char, string, bytes,
    rwx, timestamp, duration, uuid, fn_,
};

pub const Type = union(enum) {
    primitive: Primitive,
    array: Primitive,
    map: struct { key: Primitive, value: Primitive },
    named: struct { name: []const u8, kind: Kind = .struct_ },
};

pub const Annotation = struct {
    required: bool = false,
    max: ?u32 = null,
    default_bool: ?bool = null,
    default_uint: ?u64 = null,
    default_sint: ?i64 = null,
    default_string: ?[]const u8 = null,
    id: ?u32 = null,
    compress: ?[]const u8 = null,
    perms: u8 = 0,
};

pub const Kind = enum { config, struct_, buffer, union_, enum_ };

pub const Field = struct {
    name: []const u8,
    ty: Type,
    ann: Annotation = .{},
    field_id: u32 = 0,
};

pub const Struct = struct {
    name: []const u8,
    strict: bool,
    kind: Kind = .config,
    fields: []const Field,
    schema_hash: u64,
};

pub const Def = struct {
    kind: Kind,
    name: []const u8,
    strict: bool,
    fields: []const Field,
    schema_hash: u64,

    pub fn asStruct(self: Def) Struct {
        return .{
            .name = self.name,
            .strict = self.strict,
            .kind = self.kind,
            .fields = self.fields,
            .schema_hash = self.schema_hash,
        };
    }
};

pub const MAX_TYPES: usize = 32;

pub const Doc = struct {
    defs: []const Def,
    root: Struct,

    pub fn find(self: Doc, name: []const u8) ?Def {
        for (self.defs) |d| {
            if (eq(d.name, name)) return d;
        }
        return null;
    }
};

const TokenKind = enum {
    eof, ident, number, string, at,
    lbrace, rbrace, lbracket, rbracket, lparen, rparen, langle, rangle,
    colon, equal, comma,
};
const Token = struct { kind: TokenKind, text: []const u8 };

pub const Parser = struct {
    source: []const u8,
    pos: usize = 0,
    fields: [MAX_FIELDS]Field = undefined,
    field_count: usize = 0,
    defs: [MAX_TYPES]Def = undefined,
    def_count: usize = 0,
    pending: ?Token = null,

    pub fn init(source: []const u8) Parser {
        return .{ .source = source };
    }

    pub fn parse(self: *Parser) Error!Struct {
        const doc = try self.parseDoc();
        return doc.root;
    }

    pub fn parseDoc(self: *Parser) Error!Doc {
        var pending_strict = false;
        var root_index: ?usize = null;
        self.field_count = 0;
        self.def_count = 0;

        while (true) {
            var t = try self.take();
            if (t.kind == .eof) break;

            while (t.kind == .at) {
                const a = try self.take();
                if (a.kind != .ident) return error.UnknownAnnotation;
                if (eq(a.text, "strict")) {
                    pending_strict = true;
                } else if (eq(a.text, "perms")) {
                    try self.skipParen();
                } else return error.UnknownAnnotation;
                t = try self.take();
            }

            if (t.kind != .ident) return error.ExpectedKeyword;

            var kind: Kind = .config;
            if (eq(t.text, "enum")) {
                kind = .enum_;
            } else if (eq(t.text, "struct")) {
                kind = .struct_;
            } else if (eq(t.text, "buffer")) {
                kind = .buffer;
            } else if (eq(t.text, "union")) {
                kind = .union_;
            } else if (!eq(t.text, "config")) {
                return error.ExpectedKeyword;
            }

            const name_tok = try self.take();
            if (name_tok.kind != .ident or name_tok.text.len == 0) return error.ExpectedIdentifier;
            try self.expect(.lbrace);

            const strict = pending_strict;
            pending_strict = false;
            const field_start = self.field_count;

            if (kind == .enum_) {
                var next_id: u32 = 0;
                while (true) {
                    t = try self.take();
                    if (t.kind == .rbrace) break;
                    if (t.kind != .ident) return error.ExpectedIdentifier;
                    if (self.field_count == MAX_FIELDS) return error.TooManyFields;
                    const variant_name = t.text;
                    var value = next_id;
                    const peek_t = try self.take();
                    if (peek_t.kind == .equal) {
                        const lit = try self.take();
                        if (lit.kind != .number) return error.InvalidNumber;
                        value = parseU32(lit.text) catch return error.InvalidNumber;
                        t = try self.take();
                    } else {
                        t = peek_t;
                    }
                    if (t.kind == .comma) {
                        // consumed
                    } else if (t.kind == .rbrace or t.kind == .ident) {
                        self.pending = t;
                    } else return error.ExpectedSymbol;
                    self.fields[self.field_count] = .{
                        .name = variant_name,
                        .ty = .{ .primitive = .u32 },
                        .field_id = value,
                    };
                    self.field_count += 1;
                    next_id = value + 1;
                    if (self.pending) |p| {
                        if (p.kind == .rbrace) {
                            _ = try self.take();
                            break;
                        }
                    }
                }
            } else {
                while (true) {
                    t = try self.take();
                    if (t.kind == .rbrace) break;
                    if (t.kind != .ident) return error.ExpectedIdentifier;
                    if (self.field_count == MAX_FIELDS) return error.TooManyFields;
                    const stored = self.fields[field_start..self.field_count];
                    for (stored) |f| if (eq(f.name, t.text)) return error.DuplicateFieldName;

                    const field_name = t.text;
                    try self.expect(.colon);
                    const ty = try self.parseType();
                    var ann = Annotation{};

                    while (true) {
                        t = try self.take();
                        if (t.kind == .at) {
                            try self.parseAnnotation(&ann);
                            continue;
                        }
                        if (t.kind == .equal) {
                            try self.parseLiteral(&ann);
                            continue;
                        }
                        if (t.kind == .comma) break;
                        if (t.kind == .rbrace or t.kind == .ident) {
                            self.pending = t;
                            break;
                        }
                        return error.ExpectedSymbol;
                    }

                    self.fields[self.field_count] = .{ .name = field_name, .ty = ty, .ann = ann };
                    self.field_count += 1;
                    if (self.pending) |p| {
                        if (p.kind == .rbrace) {
                            _ = try self.take();
                            break;
                        }
                    }
                }
            }

            const fields = self.fields[field_start..self.field_count];
            if (kind != .enum_) try assignFieldIds(fields);
            if (self.def_count == MAX_TYPES) return error.TooManyFields;
            const hashed = hashSchema(name_tok.text, strict, fields);
            self.defs[self.def_count] = .{
                .kind = kind,
                .name = name_tok.text,
                .strict = strict,
                .fields = fields,
                .schema_hash = hashed,
            };
            if (kind == .config or kind == .buffer or kind == .union_ or kind == .struct_) {
                root_index = self.def_count;
            }
            self.def_count += 1;
        }

        self.resolveNamed();

        const ri = root_index orelse return error.Empty;
        const d = self.defs[ri];
        return .{
            .defs = self.defs[0..self.def_count],
            .root = d.asStruct(),
        };
    }

    fn resolveNamed(self: *Parser) void {
        var i: usize = 0;
        while (i < self.field_count) : (i += 1) {
            switch (self.fields[i].ty) {
                .named => |n| {
                    var kind: Kind = n.kind;
                    for (self.defs[0..self.def_count]) |d| {
                        if (eq(d.name, n.name)) {
                            kind = d.kind;
                            break;
                        }
                    }
                    self.fields[i].ty = .{ .named = .{ .name = n.name, .kind = kind } };
                },
                else => {},
            }
        }
    }

    fn parseType(self: *Parser) Error!Type {
        const t = try self.take();
        if (t.kind == .lbracket) {
            const inner = try self.take();
            try self.expect(.rbracket);
            if (inner.kind != .ident) return error.ExpectedType;
            return .{ .array = primitive(inner.text) orelse return error.UnsupportedType };
        }
        if (t.kind != .ident) return error.ExpectedType;
        if (primitive(t.text)) |p| return .{ .primitive = p };
        if (eq(t.text, "array")) {
            const open = try self.take();
            if (open.kind != .lbracket and open.kind != .langle) return error.ExpectedSymbol;
            const inner = try self.take();
            const close = try self.take();
            if (close.kind != .rbracket and close.kind != .rangle) return error.ExpectedSymbol;
            if (inner.kind != .ident) return error.ExpectedType;
            return .{ .array = primitive(inner.text) orelse return error.UnsupportedType };
        }
        if (eq(t.text, "map")) {
            const open = try self.take();
            if (open.kind != .lbracket and open.kind != .langle) return error.ExpectedSymbol;
            const k = try self.take();
            try self.expect(.comma);
            const v = try self.take();
            const close = try self.take();
            if (close.kind != .rbracket and close.kind != .rangle) return error.ExpectedSymbol;
            if (k.kind != .ident or v.kind != .ident) return error.ExpectedType;
            return .{
                .map = .{
                    .key = primitive(k.text) orelse return error.UnsupportedType,
                    .value = primitive(v.text) orelse return error.UnsupportedType,
                },
            };
        }
        return .{ .named = .{ .name = t.text } };
    }

    fn parseAnnotation(self: *Parser, ann: *Annotation) Error!void {
        const n = try self.take();
        if (n.kind != .ident) return error.InvalidAnnotation;
        if (eq(n.text, "required")) {
            ann.required = true;
            return;
        }
        if (eq(n.text, "r")) {
            ann.perms |= 0b100;
            return;
        }
        if (eq(n.text, "w")) {
            ann.perms |= 0b010;
            return;
        }
        if (eq(n.text, "x")) {
            ann.perms |= 0b001;
            return;
        }
        if (eq(n.text, "rw")) {
            ann.perms = 0b110;
            return;
        }
        if (eq(n.text, "rx")) {
            ann.perms = 0b101;
            return;
        }
        if (eq(n.text, "wx")) {
            ann.perms = 0b011;
            return;
        }
        if (eq(n.text, "rwx")) {
            ann.perms = 0b111;
            return;
        }
        if (eq(n.text, "max") or eq(n.text, "id")) {
            const is_id = eq(n.text, "id");
            try self.expect(.lparen);
            const value = try self.take();
            if (value.kind != .number) return error.InvalidNumber;
            const number = parseU32(value.text) catch return error.InvalidNumber;
            try self.expect(.rparen);
            if (is_id) ann.id = number else ann.max = number;
            return;
        }
        if (eq(n.text, "compress")) {
            try self.expect(.lparen);
            const v = try self.take();
            if (v.kind != .ident and v.kind != .string) return error.InvalidAnnotation;
            ann.compress = v.text;
            try self.expect(.rparen);
            return;
        }
        if (eq(n.text, "default")) {
            try self.expect(.lparen);
            try self.parseLiteral(ann);
            try self.expect(.rparen);
            return;
        }
        return error.UnknownAnnotation;
    }

    fn parseLiteral(self: *Parser, ann: *Annotation) Error!void {
        const lit = try self.take();
        if (lit.kind == .ident) {
            if (eq(lit.text, "true")) {
                ann.default_bool = true;
                return;
            }
            if (eq(lit.text, "false")) {
                ann.default_bool = false;
                return;
            }
            if (eq(lit.text, "rwx")) {
                const colon = try self.take();
                if (colon.kind == .colon) {
                    const n = try self.take();
                    if (n.kind != .number) return error.InvalidNumber;
                    ann.default_uint = parseU64(n.text) catch return error.InvalidNumber;
                    return;
                }
                self.pending = colon;
                return;
            }
            ann.default_string = lit.text;
            return;
        }
        if (lit.kind == .number) {
            if (lit.text.len > 0 and lit.text[0] == '-') {
                const mag = parseU64(lit.text[1..]) catch return error.InvalidNumber;
                if (mag > 9223372036854775807) return error.InvalidNumber;
                ann.default_sint = -@as(i64, @intCast(mag));
                return;
            }
            ann.default_uint = parseU64(lit.text) catch return error.InvalidNumber;
            return;
        }
        if (lit.kind == .string) {
            ann.default_string = lit.text;
            return;
        }
        return error.InvalidAnnotation;
    }

    fn skipParen(self: *Parser) Error!void {
        try self.expect(.lparen);
        var depth: usize = 1;
        while (depth > 0) {
            const t = try self.take();
            if (t.kind == .lparen) depth += 1;
            if (t.kind == .rparen) depth -= 1;
            if (t.kind == .eof) return error.ExpectedSymbol;
        }
    }

    fn expect(self: *Parser, kind: TokenKind) Error!void {
        if ((try self.take()).kind != kind) return error.ExpectedSymbol;
    }

    fn take(self: *Parser) Error!Token {
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
            if (c == '#') {
                while (self.pos < self.source.len and self.source[self.pos] != '\n') self.pos += 1;
                continue;
            }
            if (c == '/' and self.pos + 1 < self.source.len and self.source[self.pos + 1] == '/') {
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
            '{' => .{ .kind = .lbrace, .text = self.source[start..self.pos] },
            '}' => .{ .kind = .rbrace, .text = self.source[start..self.pos] },
            '[' => .{ .kind = .lbracket, .text = self.source[start..self.pos] },
            ']' => .{ .kind = .rbracket, .text = self.source[start..self.pos] },
            '(' => .{ .kind = .lparen, .text = self.source[start..self.pos] },
            ')' => .{ .kind = .rparen, .text = self.source[start..self.pos] },
            '<' => .{ .kind = .langle, .text = self.source[start..self.pos] },
            '>' => .{ .kind = .rangle, .text = self.source[start..self.pos] },
            ':' => .{ .kind = .colon, .text = self.source[start..self.pos] },
            '=' => .{ .kind = .equal, .text = self.source[start..self.pos] },
            ',' => .{ .kind = .comma, .text = self.source[start..self.pos] },
            '-' => blk: {
                if (self.pos >= self.source.len or !isDigit(self.source[self.pos])) return error.InvalidToken;
                while (self.pos < self.source.len and isDigit(self.source[self.pos])) self.pos += 1;
                break :blk .{ .kind = .number, .text = self.source[start..self.pos] };
            },
            '0'...'9' => blk: {
                if (c == '0' and self.pos < self.source.len) {
                    const p = self.source[self.pos];
                    if (p == 'x' or p == 'X' or p == 'o' or p == 'b') {
                        self.pos += 1;
                        while (self.pos < self.source.len and isHexish(self.source[self.pos], p)) self.pos += 1;
                        break :blk .{ .kind = .number, .text = self.source[start..self.pos] };
                    }
                }
                while (self.pos < self.source.len and isDigit(self.source[self.pos])) self.pos += 1;
                break :blk .{ .kind = .number, .text = self.source[start..self.pos] };
            },
            'a'...'z', 'A'...'Z', '_' => blk: {
                while (self.pos < self.source.len and isIdent(self.source[self.pos])) self.pos += 1;
                break :blk .{ .kind = .ident, .text = self.source[start..self.pos] };
            },
            '"' => blk: {
                while (self.pos < self.source.len and self.source[self.pos] != '"') self.pos += 1;
                if (self.pos >= self.source.len) return error.UnexpectedEof;
                self.pos += 1;
                break :blk .{ .kind = .string, .text = self.source[start + 1 .. self.pos - 1] };
            },
            else => return error.InvalidToken,
        };
    }
};

fn assignFieldIds(fields: []Field) Error!void {
    var used: [MAX_FIELDS]bool = [_]bool{false} ** MAX_FIELDS;
    for (fields, 0..) |*f, index| {
        const id = f.ann.id orelse @as(u32, @intCast(index + 1));
        if (id == 0 or id > MAX_FIELDS) return error.FieldIdOutOfRange;
        if (used[id - 1]) return error.DuplicateFieldId;
        used[id - 1] = true;
        f.field_id = id;
    }
}

pub fn hashSchema(name: []const u8, strict: bool, fields: []const Field) u64 {
    var h: u64 = 0xcbf29ce484222325;
    hashBytes(&h, "kati-schema-v1\x00");
    hashBytes(&h, name);
    hashByte(&h, if (strict) 1 else 0);
    for (fields) |f| {
        hashByte(&h, 0xff);
        hashBytes(&h, f.name);
        hashType(&h, f.ty);
        var id = f.field_id;
        var i: u8 = 0;
        while (i < 4) : (i += 1) {
            hashByte(&h, @truncate(id));
            id >>= 8;
        }
        hashByte(&h, if (f.ann.required) 1 else 0);
    }
    return h;
}

fn hashType(h: *u64, ty: Type) void {
    switch (ty) {
        .primitive => |p| {
            hashByte(h, 0);
            hashByte(h, @intFromEnum(p));
        },
        .array => |p| {
            hashByte(h, 1);
            hashByte(h, @intFromEnum(p));
        },
        .map => |m| {
            hashByte(h, 2);
            hashByte(h, @intFromEnum(m.key));
            hashByte(h, @intFromEnum(m.value));
        },
        .named => |n| {
            hashByte(h, 3);
            hashBytes(h, n.name);
        },
    }
}

fn hashBytes(h: *u64, bytes: []const u8) void {
    for (bytes) |b| hashByte(h, b);
}
fn hashByte(h: *u64, b: u8) void {
    h.* = (h.* ^ b) *% 0x100000001b3;
}

fn primitive(s: []const u8) ?Primitive {
    if (eq(s, "i8")) return .i8;
    if (eq(s, "i16")) return .i16;
    if (eq(s, "i32")) return .i32;
    if (eq(s, "i64")) return .i64;
    if (eq(s, "u8")) return .u8;
    if (eq(s, "u16")) return .u16;
    if (eq(s, "u32")) return .u32;
    if (eq(s, "u64")) return .u64;
    if (eq(s, "f32")) return .f32;
    if (eq(s, "f64")) return .f64;
    if (eq(s, "bool")) return .bool;
    if (eq(s, "char")) return .char;
    if (eq(s, "string")) return .string;
    if (eq(s, "bytes")) return .bytes;
    if (eq(s, "rwx")) return .rwx;
    if (eq(s, "timestamp")) return .timestamp;
    if (eq(s, "duration")) return .duration;
    if (eq(s, "uuid")) return .uuid;
    if (eq(s, "fn")) return .fn_;
    return null;
}

fn parseU32(s: []const u8) !u32 {
    const v = try parseU64(s);
    if (v > 0xffffffff) return error.InvalidNumber;
    return @intCast(v);
}

fn parseU64(s: []const u8) !u64 {
    if (s.len == 0) return error.InvalidNumber;
    if (s.len >= 3 and s[0] == '0') {
        const p = s[1];
        if (p == 'x' or p == 'X') {
            var v: u64 = 0;
            if (s.len == 2) return error.InvalidNumber;
            for (s[2..]) |c| {
                const d = hexVal(c) orelse return error.InvalidNumber;
                if (v > (~@as(u64, 0) >> 4)) return error.InvalidNumber;
                v = (v << 4) | d;
            }
            return v;
        }
        if (p == 'o') {
            var v: u64 = 0;
            for (s[2..]) |c| {
                if (c < '0' or c > '7') return error.InvalidNumber;
                const d: u64 = c - '0';
                if (v > (~@as(u64, 0) >> 3)) return error.InvalidNumber;
                v = (v << 3) | d;
            }
            return v;
        }
        if (p == 'b') {
            var v: u64 = 0;
            for (s[2..]) |c| {
                if (c != '0' and c != '1') return error.InvalidNumber;
                if (v > (~@as(u64, 0) >> 1)) return error.InvalidNumber;
                v = (v << 1) | (c - '0');
            }
            return v;
        }
    }
    var v: u64 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return error.InvalidNumber;
        const d: u64 = c - '0';
        if (v > (~@as(u64, 0) - d) / 10) return error.InvalidNumber;
        v = v * 10 + d;
    }
    return v;
}

fn hexVal(c: u8) ?u8 {
    if (c >= '0' and c <= '9') return c - '0';
    if (c >= 'a' and c <= 'f') return c - 'a' + 10;
    if (c >= 'A' and c <= 'F') return c - 'A' + 10;
    return null;
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
