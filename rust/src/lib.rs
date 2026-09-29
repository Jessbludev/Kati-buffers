#![cfg_attr(not(feature = "std"), no_std)]
//! kati — zero-runtime PrettyBuffers codec.
//! The core never allocates. Enable `std` only if a host needs files.

pub const MAGIC: &[u8; 4] = b"PBR\x01";
pub const VERSION: u8 = 1;
pub const MAX_FIELDS: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidMagic,
    UnsupportedVersion,
    InvalidFlags,
    Truncated,
    Overflow,
    InvalidVarint,
    InvalidFieldId,
    InvalidWire,
    TypeMismatch,
    PermDenied,
    InvalidToken,
    Expected,
    Duplicate,
    UnsupportedType,
    Empty,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags {
    pub compressed: bool,
    pub encrypted: bool,
    pub has_schema: bool,
    pub has_mux: bool,
    pub big_endian: bool,
}

impl Flags {
    pub const NONE: Self = Self {
        compressed: false,
        encrypted: false,
        has_schema: false,
        has_mux: false,
        big_endian: false,
    };

    pub fn pack(self) -> u8 {
        u8::from(self.compressed)
            | (u8::from(self.encrypted) << 1)
            | (u8::from(self.has_schema) << 2)
            | (u8::from(self.has_mux) << 3)
            | (u8::from(self.big_endian) << 4)
    }

    pub fn unpack(bits: u8) -> Result<Self, Error> {
        if bits & 0b1110_0000 != 0 {
            return Err(Error::InvalidFlags);
        }
        Ok(Self {
            compressed: bits & 1 != 0,
            encrypted: bits & 2 != 0,
            has_schema: bits & 4 != 0,
            has_mux: bits & 8 != 0,
            big_endian: bits & 16 != 0,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub flags: Flags,
    pub schema_hash: u64,
    pub payload_len: u64,
    pub header_len: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WireType {
    Varint = 0,
    Fixed64 = 1,
    Bytes = 2,
    Fixed32 = 5,
}

impl WireType {
    fn from_u8(v: u8) -> Result<Self, Error> {
        match v {
            0 => Ok(Self::Varint),
            1 => Ok(Self::Fixed64),
            2 => Ok(Self::Bytes),
            5 => Ok(Self::Fixed32),
            _ => Err(Error::InvalidWire),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldHeader {
    pub field_id: u32,
    pub wire_type: WireType,
}

pub struct Writer<'a> {
    out: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    pub fn new(out: &'a mut [u8]) -> Self {
        Self { out, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    fn put(&mut self, b: u8) -> Result<(), Error> {
        *self.out.get_mut(self.pos).ok_or(Error::Truncated)? = b;
        self.pos += 1;
        Ok(())
    }

    pub fn bytes(&mut self, src: &[u8]) -> Result<(), Error> {
        if src.len() > self.out.len() - self.pos {
            return Err(Error::Truncated);
        }
        self.out[self.pos..self.pos + src.len()].copy_from_slice(src);
        self.pos += src.len();
        Ok(())
    }

    pub fn u8(&mut self, v: u8) -> Result<(), Error> {
        self.put(v)
    }

    pub fn u64le(&mut self, mut v: u64) -> Result<(), Error> {
        for _ in 0..8 {
            self.put((v & 0xff) as u8)?;
            v >>= 8;
        }
        Ok(())
    }

    pub fn varint(&mut self, mut v: u64) -> Result<(), Error> {
        while v >= 0x80 {
            self.put((v as u8) | 0x80)?;
            v >>= 7;
        }
        self.put(v as u8)
    }
}

pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    fn take(&mut self) -> Result<u8, Error> {
        let b = *self.data.get(self.pos).ok_or(Error::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.data.len() - self.pos {
            return Err(Error::Truncated);
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u64le(&mut self) -> Result<u64, Error> {
        let mut v = 0u64;
        for i in 0..8 {
            v |= (self.take()? as u64) << (8 * i);
        }
        Ok(v)
    }

    pub fn varint(&mut self) -> Result<u64, Error> {
        let mut value = 0u64;
        let mut shift = 0u32;
        for _ in 0..10 {
            let b = self.take()?;
            let part = (b & 0x7f) as u64;
            if shift >= 64 || (shift == 63 && part > 1) {
                return Err(Error::Overflow);
            }
            value |= part << shift;
            if b & 0x80 == 0 {
                if part == 0 && shift > 0 {
                    return Err(Error::InvalidVarint);
                }
                return Ok(value);
            }
            shift += 7;
        }
        Err(Error::InvalidVarint)
    }
}

pub fn encode_header(out: &mut [u8], flags: Flags, schema_hash: u64, payload_len: u64) -> Result<usize, Error> {
    let mut w = Writer::new(out);
    w.bytes(MAGIC)?;
    w.u8(flags.pack())?;
    w.u64le(schema_hash)?;
    w.varint(payload_len)?;
    Ok(w.pos())
}

pub fn decode_header(buf: &[u8]) -> Result<Header, Error> {
    let mut r = Reader::new(buf);
    let magic = r.bytes(4)?;
    if magic[..3] != MAGIC[..3] {
        return Err(Error::InvalidMagic);
    }
    if magic[3] != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    let flags = Flags::unpack(r.take()?)?;
    let schema_hash = r.u64le()?;
    let payload_len = r.varint()?;
    Ok(Header {
        flags,
        schema_hash,
        payload_len,
        header_len: r.pos(),
    })
}

pub fn write_field_header(w: &mut Writer<'_>, field_id: u32, wire: WireType) -> Result<(), Error> {
    if field_id == 0 {
        return Err(Error::InvalidFieldId);
    }
    w.varint(field_id as u64)?;
    w.u8(wire as u8)
}

pub fn read_field_header(r: &mut Reader<'_>) -> Result<FieldHeader, Error> {
    let id = r.varint()?;
    if id == 0 || id > u32::MAX as u64 {
        return Err(Error::InvalidFieldId);
    }
    Ok(FieldHeader {
        field_id: id as u32,
        wire_type: WireType::from_u8(r.take()?)?,
    })
}

pub fn write_signed(w: &mut Writer<'_>, value: i64) -> Result<(), Error> {
    let encoded = ((value as u64) << 1) ^ ((value >> 63) as u64);
    w.varint(encoded)
}

pub fn read_signed(r: &mut Reader<'_>) -> Result<i64, Error> {
    let encoded = r.varint()?;
    Ok(((encoded >> 1) as i64) ^ -((encoded & 1) as i64))
}

pub fn write_bytes(w: &mut Writer<'_>, bytes: &[u8]) -> Result<(), Error> {
    w.varint(bytes.len() as u64)?;
    w.bytes(bytes)
}

pub fn read_bytes<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], Error> {
    let n = r.varint()? as usize;
    r.bytes(n)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Packed<'a> {
    pub count: u64,
    pub items: &'a [u8],
}

pub fn write_packed(w: &mut Writer<'_>, count: u64, items: &[u8]) -> Result<(), Error> {
    let mut c = count;
    let mut leb = 1usize;
    while c >= 0x80 {
        c >>= 7;
        leb += 1;
    }
    w.varint((leb + items.len()) as u64)?;
    w.varint(count)?;
    w.bytes(items)
}

pub fn read_packed<'a>(r: &mut Reader<'a>) -> Result<Packed<'a>, Error> {
    let blob = read_bytes(r)?;
    let mut inner = Reader::new(blob);
    let count = inner.varint()?;
    Ok(Packed {
        count,
        items: &blob[inner.pos()..],
    })
}

pub fn skip_value(r: &mut Reader<'_>, wire: WireType) -> Result<(), Error> {
    match wire {
        WireType::Varint => {
            r.varint()?;
        }
        WireType::Fixed64 => {
            r.u64le()?;
        }
        WireType::Fixed32 => {
            r.bytes(4)?;
        }
        WireType::Bytes => {
            read_bytes(r)?;
        }
    }
    Ok(())
}

pub const R: u8 = 0b100;
pub const W: u8 = 0b010;
pub const X: u8 = 0b001;

pub fn can(field_perms: u8, want: u8) -> bool {
    let bits = if field_perms == 0 { R | W | X } else { field_perms };
    bits & want == want
}

const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

fn fnv_byte(h: u64, b: u8) -> u64 {
    (h ^ b as u64).wrapping_mul(FNV_PRIME)
}

fn fnv_bytes(mut h: u64, bytes: &[u8]) -> u64 {
    for b in bytes {
        h = fnv_byte(h, *b);
    }
    h
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prim {
    I8 = 0,
    I16 = 1,
    I32 = 2,
    I64 = 3,
    U8 = 4,
    U16 = 5,
    U32 = 6,
    U64 = 7,
    F32 = 8,
    F64 = 9,
    Bool = 10,
    Char = 11,
    String = 12,
    Bytes = 13,
    Rwx = 14,
    Timestamp = 15,
    Duration = 16,
    Uuid = 17,
    Fn = 18,
}

fn prim_of(s: &str) -> Option<Prim> {
    Some(match s {
        "i8" => Prim::I8,
        "i16" => Prim::I16,
        "i32" => Prim::I32,
        "i64" => Prim::I64,
        "u8" => Prim::U8,
        "u16" => Prim::U16,
        "u32" => Prim::U32,
        "u64" => Prim::U64,
        "f32" => Prim::F32,
        "f64" => Prim::F64,
        "bool" => Prim::Bool,
        "char" => Prim::Char,
        "string" => Prim::String,
        "bytes" => Prim::Bytes,
        "rwx" => Prim::Rwx,
        "timestamp" => Prim::Timestamp,
        "duration" => Prim::Duration,
        "uuid" => Prim::Uuid,
        "fn" => Prim::Fn,
        _ => return None,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ty<'a> {
    Prim(Prim),
    Array(Prim),
    Map { key: Prim, value: Prim },
    Named(&'a str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field<'a> {
    pub name: &'a str,
    pub ty: Ty<'a>,
    pub required: bool,
    pub field_id: u32,
    pub max: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schema<'a> {
    pub name: &'a str,
    pub strict: bool,
    pub fields: &'a [Field<'a>],
    pub schema_hash: u64,
}

fn hash_type(mut h: u64, ty: Ty<'_>) -> u64 {
    match ty {
        Ty::Prim(p) => {
            h = fnv_byte(h, 0);
            fnv_byte(h, p as u8)
        }
        Ty::Array(p) => {
            h = fnv_byte(h, 1);
            fnv_byte(h, p as u8)
        }
        Ty::Map { key, value } => {
            h = fnv_byte(h, 2);
            h = fnv_byte(h, key as u8);
            fnv_byte(h, value as u8)
        }
        Ty::Named(n) => {
            h = fnv_byte(h, 3);
            fnv_bytes(h, n.as_bytes())
        }
    }
}

pub fn hash_schema(name: &str, strict: bool, fields: &[Field<'_>]) -> u64 {
    let mut h = fnv_bytes(FNV_OFFSET, b"kati-schema-v1\0");
    h = fnv_bytes(h, name.as_bytes());
    h = fnv_byte(h, u8::from(strict));
    for f in fields {
        h = fnv_byte(h, 0xff);
        h = fnv_bytes(h, f.name.as_bytes());
        h = hash_type(h, f.ty);
        let mut id = f.field_id;
        for _ in 0..4 {
            h = fnv_byte(h, id as u8);
            id >>= 8;
        }
        h = fnv_byte(h, u8::from(f.required));
    }
    h
}

/* A tiny schema parser sufficient for the Zig AppConfig dialect and spec sugar. */

struct Parser<'a> {
    src: &'a str,
    pos: usize,
    pending: Option<Tok<'a>>,
}

#[derive(Clone, Copy)]
enum Tok<'a> {
    Eof,
    Ident(&'a str),
    Number(u32),
    At,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    LParen,
    RParen,
    LAngle,
    RAngle,
    Colon,
    Equal,
    Comma,
}

impl<'a> Parser<'a> {
    fn skip(&mut self) {
        let b = self.src.as_bytes();
        while self.pos < b.len() {
            match b[self.pos] {
                b' ' | b'\n' | b'\r' | b'\t' => self.pos += 1,
                b'#' => {
                    while self.pos < b.len() && b[self.pos] != b'\n' {
                        self.pos += 1;
                    }
                }
                b'/' if self.pos + 1 < b.len() && b[self.pos + 1] == b'/' => {
                    while self.pos < b.len() && b[self.pos] != b'\n' {
                        self.pos += 1;
                    }
                }
                _ => return,
            }
        }
    }

    fn next(&mut self) -> Result<Tok<'a>, Error> {
        if let Some(t) = self.pending.take() {
            return Ok(t);
        }
        self.skip();
        let b = self.src.as_bytes();
        if self.pos >= b.len() {
            return Ok(Tok::Eof);
        }
        let c = b[self.pos];
        self.pos += 1;
        Ok(match c {
            b'@' => Tok::At,
            b'{' => Tok::LBrace,
            b'}' => Tok::RBrace,
            b'[' => Tok::LBracket,
            b']' => Tok::RBracket,
            b'(' => Tok::LParen,
            b')' => Tok::RParen,
            b'<' => Tok::LAngle,
            b'>' => Tok::RAngle,
            b':' => Tok::Colon,
            b'=' => Tok::Equal,
            b',' => Tok::Comma,
            b'0'..=b'9' => {
                self.pos -= 1;
                let start = self.pos;
                while self.pos < b.len() && b[self.pos].is_ascii_digit() {
                    self.pos += 1;
                }
                let n = self.src[start..self.pos].parse::<u32>().map_err(|_| Error::InvalidToken)?;
                Tok::Number(n)
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                self.pos -= 1;
                let start = self.pos;
                self.pos += 1;
                while self.pos < b.len() {
                    let ch = b[self.pos];
                    if ch.is_ascii_alphanumeric() || ch == b'_' {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                Tok::Ident(&self.src[start..self.pos])
            }
            _ => return Err(Error::InvalidToken),
        })
    }

    fn expect_ident(&mut self) -> Result<&'a str, Error> {
        match self.next()? {
            Tok::Ident(s) => Ok(s),
            _ => Err(Error::Expected),
        }
    }
}

fn parse_type<'a>(p: &mut Parser<'a>) -> Result<Ty<'a>, Error> {
    match p.next()? {
        Tok::LBracket => {
            let inner = p.expect_ident()?;
            match p.next()? {
                Tok::RBracket => {}
                _ => return Err(Error::Expected),
            }
            Ok(Ty::Array(prim_of(inner).ok_or(Error::UnsupportedType)?))
        }
        Tok::Ident("array") => {
            let open = p.next()?;
            if !matches!(open, Tok::LBracket | Tok::LAngle) {
                return Err(Error::Expected);
            }
            let inner = p.expect_ident()?;
            let close = p.next()?;
            if !matches!(close, Tok::RBracket | Tok::RAngle) {
                return Err(Error::Expected);
            }
            Ok(Ty::Array(prim_of(inner).ok_or(Error::UnsupportedType)?))
        }
        Tok::Ident("map") => {
            let open = p.next()?;
            if !matches!(open, Tok::LBracket | Tok::LAngle) {
                return Err(Error::Expected);
            }
            let key = p.expect_ident()?;
            match p.next()? {
                Tok::Comma => {}
                _ => return Err(Error::Expected),
            }
            let val = p.expect_ident()?;
            let close = p.next()?;
            if !matches!(close, Tok::RBracket | Tok::RAngle) {
                return Err(Error::Expected);
            }
            Ok(Ty::Map {
                key: prim_of(key).ok_or(Error::UnsupportedType)?,
                value: prim_of(val).ok_or(Error::UnsupportedType)?,
            })
        }
        Tok::Ident(name) => {
            if let Some(pr) = prim_of(name) {
                Ok(Ty::Prim(pr))
            } else {
                Ok(Ty::Named(name))
            }
        }
        _ => Err(Error::Expected),
    }
}

pub fn parse_schema<'a>(src: &'a str, fields: &'a mut [Field<'a>; MAX_FIELDS]) -> Result<Schema<'a>, Error> {
    let mut p = Parser {
        src,
        pos: 0,
        pending: None,
    };
    let mut strict = false;
    let mut name = "";
    let mut nfields = 0usize;
    loop {
        match p.next()? {
            Tok::Eof => break,
            Tok::At => {
                let a = p.expect_ident()?;
                if a == "strict" {
                    strict = true;
                } else if a == "perms" {
                    let mut depth = 0;
                    loop {
                        match p.next()? {
                            Tok::LParen => depth += 1,
                            Tok::RParen => {
                                depth -= 1;
                                if depth == 0 {
                                    break;
                                }
                            }
                            Tok::Eof => return Err(Error::Expected),
                            _ => {}
                        }
                    }
                } else {
                    return Err(Error::InvalidToken);
                }
            }
            Tok::Ident("enum") => {
                let _ = p.expect_ident()?;
                match p.next()? {
                    Tok::LBrace => {}
                    _ => return Err(Error::Expected),
                }
                let mut depth = 1;
                while depth > 0 {
                    match p.next()? {
                        Tok::LBrace => depth += 1,
                        Tok::RBrace => depth -= 1,
                        Tok::Eof => return Err(Error::Expected),
                        _ => {}
                    }
                }
            }
            Tok::Ident(kw) if matches!(kw, "config" | "struct" | "buffer" | "union") => {
                name = p.expect_ident()?;
                match p.next()? {
                    Tok::LBrace => {}
                    _ => return Err(Error::Expected),
                }
                nfields = 0;
                loop {
                    match p.next()? {
                        Tok::RBrace => break,
                        Tok::Ident(fname) => {
                            match p.next()? {
                                Tok::Colon => {}
                                _ => return Err(Error::Expected),
                            }
                            let ty = parse_type(&mut p)?;
                            let mut required = false;
                            let mut field_id = 0u32;
                            let mut max = 0u32;
                            loop {
                                match p.next()? {
                                    Tok::At => {
                                        let an = p.expect_ident()?;
                                        match an {
                                            "required" => required = true,
                                            "max" | "id" => {
                                                match p.next()? {
                                                    Tok::LParen => {}
                                                    _ => return Err(Error::Expected),
                                                }
                                                let num = match p.next()? {
                                                    Tok::Number(n) => n,
                                                    _ => return Err(Error::Expected),
                                                };
                                                match p.next()? {
                                                    Tok::RParen => {}
                                                    _ => return Err(Error::Expected),
                                                }
                                                if an == "id" {
                                                    field_id = num;
                                                } else {
                                                    max = num;
                                                }
                                            }
                                            "compress" | "default" => {
                                                let mut depth = 0;
                                                loop {
                                                    match p.next()? {
                                                        Tok::LParen => depth += 1,
                                                        Tok::RParen => {
                                                            depth -= 1;
                                                            if depth == 0 {
                                                                break;
                                                            }
                                                        }
                                                        Tok::Eof => return Err(Error::Expected),
                                                        _ => {}
                                                    }
                                                }
                                            }
                                            "r" | "w" | "x" | "rw" | "rx" | "wx" | "rwx" => {}
                                            _ => return Err(Error::InvalidToken),
                                        }
                                    }
                                    Tok::Equal => {
                                        let _ = p.next()?;
                                    }
                                    Tok::Comma => {
                                        fields[nfields] = Field {
                                            name: fname,
                                            ty,
                                            required,
                                            field_id,
                                            max,
                                        };
                                        nfields += 1;
                                        break;
                                    }
                                    tok @ (Tok::RBrace | Tok::Ident(_)) => {
                                        p.pending = Some(tok);
                                        fields[nfields] = Field {
                                            name: fname,
                                            ty,
                                            required,
                                            field_id,
                                            max,
                                        };
                                        nfields += 1;
                                        break;
                                    }
                                    _ => return Err(Error::Expected),
                                }
                            }
                        }
                        _ => return Err(Error::Expected),
                    }
                }
            }
            _ => return Err(Error::Expected),
        }
    }
    if name.is_empty() {
        return Err(Error::Empty);
    }
    let slice = &mut fields[..nfields];
    let mut used = [false; MAX_FIELDS];
    for (i, f) in slice.iter_mut().enumerate() {
        let id = if f.field_id == 0 { (i as u32) + 1 } else { f.field_id };
        if id == 0 || id as usize > MAX_FIELDS {
            return Err(Error::InvalidFieldId);
        }
        if used[(id - 1) as usize] {
            return Err(Error::Duplicate);
        }
        used[(id - 1) as usize] = true;
        f.field_id = id;
    }
    let schema_hash = hash_schema(name, strict, slice);
    Ok(Schema {
        name,
        strict,
        fields: &fields[..nfields],
        schema_hash,
    })
}

pub const MUX_FIN: u8 = 1;
pub const MUX_SYN: u8 = 2;
pub const MUX_RST: u8 = 4;
pub const MUX_ACK: u8 = 8;
pub const MUX_COMPRESSED: u8 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MuxFrame<'a> {
    pub chid: u16,
    pub flags: u8,
    pub seq: u32,
    pub data: &'a [u8],
}

pub fn write_mux(w: &mut Writer<'_>, chid: u16, flags: u8, seq: u32, data: &[u8]) -> Result<(), Error> {
    if flags & 0b1110_0000 != 0 {
        return Err(Error::InvalidFlags);
    }
    w.u8(chid as u8)?;
    w.u8((chid >> 8) as u8)?;
    w.u8(flags)?;
    let mut s = seq;
    for _ in 0..4 {
        w.u8((s & 0xff) as u8)?;
        s >>= 8;
    }
    write_bytes(w, data)
}

pub fn read_mux<'a>(r: &mut Reader<'a>) -> Result<MuxFrame<'a>, Error> {
    let b0 = r.take()?;
    let b1 = r.take()?;
    let chid = b0 as u16 | ((b1 as u16) << 8);
    let flags = r.take()?;
    if flags & 0b1110_0000 != 0 {
        return Err(Error::InvalidFlags);
    }
    let mut seq = 0u32;
    for i in 0..4 {
        seq |= (r.take()? as u32) << (8 * i);
    }
    let data = read_bytes(r)?;
    Ok(MuxFrame { chid, flags, seq, data })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let mut buf = [0u8; 32];
        let n = encode_header(&mut buf, Flags { has_schema: true, ..Flags::NONE }, 0x8af3c1d2, 1234).unwrap();
        let h = decode_header(&buf[..n]).unwrap();
        assert!(h.flags.has_schema);
        assert_eq!(h.schema_hash, 0x8af3c1d2);
        assert_eq!(h.payload_len, 1234);
    }

    #[test]
    fn zigzag() {
        let values = [-1000i64, -1, 0, 1, 1000];
        let mut buf = [0u8; 16];
        for v in values {
            let mut w = Writer::new(&mut buf);
            write_signed(&mut w, v).unwrap();
            let n = w.pos();
            let mut r = Reader::new(&buf[..n]);
            assert_eq!(read_signed(&mut r).unwrap(), v);
        }
    }

    #[test]
    fn schema_appconfig_hash() {
        let fields = [
            Field { name: "name", ty: Ty::Prim(Prim::String), required: true, field_id: 1, max: 0 },
            Field { name: "version", ty: Ty::Prim(Prim::U16), required: false, field_id: 2, max: 0 },
            Field { name: "debug", ty: Ty::Prim(Prim::Bool), required: false, field_id: 3, max: 0 },
            Field { name: "endpoints", ty: Ty::Array(Prim::String), required: false, field_id: 4, max: 32 },
            Field { name: "limits", ty: Ty::Map { key: Prim::String, value: Prim::U32 }, required: false, field_id: 5, max: 0 },
            Field { name: "payload", ty: Ty::Prim(Prim::Bytes), required: false, field_id: 6, max: 0 },
        ];
        assert_eq!(hash_schema("AppConfig", true, &fields), 0x3d742323fdeca80b);
    }

    #[test]
    fn parse_appconfig_text() {
        let src = "@strict\nconfig AppConfig {\n    name: string @required\n    version: u16\n    debug: bool = false\n    endpoints: array[string] @max(32)\n    limits: map[string,u32]\n    payload: bytes @compress(zstd)\n}\n";
        let mut fields = [Field {
            name: "",
            ty: Ty::Prim(Prim::U8),
            required: false,
            field_id: 0,
            max: 0,
        }; MAX_FIELDS];
        let s = parse_schema(src, &mut fields).unwrap();
        assert_eq!(s.name, "AppConfig");
        assert_eq!(s.fields.len(), 6);
        assert_eq!(s.schema_hash, 0x3d742323fdeca80b);
    }

    #[test]
    fn mux_roundtrip() {
        let mut buf = [0u8; 32];
        let mut w = Writer::new(&mut buf);
        write_mux(&mut w, 7, MUX_SYN | MUX_ACK, 42, b"hi").unwrap();
        let n = w.pos();
        let mut r = Reader::new(&buf[..n]);
        let f = read_mux(&mut r).unwrap();
        assert_eq!(f.chid, 7);
        assert_eq!(f.seq, 42);
        assert_eq!(f.data, b"hi");
    }

    #[test]
    fn overlong_varint() {
        let mut r = Reader::new(&[0x80, 0x00]);
        assert_eq!(r.varint(), Err(Error::InvalidVarint));
    }

    #[test]
    fn packed_roundtrip() {
        let mut buf = [0u8; 32];
        let mut w = Writer::new(&mut buf);
        write_packed(&mut w, 2, b"xy").unwrap();
        let n = w.pos();
        let mut r = Reader::new(&buf[..n]);
        let p = read_packed(&mut r).unwrap();
        assert_eq!(p.count, 2);
        assert_eq!(p.items, b"xy");
    }
}
