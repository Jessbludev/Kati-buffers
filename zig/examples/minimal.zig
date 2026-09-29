const kati = @import("kati");

pub fn makeHeader(out: []u8, payload_len: u64) !usize {
    return kati.encodeHeader(out, .{ .has_schema = true }, 0x8af3c1d2, payload_len);
}
