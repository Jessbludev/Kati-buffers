//! CRC-32C (Castagnoli). Used as the per-block checksum in compressed .pbr streams.
//! Table is built at comptime; no allocator, no OS.

const POLY: u32 = 0x82F63B78;

fn makeTable() [256]u32 {
    @setEvalBranchQuota(4000);
    var t: [256]u32 = undefined;
    for (0..256) |i| {
        var crc: u32 = @intCast(i);
        for (0..8) |_| {
            if (crc & 1 != 0) crc = (crc >> 1) ^ POLY else crc >>= 1;
        }
        t[i] = crc;
    }
    return t;
}

const TABLE = makeTable();

pub fn crc32c(data: []const u8) u32 {
    var crc: u32 = 0xffffffff;
    for (data) |b| {
        crc = TABLE[(crc ^ b) & 0xff] ^ (crc >> 8);
    }
    return crc ^ 0xffffffff;
}

test "crc32c empty and vectors" {
    const std = @import("std");
    try std.testing.expectEqual(@as(u32, 0), crc32c(""));
    try std.testing.expectEqual(@as(u32, 0xe3069283), crc32c("123456789"));
}
