const std = @import("std");
const kati = @import("kati");

test "reject invalid magic" {
    var data = [_]u8{ 'X', 'B', 'R', 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    try std.testing.expectError(error.InvalidMagic, kati.decodeHeader(&data));
}

test "reject reserved flags" {
    var buf: [32]u8 = undefined;
    _ = try kati.encodeHeader(&buf, .{ .has_schema = true }, 1, 1);
    buf[4] |= 0b1110_0000;
    try std.testing.expectError(error.InvalidFlags, kati.decodeHeader(&buf));
}
