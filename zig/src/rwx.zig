//! POSIX-style rwx bits applied to fields and buffers.
//! Unspecified (0) is treated as rwx — the same default as an 0777-style open.

pub const R: u8 = 0b100;
pub const W: u8 = 0b010;
pub const X: u8 = 0b001;
pub const RW: u8 = R | W;
pub const RX: u8 = R | X;
pub const WX: u8 = W | X;
pub const RWX: u8 = R | W | X;

pub fn effective(field_perms: u8) u8 {
    return if (field_perms == 0) RWX else field_perms;
}

pub fn can(field_perms: u8, want: u8) bool {
    return effective(field_perms) & want == want;
}

pub fn canRead(field_perms: u8) bool {
    return can(field_perms, R);
}

pub fn canWrite(field_perms: u8) bool {
    return can(field_perms, W);
}

pub fn canExecute(field_perms: u8) bool {
    return can(field_perms, X);
}

pub fn chmod(_: u8, next: u8) u8 {
    return next & RWX;
}

pub fn fromOctal(mode: u32) u8 {
    var bits: u8 = 0;
    if (mode & 0o400 != 0) bits |= R;
    if (mode & 0o200 != 0) bits |= W;
    if (mode & 0o100 != 0) bits |= X;
    return bits;
}

pub fn toOctal(field_perms: u8) u32 {
    const p = effective(field_perms);
    var mode: u32 = 0;
    if (p & R != 0) mode |= 0o400;
    if (p & W != 0) mode |= 0o200;
    if (p & X != 0) mode |= 0o100;
    return mode;
}

test "unspecified is rwx" {
    const std = @import("std");
    try std.testing.expect(canRead(0) and canWrite(0) and canExecute(0));
    try std.testing.expect(canRead(R));
    try std.testing.expect(!canWrite(R));
    try std.testing.expectEqual(@as(u8, RW), chmod(R, RW));
    try std.testing.expectEqual(@as(u8, R | W), fromOctal(0o644));
    try std.testing.expectEqual(@as(u32, 0o600), toOctal(RW));
}
