const std = @import("std");
const kati = @import("kati");
const value = kati.value;

test "bytes roundtrip" {
    var buf: [32]u8 = undefined;
    var w = kati.Writer.init(&buf);
    try value.writeBytes(&w, "hello");
    var r = kati.Reader.init(buf[0..w.pos]);
    try std.testing.expectEqualStrings("hello", try value.readBytes(&r));
}

test "unknown field can be skipped" {
    var buf: [32]u8 = undefined;
    var w = kati.Writer.init(&buf);
    try value.writeFieldHeader(&w, 99, .varint);
    try value.writeUnsigned(&w, 1234);
    try value.writeFieldHeader(&w, 2, .bytes);
    try value.writeBytes(&w, "ok");
    var r = kati.Reader.init(buf[0..w.pos]);
    const a = try value.readFieldHeader(&r);
    try value.skipValue(&r, a.wire_type);
    const b = try value.readFieldHeader(&r);
    try std.testing.expectEqual(@as(u32, 2), b.field_id);
    try std.testing.expectEqualStrings("ok", try value.readBytes(&r));
}
