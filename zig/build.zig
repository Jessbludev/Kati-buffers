const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});

    const core = b.addModule("kati", .{
        .root_source_file = b.path("src/kati.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .name = "kati",
        .linkage = .static,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/kati.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(lib);

    const cli = b.addExecutable(.{
        .name = "kati",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    cli.root_module.addImport("kati", core);
    b.installArtifact(cli);

    const run_cmd = b.addRunArtifact(cli);
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run kati CLI");
    run_step.dependOn(&run_cmd.step);

    const test_step = b.step("test", "Run core tests");

    const files = [_][]const u8{
        "tests/core_test.zig",
        "tests/schema_test.zig",
        "tests/value_test.zig",
        "tests/record_test.zig",
        "tests/pretty_test.zig",
        "tests/engine_test.zig",
        "tests/path_test.zig",
        "src/mux.zig",
        "src/kati.zig",
        "src/value.zig",
        "src/io.zig",
        "src/rwx.zig",
        "src/crc.zig",
        "src/block.zig",
        "src/record.zig",
        "src/pretty.zig",
        "src/schema.zig",
        "src/path.zig",
        "src/wal.zig",
    };
    for (files) |file| {
        const t = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(file),
                .target = target,
                .optimize = optimize,
            }),
        });
        if (std.mem.startsWith(u8, file, "tests/")) {
            t.root_module.addImport("kati", core);
        }
        test_step.dependOn(&b.addRunArtifact(t).step);
    }

    const fw = b.addLibrary(.{
        .name = "kati-freestanding",
        .linkage = .static,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/kati.zig"),
            .target = b.resolveTargetQuery(.{ .os_tag = .freestanding }),
            .optimize = optimize,
        }),
    });
    const fw_step = b.step("freestanding", "Compile the core for a freestanding target");
    fw_step.dependOn(&fw.step);
    test_step.dependOn(fw_step);
}
