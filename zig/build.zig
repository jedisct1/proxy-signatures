const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Module for the proxy signatures library
    const proxy_signatures_module = b.addModule("proxy-signatures", .{
        .root_source_file = b.path("src/proxy_signatures.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Demo executable
    const demo = b.addExecutable(.{
        .name = "demo",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/demo.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "proxy-signatures", .module = proxy_signatures_module },
            },
        }),
    });
    b.installArtifact(demo);

    // Run demo command
    const run_demo = b.addRunArtifact(demo);
    run_demo.step.dependOn(b.getInstallStep());
    const run_demo_step = b.step("run", "Run the demo application");
    run_demo_step.dependOn(&run_demo.step);

    // Tests
    const lib_tests = b.addTest(.{
        .root_module = proxy_signatures_module,
    });
    const run_lib_tests = b.addRunArtifact(lib_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_tests.step);
}
