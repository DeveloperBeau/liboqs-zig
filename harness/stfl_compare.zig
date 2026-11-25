//! Compares the stateful harness outputs of the C reference (stfl_cref) and the
//! typed Zig wrappers (stfl_zref). Like tools/parity.sh, the compare is keyed by
//! (algorithm, field) and checks both directions, so a dropped or extra
//! algorithm or field on either side fails. It also compares the "run" and "skip"
//! lists, so the two sides must agree on which parameter sets are checked, and
//! it requires every checked algorithm to carry all five fields.
//!
//! As a program it takes the file paths: cref list, zref list, cref output and
//! zref output. It prints the result and exits 1 on any mismatch.
const std = @import("std");

/// The fields every checked algorithm must report on both sides.
pub const required_fields = [_][]const u8{ "pk", "sig", "verified", "remaining", "total" };

/// The text of the four files the compare reads.
pub const Inputs = struct {
    cref_list: []const u8,
    zref_list: []const u8,
    cref_out: []const u8,
    zref_out: []const u8,
};

/// What a compare found. It passed when `failures` is 0.
pub const Result = struct {
    checked: usize,
    skipped: usize,
    failures: usize,
};

const Entry = struct { run: bool, height: []const u8 };

/// Compares the two sides, writing one line per problem to `w`.
pub fn compare(gpa: std.mem.Allocator, in: Inputs, w: *std.Io.Writer) !Result {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var failures: usize = 0;
    var c_list: std.StringArrayHashMapUnmanaged(Entry) = .empty;
    var z_list: std.StringArrayHashMapUnmanaged(Entry) = .empty;
    try parseList(arena, in.cref_list, &c_list);
    try parseList(arena, in.zref_list, &z_list);

    var checked: usize = 0;
    var skipped: usize = 0;
    var run_names: std.StringHashMapUnmanaged(void) = .empty;
    for (c_list.keys(), c_list.values()) |name, c_entry| {
        const z_entry = z_list.get(name) orelse {
            try w.print("    LIST MISSING IN ZREF: {s}\n", .{name});
            failures += 1;
            continue;
        };
        if (c_entry.run != z_entry.run or !std.mem.eql(u8, c_entry.height, z_entry.height)) {
            try w.print("    LIST DIFF:            {s}\n", .{name});
            failures += 1;
            continue;
        }
        if (c_entry.run) {
            checked += 1;
            try run_names.put(arena, name, {});
        } else {
            skipped += 1;
        }
    }
    for (z_list.keys()) |name| {
        if (!c_list.contains(name)) {
            try w.print("    LIST MISSING IN CREF: {s}\n", .{name});
            failures += 1;
        }
    }

    if (checked == 0) {
        try w.print("    NOTHING CHECKED: the lists name no algorithm to run\n", .{});
        failures += 1;
    }

    var c_out = std.StringHashMapUnmanaged([]const u8).empty;
    var z_out = std.StringHashMapUnmanaged([]const u8).empty;
    failures += try parseOutput(arena, in.cref_out, &c_out, "CREF", w);
    failures += try parseOutput(arena, in.zref_out, &z_out, "ZREF", w);

    var names = run_names.keyIterator();
    while (names.next()) |name| {
        for (required_fields) |field| {
            const key = try std.fmt.allocPrint(arena, "{s} {s}", .{ name.*, field });
            const c_val = c_out.get(key);
            const z_val = z_out.get(key);
            if (c_val == null) {
                try w.print("    MISSING IN CREF: {s}\n", .{key});
                failures += 1;
            }
            if (z_val == null) {
                try w.print("    MISSING IN ZREF: {s}\n", .{key});
                failures += 1;
            }
            if (c_val != null and z_val != null and !std.mem.eql(u8, c_val.?, z_val.?)) {
                try w.print("    VALUE DIFF:      {s}\n", .{key});
                failures += 1;
            }
        }
    }
    failures += try unexpected(&c_out, &run_names, "CREF", w);
    failures += try unexpected(&z_out, &run_names, "ZREF", w);
    return .{ .checked = checked, .skipped = skipped, .failures = failures };
}

// A list line is "run NAME HEIGHT" or "skip NAME HEIGHT". Other lines are ignored.
fn parseList(arena: std.mem.Allocator, text: []const u8, map: *std.StringArrayHashMapUnmanaged(Entry)) !void {
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var p = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = p.next() orelse continue;
        const name = p.next() orelse continue;
        const height = p.next() orelse continue;
        if (p.next() != null) continue;
        const run = std.mem.eql(u8, kind, "run");
        if (!run and !std.mem.eql(u8, kind, "skip")) continue;
        try map.put(arena, name, .{ .run = run, .height = height });
    }
}

// An output line is "NAME FIELD HEX". Other lines are ignored. A key that
// appears twice with different values counts as a failure.
fn parseOutput(
    arena: std.mem.Allocator,
    text: []const u8,
    map: *std.StringHashMapUnmanaged([]const u8),
    side: []const u8,
    w: *std.Io.Writer,
) !usize {
    var failures: usize = 0;
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var p = std.mem.tokenizeScalar(u8, line, ' ');
        const name = p.next() orelse continue;
        const field = p.next() orelse continue;
        const hex = p.next() orelse continue;
        if (p.next() != null) continue;
        const key = try std.fmt.allocPrint(arena, "{s} {s}", .{ name, field });
        if (map.get(key)) |old| {
            if (!std.mem.eql(u8, old, hex)) {
                try w.print("    DUPLICATE IN {s}: {s}\n", .{ side, key });
                failures += 1;
            }
            continue;
        }
        try map.put(arena, key, hex);
    }
    return failures;
}

// Reports output for an algorithm that the lists did not say to run.
fn unexpected(
    map: *std.StringHashMapUnmanaged([]const u8),
    run_names: *std.StringHashMapUnmanaged(void),
    side: []const u8,
    w: *std.Io.Writer,
) !usize {
    var failures: usize = 0;
    var keys = map.keyIterator();
    while (keys.next()) |key| {
        const sp = std.mem.indexOfScalar(u8, key.*, ' ').?;
        if (!run_names.contains(key.*[0..sp])) {
            try w.print("    UNEXPECTED IN {s}: {s}\n", .{ side, key.* });
            failures += 1;
        }
    }
    return failures;
}

/// Prints each skipped name from a list, as the script shows them to the caller.
pub fn printSkipped(list: []const u8, w: *std.Io.Writer, max_height: u32) !void {
    var lines = std.mem.tokenizeScalar(u8, list, '\n');
    while (lines.next()) |line| {
        var p = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = p.next() orelse continue;
        const name = p.next() orelse continue;
        const height = p.next() orelse continue;
        if (!std.mem.eql(u8, kind, "skip")) continue;
        try w.print("    skipping {s}, total height {s} > {d} (set OQS_STATEFUL_ALL=1 to run)\n", .{ name, height, max_height });
    }
}

pub fn main(init: std.process.Init.Minimal) !void {
    const io = std.Io.Threaded.global_single_threaded.io();
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();
    var buf: [4096]u8 = undefined;
    var fw = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &fw.interface;

    var args = init.args.iterate();
    _ = args.skip();
    var paths: [4][]const u8 = undefined;
    for (&paths) |*p| p.* = args.next() orelse {
        std.debug.print("usage: stfl_compare CREF_LIST ZREF_LIST CREF_OUT ZREF_OUT\n", .{});
        std.process.exit(2);
    };
    var texts: [4][]u8 = undefined;
    var read: usize = 0;
    defer for (texts[0..read]) |t| gpa.free(t);
    for (paths, 0..) |path, i| {
        texts[i] = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 30));
        read += 1;
    }
    const result = try compare(gpa, .{
        .cref_list = texts[0],
        .zref_list = texts[1],
        .cref_out = texts[2],
        .zref_out = texts[3],
    }, w);
    try printSkipped(texts[0], w, @import("stfl_filter").max_default_height);
    try w.print("    {d} algorithms checked, {d} skipped\n", .{ result.checked, result.skipped });
    if (result.failures != 0) {
        try w.print("STATEFUL PARITY FAILED: {d} problems\n", .{result.failures});
        try fw.flush();
        std.process.exit(1);
    }
    try w.print("STATEFUL PARITY OK: cref and the typed wrappers are byte-identical across {d} algorithms ({d} skipped)\n", .{ result.checked, result.skipped });
    try fw.flush();
}
