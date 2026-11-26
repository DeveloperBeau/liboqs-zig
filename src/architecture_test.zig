//! Ring check for the entities: the plain data files may import only std and
//! each other. The repo-wide check of every ring is not here yet.
const std = @import("std");

const Entity = struct { file: []const u8, source: []const u8 };

// Every entity file, read at compile time so the check needs no file system.
const entities = [_]Entity{
    .{ .file = "errors.zig", .source = @embedFile("errors.zig") },
    .{ .file = "kem_description.zig", .source = @embedFile("kem_description.zig") },
    .{ .file = "sig_description.zig", .source = @embedFile("sig_description.zig") },
    .{ .file = "sig_stfl_description.zig", .source = @embedFile("sig_stfl_description.zig") },
};

// Walks the `@import("...")` calls of a Zig source file in order.
const ImportScanner = struct {
    source: []const u8,
    at: usize = 0,

    fn next(self: *ImportScanner) ?[]const u8 {
        const marker = "@import(";
        while (std.mem.indexOfPos(u8, self.source, self.at, marker)) |found| {
            var i = found + marker.len;
            self.at = i;
            while (i < self.source.len and std.ascii.isWhitespace(self.source[i])) i += 1;
            if (i >= self.source.len or self.source[i] != '"') continue;
            const start = i + 1;
            const end = std.mem.indexOfScalarPos(u8, self.source, start, '"') orelse return null;
            self.at = end + 1;
            return self.source[start..end];
        }
        return null;
    }
};

fn isEntityFile(file: []const u8) bool {
    for (entities) |e| {
        if (std.mem.eql(u8, e.file, file)) return true;
    }
    return false;
}

// The first import of `source` that an entity may not have, or null.
fn firstOutwardImport(source: []const u8) ?[]const u8 {
    var scanner = ImportScanner{ .source = source };
    while (scanner.next()) |target| {
        if (std.mem.eql(u8, target, "std")) continue;
        if (isEntityFile(target)) continue;
        return target;
    }
    return null;
}

test "every entity file imports only std and other entity files" {
    for (entities) |e| {
        if (firstOutwardImport(e.source)) |target| {
            std.debug.print("{s} imports {s}, which is outside the entities ring\n", .{ e.file, target });
            return error.TestUnexpectedResult;
        }
    }
}

test "every description file that root.zig exports is checked as an entity" {
    var scanner = ImportScanner{ .source = @embedFile("root.zig") };
    var described: usize = 0;
    while (scanner.next()) |target| {
        if (!std.mem.endsWith(u8, target, "_description.zig")) continue;
        described += 1;
        if (!isEntityFile(target)) {
            std.debug.print("{s} is exported by root.zig but is not in the entity list\n", .{target});
            return error.TestUnexpectedResult;
        }
    }
    // KemDescription, SigDescription and SigStflDescription.
    try std.testing.expectEqual(@as(usize, 3), described);
}

test "the import check flags an outward import and passes std and entity imports" {
    try std.testing.expectEqualStrings("c.zig", firstOutwardImport(
        \\const std = @import("std");
        \\const c = @import("c.zig").c;
    ).?);
    try std.testing.expectEqualStrings("registry.zig", firstOutwardImport(
        \\const Registry = @import( "registry.zig" ).Registry;
    ).?);
    try std.testing.expectEqualStrings("init.zig", firstOutwardImport(
        \\const E = @import("errors.zig").OqsError;
        \\const init = @import("init.zig");
    ).?);
    try std.testing.expect(firstOutwardImport(
        \\const std = @import("std");
        \\const E = @import("errors.zig").OqsError;
        \\const K = @import("kem_description.zig").KemDescription;
    ) == null);
    try std.testing.expect(firstOutwardImport("pub const X = struct {};") == null);
}
