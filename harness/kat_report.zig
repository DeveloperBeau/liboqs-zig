//! The result lines of a known-answer run and the check that reads them back.
//!
//! A run prints one line per algorithm: `<kind> <name> digest <sha256>` or
//! `<kind> <name> noentry`. The check compares each digest with `kats.json`
//! in one place. It also fails when an enabled algorithm that has an entry
//! was not reported, so the run cannot skip one silently.
const std = @import("std");
const KatDigests = @import("kat_digests.zig").KatDigests;

/// The result lines and their check.
pub const KatReport = struct {
    /// Which kind of algorithm a line is about.
    pub const Kind = enum { kem, sig };

    /// What `summarize` found.
    pub const Summary = struct {
        kems_checked: usize = 0,
        sigs_checked: usize = 0,
        kems_without_entry: usize = 0,
        sigs_without_entry: usize = 0,
        kem_entries_not_enabled: usize = 0,
        sig_entries_not_enabled: usize = 0,
        /// The number of mismatches, missing, duplicate and unexpected lines.
        problems: usize = 0,
    };

    /// What `summarize` reads.
    pub const Input = struct {
        /// The enabled KEM names the run was asked to cover.
        kem_names: []const []const u8,
        /// The enabled signature names the run was asked to cover.
        sig_names: []const []const u8,
        kem_digests: *const KatDigests,
        sig_digests: *const KatDigests,
        mode: KatDigests.Mode,
        /// The result lines of every shard.
        lines: []const u8,
        /// True if the run covered only some of the enabled names.
        filtered: bool,
        /// The liboqs version, for the last line.
        version: []const u8,
    };

    /// Writes the line of an algorithm whose digest was computed.
    pub fn writeDigest(w: *std.Io.Writer, kind: Kind, name: []const u8, digest: [32]u8) std.Io.Writer.Error!void {
        const hex = std.fmt.bytesToHex(digest, .lower);
        try w.print("{s} {s} digest {s}\n", .{ @tagName(kind), name, &hex });
    }

    /// Writes the line of an algorithm that `kats.json` has no entry for.
    pub fn writeNoEntry(w: *std.Io.Writer, kind: Kind, name: []const u8) std.Io.Writer.Error!void {
        try w.print("{s} {s} noentry\n", .{ @tagName(kind), name });
    }

    const Seen = struct { kind: Kind, name: []const u8 };

    /// Checks `input.lines` against the digest files and the enabled names, and prints the result to `w`.
    ///
    /// The last line printed is `KAT OK: ...` or `KAT FAILED: ...`.
    pub fn summarize(allocator: std.mem.Allocator, w: *std.Io.Writer, input: Input) !Summary {
        var summary = Summary{};
        var seen: std.ArrayList(Seen) = .empty;
        defer seen.deinit(allocator);
        var without_entry: [2]std.ArrayList([]const u8) = .{ .empty, .empty };
        defer for (&without_entry) |*list| list.deinit(allocator);

        var lines = std.mem.tokenizeScalar(u8, input.lines, '\n');
        while (lines.next()) |line| {
            var parts = std.mem.tokenizeScalar(u8, line, ' ');
            const kind_text = parts.next() orelse continue;
            const name = parts.next() orelse "";
            const status = parts.next() orelse "";
            const kind: Kind = if (std.mem.eql(u8, kind_text, "kem"))
                .kem
            else if (std.mem.eql(u8, kind_text, "sig"))
                .sig
            else {
                try problem(w, &summary, "malformed line: {s}", .{line});
                continue;
            };
            const names = if (kind == .kem) input.kem_names else input.sig_names;
            if (!contains(names, name)) {
                try problem(w, &summary, "UNEXPECTED {s} {s}: the run was not asked to cover it", .{ kind_text, name });
                continue;
            }
            if (wasSeen(seen.items, kind, name)) {
                try problem(w, &summary, "DUPLICATE {s} {s}: reported twice", .{ kind_text, name });
                continue;
            }
            try seen.append(allocator, .{ .kind = kind, .name = name });

            const digests = if (kind == .kem) input.kem_digests else input.sig_digests;
            const entry = digests.find(name);
            if (std.mem.eql(u8, status, "noentry")) {
                if (entry != null) {
                    try problem(w, &summary, "{s} {s}: reported without an entry, but kats.json has one", .{ kind_text, name });
                    continue;
                }
                try without_entry[@backingInt(kind)].append(allocator, name);
                if (kind == .kem) summary.kems_without_entry += 1 else summary.sigs_without_entry += 1;
                continue;
            }
            const found = entry orelse {
                try problem(w, &summary, "{s} {s}: a digest was reported but kats.json has no entry", .{ kind_text, name });
                continue;
            };
            const actual_hex = parts.next() orelse "";
            var actual: [32]u8 = undefined;
            if (!std.mem.eql(u8, status, "digest") or !decodeDigest(actual_hex, &actual)) {
                try problem(w, &summary, "malformed line: {s}", .{line});
                continue;
            }
            if (!found.matches(input.mode, actual)) {
                const expected = if (input.mode == .single) found.single else found.all;
                try problem(w, &summary, "MISMATCH {s} {s} ({s})\n        expected {s}\n        actual   {s}", .{ kind_text, name, @tagName(input.mode), &expected, actual_hex });
                continue;
            }
            if (kind == .kem) summary.kems_checked += 1 else summary.sigs_checked += 1;
        }

        for (input.kem_names) |name| {
            if (!wasSeen(seen.items, .kem, name)) try problem(w, &summary, "NOT REPORTED kem {s}: an enabled algorithm was skipped", .{name});
        }
        for (input.sig_names) |name| {
            if (!wasSeen(seen.items, .sig, name)) try problem(w, &summary, "NOT REPORTED sig {s}: an enabled algorithm was skipped", .{name});
        }
        if (!input.filtered) {
            summary.kem_entries_not_enabled = entriesNotIn(input.kem_digests, input.kem_names);
            summary.sig_entries_not_enabled = entriesNotIn(input.sig_digests, input.sig_names);
        }

        try w.print("    {d} KEMs checked, {d} signatures checked, {d} enabled KEMs and {d} enabled signatures without an entry\n", .{
            summary.kems_checked,
            summary.sigs_checked,
            summary.kems_without_entry,
            summary.sigs_without_entry,
        });
        try writeNames(w, "enabled KEMs without an entry", without_entry[0].items);
        try writeNames(w, "enabled signatures without an entry", without_entry[1].items);
        if (!input.filtered) {
            try w.print("    entries not enabled in this build: {d} KEMs, {d} signatures\n", .{ summary.kem_entries_not_enabled, summary.sig_entries_not_enabled });
        }
        if (summary.problems != 0) {
            try w.print("KAT FAILED: {d} problems\n", .{summary.problems});
        } else {
            try w.print("KAT OK: {d} KEMs and {d} signatures match liboqs {s} kats.json ({s})\n", .{ summary.kems_checked, summary.sigs_checked, input.version, @tagName(input.mode) });
        }
        return summary;
    }

    fn problem(w: *std.Io.Writer, summary: *Summary, comptime format: []const u8, args: anytype) !void {
        summary.problems += 1;
        try w.print("    " ++ format ++ "\n", args);
    }

    // True if `text` is 64 hexadecimal characters, which are then in `out`.
    fn decodeDigest(text: []const u8, out: *[32]u8) bool {
        if (text.len != 64) return false;
        _ = std.fmt.hexToBytes(out, text) catch return false;
        return true;
    }

    fn contains(names: []const []const u8, name: []const u8) bool {
        for (names) |candidate| {
            if (std.mem.eql(u8, candidate, name)) return true;
        }
        return false;
    }

    fn wasSeen(seen: []const Seen, kind: Kind, name: []const u8) bool {
        for (seen) |item| {
            if (item.kind == kind and std.mem.eql(u8, item.name, name)) return true;
        }
        return false;
    }

    fn entriesNotIn(digests: *const KatDigests, names: []const []const u8) usize {
        var missing: usize = 0;
        for (0..digests.count()) |i| {
            if (!contains(names, digests.nameAt(i))) missing += 1;
        }
        return missing;
    }

    // Prints names in rows that stay under about 100 columns.
    fn writeNames(w: *std.Io.Writer, label: []const u8, names: []const []const u8) !void {
        if (names.len == 0) return;
        try w.print("    {s}:", .{label});
        var column: usize = 0;
        for (names, 0..) |name, i| {
            if (i > 0) try w.writeAll(",");
            if (column == 0 or column + name.len > 96) {
                try w.writeAll("\n      ");
                column = 0;
            } else {
                try w.writeAll(" ");
            }
            try w.writeAll(name);
            column += name.len + 2;
        }
        try w.writeAll("\n");
    }
};
