//! The expected digests of a liboqs `kats.json` file.
//!
//! The file maps an algorithm name to an object with two keys. `single` is the
//! SHA-256 of the program output for count 0. `all` is the SHA-256 of the
//! output for every count.
const std = @import("std");

/// The digests of one `kats.json` file, by algorithm name.
pub const KatDigests = struct {
    /// Which of the two digests of an algorithm to use.
    pub const Mode = enum {
        /// The program output for count 0 only.
        single,
        /// The program output for every count.
        all,
    };

    /// The two digests of one algorithm, as 64 lower-case hexadecimal characters each.
    pub const Entry = struct {
        single: [64]u8,
        all: [64]u8,

        /// True if `digest` is the SHA-256 that this entry holds for `mode`.
        pub fn matches(self: Entry, mode: Mode, digest: [32]u8) bool {
            const hex = std.fmt.bytesToHex(digest, .lower);
            const expected = switch (mode) {
                .single => self.single,
                .all => self.all,
            };
            return std.mem.eql(u8, &expected, &hex);
        }
    };

    /// Why a `kats.json` text did not parse.
    pub const ParseError = error{
        /// The text is not valid JSON, or it ends early.
        SyntaxError,
        /// The text is JSON but not a map of names to `single` and `all` digests.
        UnexpectedShape,
        /// A digest is not 64 lower-case hexadecimal characters.
        InvalidDigest,
        /// Two entries have the same name, or one entry repeats a key.
        DuplicateName,
        OutOfMemory,
    };

    const Item = struct { name: []u8, entry: Entry };

    arena: std.heap.ArenaAllocator,
    items: []const Item,

    /// Reads `text`. The result owns copies of the names.
    pub fn parse(allocator: std.mem.Allocator, text: []const u8) ParseError!KatDigests {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const a = arena.allocator();
        var scanner = std.json.Scanner.initCompleteInput(a, text);
        var items: std.ArrayList(Item) = .empty;

        try expect(&scanner, a, .object_begin);
        while (true) {
            const key = try nextToken(&scanner, a);
            const name = switch (key) {
                .object_end => break,
                .string, .allocated_string => |s| s,
                else => return error.UnexpectedShape,
            };
            for (items.items) |item| {
                if (std.mem.eql(u8, item.name, name)) return error.DuplicateName;
            }
            const entry = try parseEntry(&scanner, a);
            try items.append(a, .{ .name = try a.dupe(u8, name), .entry = entry });
        }
        try expect(&scanner, a, .end_of_document);
        return .{ .arena = arena, .items = items.items };
    }

    /// Frees the names.
    pub fn deinit(self: *KatDigests) void {
        self.arena.deinit();
        self.* = undefined;
    }

    /// The number of algorithms in the file.
    pub fn count(self: KatDigests) usize {
        return self.items.len;
    }

    /// The name of the `index`th entry, in file order.
    pub fn nameAt(self: KatDigests, index: usize) []const u8 {
        return self.items[index].name;
    }

    /// The entry of `name`. The name must be equal byte for byte.
    pub fn find(self: KatDigests, name: []const u8) ?Entry {
        for (self.items) |item| {
            if (std.mem.eql(u8, item.name, name)) return item.entry;
        }
        return null;
    }

    fn nextToken(scanner: *std.json.Scanner, a: std.mem.Allocator) ParseError!std.json.Token {
        return scanner.nextAlloc(a, .alloc_if_needed) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.SyntaxError,
        };
    }

    fn expect(scanner: *std.json.Scanner, a: std.mem.Allocator, want: std.meta.Tag(std.json.Token)) ParseError!void {
        const token = try nextToken(scanner, a);
        if (std.meta.activeTag(token) != want) return error.UnexpectedShape;
    }

    fn parseEntry(scanner: *std.json.Scanner, a: std.mem.Allocator) ParseError!Entry {
        try expect(scanner, a, .object_begin);
        var single: ?[64]u8 = null;
        var all: ?[64]u8 = null;
        while (true) {
            const key = switch (try nextToken(scanner, a)) {
                .object_end => break,
                .string, .allocated_string => |s| s,
                else => return error.UnexpectedShape,
            };
            const slot = if (std.mem.eql(u8, key, "single"))
                &single
            else if (std.mem.eql(u8, key, "all"))
                &all
            else
                return error.UnexpectedShape;
            if (slot.* != null) return error.DuplicateName;
            const value = switch (try nextToken(scanner, a)) {
                .string, .allocated_string => |s| s,
                else => return error.UnexpectedShape,
            };
            slot.* = try digestFrom(value);
        }
        return .{
            .single = single orelse return error.UnexpectedShape,
            .all = all orelse return error.UnexpectedShape,
        };
    }

    fn digestFrom(text: []const u8) ParseError![64]u8 {
        if (text.len != 64) return error.InvalidDigest;
        for (text) |ch| {
            if (!std.ascii.isDigit(ch) and !(ch >= 'a' and ch <= 'f')) return error.InvalidDigest;
        }
        return text[0..64].*;
    }
};
