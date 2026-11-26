const std = @import("std");

/// The names of the enabled algorithms of one kind, in liboqs order, read one at a time with no allocation.
///
/// Get one from `oqs.Registry.kemNames`, `sigNames` or `sigStflNames`. It walks
/// the liboqs identifier list and skips the names this build does not enable.
pub const AlgorithmNames = struct {
    /// The position in the liboqs identifier list of the next name to read.
    index: usize,
    /// The number of identifiers in the liboqs list, enabled or not.
    total: usize,
    /// The liboqs function that returns the identifier at a position.
    identifierAt: *const fn (usize) callconv(.c) [*c]const u8,
    /// The liboqs function that says whether this build enables a name.
    isEnabled: *const fn ([*c]const u8) callconv(.c) c_int,

    /// The next enabled name, or null after the last one.
    ///
    /// The name points at a static liboqs string, so it lives as long as the program.
    pub fn next(self: *AlgorithmNames) ?[:0]const u8 {
        while (self.index < self.total) {
            // liboqs returns a string literal for every position below its
            // count, so the identifier is never null here.
            const identifier = self.identifierAt(self.index);
            self.index += 1;
            if (self.isEnabled(identifier) != 1) continue;
            return std.mem.span(@as([*:0]const u8, identifier));
        }
        return null;
    }
};

// Stand-ins for the liboqs list functions. Every liboqs identifier is enabled
// in this build, so only a stand-in can show that a disabled name is skipped.
const StandIn = struct {
    const identifiers = [_][*:0]const u8{ "First-1", "Off-2", "Middle-3", "Off-4", "Last-5" };

    fn identifierAt(i: usize) callconv(.c) [*c]const u8 {
        return identifiers[i];
    }

    fn isEnabled(name: [*c]const u8) callconv(.c) c_int {
        return @intFromBool(!std.mem.startsWith(u8, std.mem.span(@as([*:0]const u8, name)), "Off-"));
    }
};

test "next skips the names liboqs reports as disabled, keeps the order and stops after the last one" {
    var it = AlgorithmNames{
        .index = 0,
        .total = StandIn.identifiers.len,
        .identifierAt = StandIn.identifierAt,
        .isEnabled = StandIn.isEnabled,
    };
    try std.testing.expectEqualStrings("First-1", it.next().?);
    try std.testing.expectEqualStrings("Middle-3", it.next().?);
    try std.testing.expectEqualStrings("Last-5", it.next().?);
    try std.testing.expect(it.next() == null);
    try std.testing.expect(it.next() == null);
}

test "next gives nothing for an empty list" {
    var it = AlgorithmNames{ .index = 0, .total = 0, .identifierAt = StandIn.identifierAt, .isEnabled = StandIn.isEnabled };
    try std.testing.expect(it.next() == null);
}
