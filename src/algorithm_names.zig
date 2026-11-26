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
