//! Total tree height of a stateful signature name, and the default height cutoff
//! for the stateful parity run. The harness and the unit tests share this file,
//! so there is one rule for which parameter sets run by default.
//!
//! Key generation cost grows with tree height. Debug builds need hours at
//! height 20 and above, so the default run keeps to 16 or less and the rest
//! run only when asked for.
const std = @import("std");

/// The largest total tree height that runs without `OQS_STATEFUL_ALL=1`.
pub const max_default_height: u32 = 16;

/// The total tree height from a liboqs name, or null if the name has no valid shape.
///
/// `XMSS-SHA2_10_256` is 10, `XMSSMT-SHA2_20/2_256` is 20 (the number before the
/// slash) and `LMS_SHA256_H10_W4_H5_W8` is 10 + 5.
pub fn totalHeight(name: []const u8) ?u32 {
    if (std.mem.startsWith(u8, name, "LMS_")) return lmsHeight(name["LMS_".len..]);
    var it = std.mem.splitScalar(u8, name, '_');
    const family = it.next().?;
    const height_field = it.next() orelse return null;
    const param_field = it.next() orelse return null;
    if (it.next() != null) return null;
    if (parseNumber(param_field) == null) return null;
    if (std.mem.startsWith(u8, family, "XMSSMT-") and family.len > "XMSSMT-".len) {
        const slash = std.mem.indexOfScalar(u8, height_field, '/') orelse return null;
        if (parseNumber(height_field[slash + 1 ..]) == null) return null;
        return parseNumber(height_field[0..slash]);
    }
    if (std.mem.startsWith(u8, family, "XMSS-") and family.len > "XMSS-".len) {
        return parseNumber(height_field);
    }
    return null;
}

/// True if a parameter set runs when `OQS_STATEFUL_ALL` is not set.
pub fn includedByDefault(name: []const u8) bool {
    const h = totalHeight(name) orelse return false;
    return h <= max_default_height;
}

/// True if a parameter set runs, given whether `OQS_STATEFUL_ALL=1` is set.
pub fn isIncluded(name: []const u8, all: bool) bool {
    return all or includedByDefault(name);
}

// The part after "LMS_" is a hash name, then one or two "H<height>_W<width>" levels.
fn lmsHeight(rest: []const u8) ?u32 {
    var it = std.mem.splitScalar(u8, rest, '_');
    const hash = it.next().?;
    if (hash.len == 0) return null;
    var sum: u32 = 0;
    var levels: usize = 0;
    while (it.next()) |h_field| {
        const w_field = it.next() orelse return null;
        if (h_field.len < 2 or h_field[0] != 'H') return null;
        if (w_field.len < 2 or w_field[0] != 'W') return null;
        const h = parseNumber(h_field[1..]) orelse return null;
        _ = parseNumber(w_field[1..]) orelse return null;
        sum = std.math.add(u32, sum, h) catch return null;
        levels += 1;
    }
    if (levels < 1 or levels > 2) return null;
    return sum;
}

// Plain decimal digits only: no sign, no separators, no leading zero.
fn parseNumber(s: []const u8) ?u32 {
    if (s.len == 0) return null;
    if (s.len > 1 and s[0] == '0') return null;
    for (s) |ch| if (ch < '0' or ch > '9') return null;
    return std.fmt.parseInt(u32, s, 10) catch null;
}
