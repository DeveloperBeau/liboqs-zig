//! ZigOQS — safe Zig wrapper around liboqs.
const init = @import("init.zig");

pub const ensureInitialized = init.ensure;
pub const OqsError = @import("errors.zig").OqsError;

pub const testing = struct {
    pub const seedKat = @import("rng.zig").seedKat;
};

pub const version = "0.0.0";

test {
    _ = init;
    _ = @import("rng.zig");
}
