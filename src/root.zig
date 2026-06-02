//! ZigOQS — safe Zig wrapper around liboqs.
const init = @import("init.zig");

pub const ensureInitialized = init.ensure;
pub const OqsError = @import("errors.zig").OqsError;

pub const Kem = @import("kem.zig").Kem;
pub const Sig = @import("sig.zig").Sig;

pub const testing = struct {
    pub const seedKat = @import("rng.zig").seedKat;
};

pub const version = "0.0.0";

test {
    _ = init;
    _ = @import("rng.zig");
    _ = @import("kem.zig");
    _ = @import("sig.zig");
}
