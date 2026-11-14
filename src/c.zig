//! Single import boundary for the liboqs C API. Internal use only.
//! The translated C module is wired in by build.zig (`@cImport` is gone).
pub const c = @import("c_api");
