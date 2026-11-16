//! Single import boundary for the liboqs C API. Internal use only.
//! build.zig translates the C API in src/c.h with translate-c and provides it as `c_api`.
pub const c = @import("c_api");
