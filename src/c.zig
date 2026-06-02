//! Single import boundary for the liboqs C API. Internal use only.
pub const c = @cImport({
    @cInclude("oqs/oqs.h");
    @cInclude("oqs/rand_nist.h");
});
