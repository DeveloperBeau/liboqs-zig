//! The text lines of the liboqs known-answer programs `kat_kem` and `kat_sig`.
//! Each helper prints one line in the exact form of the C program, so the
//! SHA-256 of the whole text matches the digest in `kats.json`.
const std = @import("std");

/// The line printers of the known-answer text.
pub const KatText = struct {
    const hex_digits = "0123456789ABCDEF";

    /// Writes `label`, the bytes as upper-case hexadecimal and a newline.
    ///
    /// This is `OQS_fprintBstr`. An empty value prints as `00`.
    pub fn writeBstr(w: *std.Io.Writer, label: []const u8, bytes: []const u8) std.Io.Writer.Error!void {
        try w.writeAll(label);
        if (bytes.len == 0) {
            try w.writeAll("00");
        }
        var chunk: [512]u8 = undefined;
        var rest = bytes;
        while (rest.len > 0) {
            const n: usize = @min(rest.len, chunk.len / 2);
            for (rest[0..n], 0..) |byte, i| {
                chunk[2 * i] = hex_digits[byte >> 4];
                chunk[2 * i + 1] = hex_digits[byte & 0x0F];
            }
            try w.writeAll(chunk[0 .. 2 * n]);
            rest = rest[n..];
        }
        try w.writeAll("\n");
    }

    /// Writes `count = <n>` and a newline.
    pub fn writeCount(w: *std.Io.Writer, count: usize) std.Io.Writer.Error!void {
        try w.print("count = {d}\n", .{count});
    }

    /// Writes `<label> = <n>` and a newline, as for `mlen` and `smlen`.
    pub fn writeLength(w: *std.Io.Writer, label: []const u8, length: usize) std.Io.Writer.Error!void {
        try w.print("{s} = {d}\n", .{ label, length });
    }

    /// Writes the empty line that separates two counts.
    pub fn writeSeparator(w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.writeAll("\n");
    }
};
