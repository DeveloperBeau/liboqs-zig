//! The layout of the signed message `sm` that `kat_sig` prints for a scheme.
const std = @import("std");

/// How `kat_sig` puts the message and the signature together, chosen by scheme name.
pub const SignedMessageForm = enum {
    /// The signature, then the message.
    signature_then_message,
    /// The message, then the signature.
    message_then_signature,
    /// Falcon-512: signature length, salt, message, the byte 0x29 and the rest.
    falcon_512,
    /// Falcon-1024: signature length, salt, message, the byte 0x2A and the rest.
    falcon_1024,

    /// Why `combine` could not build a signed message.
    pub const Error = error{
        /// A Falcon signature is shorter than its header byte and salt.
        SignatureTooShort,
        OutOfMemory,
    };

    const falcon_salt_len = 40;
    const falcon_header_len = 1 + falcon_salt_len;

    /// The layout `kat_sig` uses for `name`, or null if it has none.
    ///
    /// A scheme with no layout, such as SLH-DSA, has no `kat_sig` run. The C
    /// program lists 65 names and this matches them by family prefix.
    pub fn of(name: []const u8) ?SignedMessageForm {
        if (std.mem.eql(u8, name, "Falcon-512")) return .falcon_512;
        if (std.mem.eql(u8, name, "Falcon-1024")) return .falcon_1024;
        const signature_first = [_][]const u8{ "ML-DSA-", "Falcon-padded-", "MAYO-", "SNOVA_" };
        for (signature_first) |prefix| {
            if (std.mem.startsWith(u8, name, prefix)) return .signature_then_message;
        }
        const message_first = [_][]const u8{ "cross-rsdp", "OV-", "mqom2_" };
        for (message_first) |prefix| {
            if (std.mem.startsWith(u8, name, prefix)) return .message_then_signature;
        }
        return null;
    }

    /// Builds the signed message of this layout. The caller owns the result.
    pub fn combine(self: SignedMessageForm, allocator: std.mem.Allocator, message: []const u8, signature: []const u8) Error![]u8 {
        switch (self) {
            .signature_then_message => return join(allocator, signature, message),
            .message_then_signature => return join(allocator, message, signature),
            .falcon_512 => return falcon(allocator, message, signature, 0x29),
            .falcon_1024 => return falcon(allocator, message, signature, 0x2A),
        }
    }

    fn join(allocator: std.mem.Allocator, first: []const u8, second: []const u8) Error![]u8 {
        const out = try allocator.alloc(u8, first.len + second.len);
        @memcpy(out[0..first.len], first);
        @memcpy(out[first.len..], second);
        return out;
    }

    // The Falcon signature starts with a header byte and a 40-byte salt. The
    // signed message moves the salt before the message and writes a length
    // that does not count the header byte or the salt.
    fn falcon(allocator: std.mem.Allocator, message: []const u8, signature: []const u8, tag: u8) Error![]u8 {
        if (signature.len < falcon_header_len) return error.SignatureTooShort;
        const out = try allocator.alloc(u8, 2 + signature.len + message.len);
        const length: u16 = @truncate(signature.len - falcon_salt_len);
        std.mem.writeInt(u16, out[0..2], length, .big);
        const salt = signature[1..falcon_header_len];
        @memcpy(out[2 .. 2 + falcon_salt_len], salt);
        const message_at = 2 + falcon_salt_len;
        @memcpy(out[message_at .. message_at + message.len], message);
        out[message_at + message.len] = tag;
        @memcpy(out[message_at + message.len + 1 ..], signature[falcon_header_len..]);
        return out;
    }
};
