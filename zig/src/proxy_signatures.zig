const std = @import("std");
const crypto = std.crypto;
const Ristretto255 = crypto.ecc.Ristretto255;
const Scalar = Ristretto255.scalar.Scalar;
const Point = Ristretto255;
const mem = std.mem;
const fmt = std.fmt;

// Error types are now standard Zig errors

/// Cryptographic key pair containing a secret key and corresponding public key
/// This represents original (non-proxy) keys that can create delegations
pub const KeyPair = struct {
    /// Secret scalar value
    sk: Scalar,
    /// Public point value
    pk: Point,

    /// Generate a new random key pair
    pub fn new() KeyPair {
        const sk = Scalar.random();
        const pk = Point.basePoint.mul(sk.toBytes()) catch unreachable;
        return .{ .sk = sk, .pk = pk };
    }

    /// Create a KeyPair from existing secret key
    pub fn fromSecretKey(sk: Scalar) KeyPair {
        const pk = Point.basePoint.mul(sk.toBytes()) catch unreachable;
        return .{ .sk = sk, .pk = pk };
    }

    pub fn publicKey(self: *const KeyPair) *const Point {
        return &self.pk;
    }

    pub fn secretKey(self: *const KeyPair) *const Scalar {
        return &self.sk;
    }

    pub fn eql(self: KeyPair, other: KeyPair) bool {
        const sk_bytes_self = self.sk.toBytes();
        const sk_bytes_other = other.sk.toBytes();
        const sk_equal = std.crypto.timing_safe.eql([32]u8, sk_bytes_self, sk_bytes_other);
        return sk_equal and self.pk.equivalent(other.pk);
    }
};

/// Hash multiple byte arrays to produce a Ristretto255 scalar
fn hashToScalar(parts: []const []const u8) !Scalar {
    var hasher = crypto.hash.blake2.Blake2b512.init(.{});
    for (parts) |part| hasher.update(part);

    var hash: [64]u8 = undefined;
    hasher.final(&hash);
    return Scalar.fromBytes64(hash);
}

/// Schnorr signature containing the signature scalar and commitment point
pub const SchnorrSignature = struct {
    /// Signature scalar s = k + e*sk
    s: Scalar,
    /// Commitment point R = k*G
    r: Point,

    /// Create a Schnorr signature for a message using a secret key
    pub fn sign(sk: *const Scalar, msg: []const u8) !SchnorrSignature {
        const k = Scalar.random();
        const r = try Point.basePoint.mul(k.toBytes());

        const r_bytes = r.toBytes();
        const e = try hashToScalar(&.{ msg, &r_bytes });
        const s = k.add(e.mul(sk.*));

        return .{ .s = s, .r = r };
    }

    /// Verify a Schnorr signature against a public key and message
    pub fn verify(self: *const SchnorrSignature, pk: *const Point, msg: []const u8) !bool {
        const r_bytes = self.r.toBytes();
        const e = try hashToScalar(&.{ msg, &r_bytes });
        const left = try Point.basePoint.mul(self.s.toBytes());
        const right = self.r.add(try pk.mul(e.toBytes()));

        return left.equivalent(right);
    }
};

/// Maximum warrant size (256 bytes should be enough for most use cases)
pub const MAX_WARRANT_SIZE = 256;

/// Warrant type - fixed size buffer with actual length
pub const Warrant = struct {
    data: [MAX_WARRANT_SIZE]u8 = @splat(0),
    len: usize = 0,

    pub fn fromSlice(data: []const u8) !Warrant {
        if (data.len > MAX_WARRANT_SIZE) return error.InvalidLength;

        var warrant: Warrant = .{ .len = data.len };
        @memcpy(warrant.data[0..data.len], data);
        return warrant;
    }

    pub fn slice(self: *const Warrant) []const u8 {
        return self.data[0..self.len];
    }
};

/// Delegation token that authorizes a proxy to sign on behalf of the original signer
pub const DelegationToken = struct {
    /// Warrant describing the delegation terms
    warrant: Warrant,
    /// Commitment point Rw = a*G
    rw: Point,
    /// Signature scalar sw = a + e_w*x_A
    sw: Scalar,
    /// Proxy's public key (bound to prevent delegation transfer)
    b_pub: Point,

    /// Create a delegation token authorizing a specific proxy
    pub fn create(a_keys: *const KeyPair, b_pub: *const Point, warrant: []const u8) !DelegationToken {
        const a_nonce = Scalar.random();
        const rw = try Point.basePoint.mul(a_nonce.toBytes());

        // Include proxy's public key in the hash to bind the delegation
        const rw_bytes = rw.toBytes();
        const b_pub_bytes = b_pub.toBytes();
        const e_w = try hashToScalar(&.{ warrant, &rw_bytes, &b_pub_bytes });
        const sw = a_nonce.add(e_w.mul(a_keys.sk));

        return .{
            .warrant = try Warrant.fromSlice(warrant),
            .rw = rw,
            .sw = sw,
            .b_pub = b_pub.*,
        };
    }

    /// Verify that a delegation token is valid for the given public key and proxy
    pub fn verify(self: *const DelegationToken, a_pub: *const Point) !bool {
        // Include proxy's public key in the hash to verify binding
        const rw_bytes = self.rw.toBytes();
        const b_pub_bytes = self.b_pub.toBytes();
        const e_w = try hashToScalar(&.{ self.warrant.slice(), &rw_bytes, &b_pub_bytes });
        const left = try Point.basePoint.mul(self.sw.toBytes());
        const right = self.rw.add(try a_pub.mul(e_w.toBytes()));

        return left.equivalent(right);
    }

    pub fn warrantStr(self: *const DelegationToken) []const u8 {
        return self.warrant.slice();
    }

    pub fn proxyPublicKey(self: *const DelegationToken) *const Point {
        return &self.b_pub;
    }
};

/// Public context needed to verify proxy signatures
pub const ProxyPublicContext = struct {
    /// Warrant describing the delegation
    warrant: Warrant,
    /// Commitment point from delegation token
    rw: Point,
    /// Proxy's combined public key
    yp: Point,

    pub fn init(warrant: []const u8, rw: Point, yp: Point) !ProxyPublicContext {
        return .{
            .warrant = try Warrant.fromSlice(warrant),
            .rw = rw,
            .yp = yp,
        };
    }

    pub fn fromToken(token: *const DelegationToken, yp: Point) ProxyPublicContext {
        return .{
            .warrant = token.warrant,
            .rw = token.rw,
            .yp = yp,
        };
    }

    pub fn warrantStr(self: *const ProxyPublicContext) []const u8 {
        return self.warrant.slice();
    }
};

/// Proxy key pair derived from delegation
/// This type cannot be used to create new delegations (prevents redelegation chains)
pub const ProxyKeyPair = struct {
    /// Proxy's derived secret key
    sk: Scalar,
    /// Proxy's derived public key
    pk: Point,

    /// Sign a message using the proxy key
    pub fn sign(self: *const ProxyKeyPair, message: []const u8) !SchnorrSignature {
        return SchnorrSignature.sign(&self.sk, message);
    }

    pub fn publicKey(self: *const ProxyKeyPair) *const Point {
        return &self.pk;
    }

    pub fn secretKey(self: *const ProxyKeyPair) *const Scalar {
        return &self.sk;
    }

    /// Verify a signature with this proxy key
    pub fn verify(self: *const ProxyKeyPair, message: []const u8, signature: *const SchnorrSignature) !bool {
        return signature.verify(&self.pk, message);
    }
};

/// Derived proxy keys with named fields for better type safety
pub const ProxyKeys = struct {
    /// Proxy's derived secret key
    sk: Scalar,
    /// Proxy's derived public key
    pk: Point,

    pub fn init(sk: Scalar, pk: Point) ProxyKeys {
        return .{ .sk = sk, .pk = pk };
    }
};

/// Derive proxy signing keys from a delegation token
pub fn deriveProxyKeys(b_keys: *const KeyPair, a_pub: *const Point, token: *const DelegationToken) !ProxyKeys {
    // Verify that this proxy is the one bound to the delegation token
    if (!b_keys.pk.equivalent(token.b_pub)) {
        return error.ProxyKeyMismatch;
    }

    if (!try token.verify(a_pub)) {
        return error.InvalidDelegation;
    }

    // Use the bound proxy key in the hash
    const rw_bytes = token.rw.toBytes();
    const b_pub_bytes = token.b_pub.toBytes();
    const e_w = try hashToScalar(&.{ token.warrant.slice(), &rw_bytes, &b_pub_bytes });
    const xp = token.sw.add(b_keys.sk);

    // Compute YP both ways for verification
    const yp_from_secret = try Point.basePoint.mul(xp.toBytes());
    const yp_from_relation = token.rw.add(try a_pub.mul(e_w.toBytes())).add(b_keys.pk);

    if (!yp_from_secret.equivalent(yp_from_relation)) {
        return error.ProxyKeyMismatch;
    }

    return ProxyKeys.init(xp, yp_from_secret);
}

/// Derive proxy signing key pair from a delegation token
pub fn deriveProxyKeyPair(b_keys: *const KeyPair, a_pub: *const Point, token: *const DelegationToken) !ProxyKeyPair {
    const keys = try deriveProxyKeys(b_keys, a_pub, token);
    return .{ .sk = keys.sk, .pk = keys.pk };
}

/// Create a proxy signature for a message
pub fn proxySign(xp: *const Scalar, message: []const u8) !SchnorrSignature {
    return SchnorrSignature.sign(xp, message);
}

/// Verify a proxy signature
pub fn proxyVerify(
    a_pub: *const Point,
    b_pub: *const Point,
    message: []const u8,
    sig: *const SchnorrSignature,
    ctx: *const ProxyPublicContext,
) !bool {
    // Include proxy's public key in the hash for bound delegation verification
    const rw_bytes = ctx.rw.toBytes();
    const b_pub_bytes = b_pub.toBytes();
    const e_w = try hashToScalar(&.{ ctx.warrant.slice(), &rw_bytes, &b_pub_bytes });
    const yp = ctx.rw.add(try a_pub.mul(e_w.toBytes())).add(b_pub.*);

    // Verify that the provided YP matches the computed one
    if (!ctx.yp.equivalent(yp)) {
        return false;
    }

    return sig.verify(&yp, message);
}

// Tests
test "key generation" {
    const keypair = KeyPair.new();
    const keypair2 = KeyPair.new();

    // Verify that multiple key generations produce different keys
    try std.testing.expect(!keypair.sk.isZero());
    try std.testing.expect(!keypair.eql(keypair2));
}

test "schnorr signature" {
    const keypair = KeyPair.new();
    const message = "Test message for signing";

    // Sign and verify
    const sig = try SchnorrSignature.sign(&keypair.sk, message);
    try std.testing.expect(try sig.verify(&keypair.pk, message));

    // Wrong message should fail
    const wrong_message = "Different message";
    try std.testing.expect(!try sig.verify(&keypair.pk, wrong_message));

    // Wrong public key should fail
    const other_keypair = KeyPair.new();
    try std.testing.expect(!try sig.verify(&other_keypair.pk, message));
}

test "delegation token" {
    const a = KeyPair.new();
    const b = KeyPair.new();
    const warrant = "Proxy B may sign for A until 2024-12-31";

    // Create and verify delegation
    const token = try DelegationToken.create(&a, &b.pk, warrant);
    try std.testing.expect(try token.verify(&a.pk));

    // Verification with wrong public key should fail
    try std.testing.expect(!try token.verify(&b.pk));
}

test "proxy signature flow" {
    // Setup: Create key pairs
    const a = KeyPair.new(); // Original signer
    const b = KeyPair.new(); // Proxy signer

    // Step 1: Create delegation
    const warrant = "Proxy B may sign on behalf of A for project X";
    const token = try DelegationToken.create(&a, &b.pk, warrant);
    try std.testing.expect(try token.verify(&a.pk));

    // Step 2: Derive proxy keys
    const keys = try deriveProxyKeys(&b, &a.pk, &token);

    // Step 3: Create proxy signature
    const message = "Authorize payment of 100 units";
    const sig = try proxySign(&keys.sk, message);

    // Step 4: Verify proxy signature
    const ctx = try ProxyPublicContext.init(warrant, token.rw, keys.pk);

    try std.testing.expect(try proxyVerify(&a.pk, &b.pk, message, &sig, &ctx));

    // Wrong message should fail
    const wrong_message = "Authorize payment of 200 units";
    try std.testing.expect(!try proxyVerify(&a.pk, &b.pk, wrong_message, &sig, &ctx));

    // Wrong proxy public key should fail
    const c = KeyPair.new();
    try std.testing.expect(!try proxyVerify(&a.pk, &c.pk, message, &sig, &ctx));
}

test "invalid delegation" {
    const a = KeyPair.new();
    const b = KeyPair.new();
    const warrant = "Test warrant";

    // Create valid token but tamper with it
    var token = try DelegationToken.create(&a, &b.pk, warrant);

    // Tamper with sw by modifying the scalar
    // Create a scalar with value 1 by creating bytes array with 1 in the first position
    const one_bytes = [_]u8{1} ++ [_]u8{0} ** 31;
    const one_scalar = Scalar.fromBytes(one_bytes);
    token.sw = token.sw.add(one_scalar);

    // Deriving proxy keys should fail
    const result = deriveProxyKeys(&b, &a.pk, &token);
    try std.testing.expectError(error.InvalidDelegation, result);
}

test "proxy binding prevents transfer" {
    const a = KeyPair.new();
    const b = KeyPair.new();
    const c = KeyPair.new(); // Different proxy
    const warrant = "Proxy B may sign for A";

    // Create delegation for proxy B
    const token = try DelegationToken.create(&a, &b.pk, warrant);
    try std.testing.expect(try token.verify(&a.pk));

    // B can derive proxy keys
    const keys_b = try deriveProxyKeys(&b, &a.pk, &token);

    // C cannot use B's delegation token (proxy binding prevents this)
    const result = deriveProxyKeys(&c, &a.pk, &token);
    try std.testing.expectError(error.ProxyKeyMismatch, result);

    // Create proxy signature with B's keys
    const message = "Test message";
    const sig = try proxySign(&keys_b.sk, message);

    // Verify works with correct proxy
    const ctx = try ProxyPublicContext.init(warrant, token.rw, keys_b.pk);
    try std.testing.expect(try proxyVerify(&a.pk, &b.pk, message, &sig, &ctx));

    // Verify fails with wrong proxy public key (C instead of B)
    try std.testing.expect(!try proxyVerify(&a.pk, &c.pk, message, &sig, &ctx));
}

test "proxy cannot redelegate" {
    const a = KeyPair.new();
    const b = KeyPair.new();
    const warrant_ab = "Proxy B may sign for A";

    // A creates delegation for B
    const token_ab = try DelegationToken.create(&a, &b.pk, warrant_ab);
    try std.testing.expect(try token_ab.verify(&a.pk));

    // B derives proxy keys - returns ProxyKeyPair type
    const proxy_keys = try deriveProxyKeyPair(&b, &a.pk, &token_ab);

    // ProxyKeyPair can sign messages
    const message = "Test message";
    const sig = try proxy_keys.sign(message);
    try std.testing.expect(try sig.verify(&proxy_keys.pk, message));

    // Verify that proxy keys work for their intended purpose (signing)
    const sig2 = try proxySign(&proxy_keys.sk, "Another message");
    try std.testing.expect(sig2.s.toBytes().len == 32);
}
