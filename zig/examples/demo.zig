const std = @import("std");
const proxy_signatures = @import("proxy-signatures");
const KeyPair = proxy_signatures.KeyPair;
const DelegationToken = proxy_signatures.DelegationToken;
const ProxyPublicContext = proxy_signatures.ProxyPublicContext;

pub fn main() !void {
    const print = std.debug.print;

    print("=== Ristretto255 Proxy Signatures Demo ===\n\n", .{});

    // 1) Key generation
    print("1. Generating keys...\n", .{});
    const a = KeyPair.new(); // Original signer
    const b = KeyPair.new(); // Proxy signer

    const a_pk_bytes = a.pk.toBytes();
    const b_pk_bytes = b.pk.toBytes();

    const a_hex = std.fmt.bytesToHex(a_pk_bytes, .lower);
    print("   A's public key: {s}\n", .{a_hex});

    const b_hex = std.fmt.bytesToHex(b_pk_bytes, .lower);
    print("   B's public key: {s}\n", .{b_hex});

    // 2) Delegation with warrant
    print("\n2. Creating delegation...\n", .{});
    const warrant = "Proxy: B may sign for A for service XYZ until 2026-12-31";
    const token = try DelegationToken.create(&a, &b.pk, warrant);

    if (!try token.verify(&a.pk)) {
        return error.InvalidDelegation;
    }
    print("   Warrant: {s}\n", .{warrant});
    print("   Delegation token created and verified\n", .{});

    // 3) Proxy key derivation
    print("\n3. Deriving proxy keys...\n", .{});
    const keys = try proxy_signatures.deriveProxyKeys(&b, &a.pk, &token);

    const yp_bytes = keys.pk.toBytes();
    const yp_hex = std.fmt.bytesToHex(yp_bytes, .lower);
    print("   Proxy public key YP: {s}\n", .{yp_hex});

    // 4) Proxy signs
    print("\n4. Creating proxy signature...\n", .{});
    const msg = "Pay 10 units to Carol";
    const sig = try proxy_signatures.proxySign(&keys.sk, msg);
    print("   Message: {s}\n", .{msg});
    print("   Signature created\n", .{});

    // 5) Verify proxy signature
    print("\n5. Verifying proxy signature...\n", .{});
    const ctx = try ProxyPublicContext.init(warrant, token.rw, keys.pk);

    const valid = try proxy_signatures.proxyVerify(&a.pk, &b.pk, msg, &sig, &ctx);
    print("   Proxy signature valid? {}\n", .{valid});

    // 6) Test with wrong message
    print("\n6. Testing with wrong message...\n", .{});
    const wrong_msg = "Pay 100 units to Carol";
    const invalid = try proxy_signatures.proxyVerify(&a.pk, &b.pk, wrong_msg, &sig, &ctx);
    print("   Wrong message signature valid? {} (should be false)\n", .{invalid});

    // 7) Demonstrate revocation by tampering with warrant
    print("\n7. Testing revocation (modified warrant)...\n", .{});
    const revoked_ctx = try ProxyPublicContext.init("REVOKED: Original warrant no longer valid", ctx.rw, ctx.yp);

    const revoked = try proxy_signatures.proxyVerify(&a.pk, &b.pk, msg, &sig, &revoked_ctx);
    print("   Signature with revoked warrant valid? {} (should be false)\n", .{revoked});

    print("\n✅ All operations completed successfully!\n", .{});
}
