//! Example demonstration of Ristretto255 proxy signatures

use ct_codecs::{Encoder, Hex};
use proxy_signatures::{DelegationToken, KeyPair, ProxyPublicContext, Result};

fn main() -> Result<()> {
    println!("=== Ristretto255 Proxy Signatures Demo ===\n");

    // 1) Key generation
    println!("1. Generating keys...");
    let a = KeyPair::new()?; // Original signer
    let b = KeyPair::new()?; // Proxy signer
    println!(
        "   A's public key: {}",
        Hex::encode_to_string(a.pk).unwrap()
    );
    println!(
        "   B's public key: {}",
        Hex::encode_to_string(b.pk).unwrap()
    );

    // 2) Delegation with warrant
    println!("\n2. Creating delegation...");
    let warrant = b"Proxy: B may sign for A for service XYZ until 2026-12-31";
    let token = DelegationToken::create(&a, &b.pk, warrant)?;
    if !token.verify(&a.pk)? {
        return Err(proxy_signatures::ProxySignatureError::InvalidDelegation);
    }
    println!("   Warrant: {}", std::str::from_utf8(warrant)?);
    println!("   Delegation token created and verified");

    // 3) Proxy key derivation
    println!("\n3. Deriving proxy keys...");
    let keys = proxy_signatures::derive_proxy_keys(&b, &a.pk, &token)?;
    let ctx = ProxyPublicContext {
        warrant: warrant.to_vec(),
        rw: token.rw,
        yp: keys.pk,
    };
    println!(
        "   Proxy public key YP: {}",
        Hex::encode_to_string(keys.pk).unwrap()
    );

    // 4) Proxy signs
    println!("\n4. Creating proxy signature...");
    let msg = b"Pay 10 units to Carol";
    let sig = proxy_signatures::proxy_sign(&keys.sk, msg)?;
    println!("   Message: {}", std::str::from_utf8(msg)?);
    println!("   Signature created");

    // 5) Verify proxy signature
    println!("\n5. Verifying proxy signature...");
    let valid = proxy_signatures::proxy_verify(&a.pk, &b.pk, msg, &sig, &ctx)?;
    println!("   Proxy signature valid? {}", valid);

    // 6) Test with wrong message
    println!("\n6. Testing with wrong message...");
    let wrong_msg = b"Pay 100 units to Carol";
    let invalid = proxy_signatures::proxy_verify(&a.pk, &b.pk, wrong_msg, &sig, &ctx)?;
    println!(
        "   Wrong message signature valid? {} (should be false)",
        invalid
    );

    // 7) Demonstrate revocation by tampering with warrant
    println!("\n7. Testing revocation (modified warrant)...");
    let revoked_ctx = ProxyPublicContext {
        warrant: b"REVOKED: Original warrant no longer valid".to_vec(),
        rw: ctx.rw,
        yp: ctx.yp,
    };
    let revoked = proxy_signatures::proxy_verify(&a.pk, &b.pk, msg, &sig, &revoked_ctx)?;
    println!(
        "   Signature with revoked warrant valid? {} (should be false)",
        revoked
    );

    println!("\n✅ All operations completed successfully!");

    Ok(())
}
