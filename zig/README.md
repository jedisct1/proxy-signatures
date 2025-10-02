# Proxy Signatures with Delegation by Warrant

Proxy signatures with delegation by warrant, over the Ristretto255 group.

This library implements classic proxy signatures with “partial delegation with warrant” and binds each delegation to the designated proxy’s public key to prevent transfer.

Use it when an owner must stay accountable while a separate component signs on the owner’s behalf without learning the owner’s long‑term secret.

A delegation is tied to exactly one proxy by hashing the proxy’s public key into the authenticated warrant/commitment. The proxy derives a special signing key that cannot be used to create new delegations (non‑transferable by construction). Warrant semantics (expiry, scope, etc.) are application‑defined and shipped as bytes that can be the serialization of a structure.

## Quick Start

### Zig

```zig
const std = @import("std");
const proxy_signatures = @import("proxy-signatures");
const KeyPair = proxy_signatures.KeyPair;
const DelegationToken = proxy_signatures.DelegationToken;
const ProxyPublicContext = proxy_signatures.ProxyPublicContext;

pub fn main() !void {
    // Original signer A and designated proxy B
    const a = KeyPair.new();
    const b = KeyPair.new();

    // A creates a warrant describing scope/expiry/purpose (free-form bytes)
    const warrant = "Proxy B may sign for A until 2026-12-31 for invoices only";
    const token = try DelegationToken.create(&a, &b.pk, warrant);
    std.debug.assert(try token.verify(&a.pk));

    // B derives proxy signing keys bound to this delegation
    const keys = try proxy_signatures.deriveProxyKeys(&b, &a.pk, &token);
    const ctx = try ProxyPublicContext.init(warrant, token.rw, keys.pk);

    // B signs as proxy
    const msg = "Invoice #4387 approved";
    const sig = try proxy_signatures.proxySign(&keys.sk, msg);

    // Anyone can verify with (A_pub, B_pub) + public context
    const ok = try proxy_signatures.proxyVerify(&a.pk, &b.pk, msg, &sig, &ctx);
    std.debug.assert(ok);
}
```

### Rust

```toml
[dependencies]
proxy-signatures = "0"
```

```rust
use proxy_signatures::{DelegationToken, KeyPair, ProxyPublicContext, Result};

fn main() -> Result<()> {
    // Original signer A and designated proxy B
    let a = KeyPair::new()?;
    let b = KeyPair::new()?;

    // A creates a warrant describing scope/expiry/purpose (free-form bytes)
    let warrant = b"Proxy B may sign for A until 2026-12-31 for invoices only";
    let token = DelegationToken::create(&a, &b.pk, warrant)?;
    assert!(token.verify(&a.pk)?);

    // B derives proxy signing keys bound to this delegation
    let keys = proxy_signatures::derive_proxy_keys(&b, &a.pk, &token)?;
    let ctx = ProxyPublicContext::from_token(&token, keys.pk);

    // B signs as proxy
    let msg = b"Invoice #4387 approved";
    let sig = proxy_signatures::proxy_sign(&keys.sk, msg)?;

    // Anyone can verify with (A_pub, B_pub) + public context
    let ok = proxy_signatures::proxy_verify(&a.pk, &b.pk, msg, &sig, &ctx)?;
    assert!(ok);
    Ok(())
}
```

## API Overview

The `KeyPair` type represents an original signer capable of creating delegations.

A `DelegationToken` carries the warrant bytes together with a commitment and is explicitly tied to the designated proxy’s public key. 

A proxy uses `derive_proxy_keys` or `derive_proxy_key_pair` to obtain the special proxy key material that is valid only under the delegation. Messages are signed with `proxy_sign` and verified with `proxy_verify`, which takes the owner and proxy public keys alongside a `ProxyPublicContext` describing the warrant, commitment, and derived proxy public key needed for verification.

## How It Works (informal)

- Delegation: the owner authenticates the warrant and commitment while hashing the proxy’s public key, yielding a token {warrant, commitment, auth scalar} that verifies under the owner key.
- Derivation: the proxy verifies the token and derives a proxy secret/public key from (token + its own key).
- Signing: the proxy signs messages with the derived key using Schnorr over Ristretto255.
- Verification: verifiers recompute the bound proxy public key from (owner key, proxy key, warrant, commitment) and check the Schnorr signature against it.

This is a simple and efficient alternative to traditional signature chains when warrants change frequently and verification cannot be cached. Only one signature verification is required, and delegation is ensured by the cryptographic structure itself.

## In Practice: What This Enables

Most systems have one accountable owner and many components that must act on its behalf. Proxy signatures express this cleanly: the owner issues a warrant‑backed delegation to one proxy; the proxy derives a special signing key; verifiers check signatures against the owner key, proxy key, and warrant.

Concrete patterns:

- CDN Operations: Proxy signatures are useful in CDN scenarios where the owner keeps the root key offline while delegating to CDN infrastructure:
  - Signed URLs: CDN generates signed URLs with time- and path-scoped warrants. When warrants expire, URL generation automatically stops - no root key rollover needed.
  - Edge Authentication: Edge nodes validate requests and sign responses locally using proxy keys. Warrants encode geographic restrictions, content types, or user agent policies for fine-grained access control at the edge.
  - Distributed Token Generation: Edge nodes generate signed authentication tokens for client requests without origin server involvement, reducing latency while maintaining cryptographic authenticity.
  - Multi-CDN Strategy: Primary CDN delegates to secondary CDNs for specific regions or content types. Each provider receives a non-transferable delegation bound to their public key.

- Regional JWT issuance: An auth server delegates JWT signing to regional services. Warrant encodes audiences, lifetimes, and an identifier for logging. Regions sign locally; verifiers use owner key + region key + public context.

- CI release signing: Security holds the product key; CI gets a delegation limited to repo/version window. CI derives during the job and signs release checksums. Users verify with org key + CI key and read the warrant for scope.

- Device fleets: Manufacturers delegate to operators per device class/region/window. Devices verify with manufacturer key + operator key and display/log the warrant. Rotate by issuing a new warrant or letting old ones expire.

- Integration pattern: Exchange public keys and a one‑time delegation over your control plane. The proxy keeps only its own key and the token. Each signature includes compact public context (warrant + commitment) so verifiers can check without calling home.

## Design Notes and Non‑Goals

- Non‑transferable by design: the proxy’s public key is bound into the delegation, and proxy keys are a distinct type that cannot create further delegations.
- Policy in the warrant: expiry, scope, audiences, identifiers, etc. live in warrant bytes; applications must parse and enforce them.
- Single hop only: owner → one proxy. No chains, multi‑hop, or threshold delegation in scope.

## References

The construction follows the original proxy‑signature notion by Mambo, Usuda and Okamoto (IEICE Trans. Fundamentals E79‑A(9), 1996) and the “partial delegation with warrant” refinement by Kim, Park and Won (ICICS 1997, LNCS 1334). For definitions and security analysis, see the work by Boldyreva, Palacio and Warinschi (IACR ePrint 2003/096; Journal of Cryptology 25(1), 2012).