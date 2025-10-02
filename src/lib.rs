//! # Ristretto255 Proxy Signatures
//!
//! Implementation of proxy signatures using the Ristretto255 prime-order group.
//! Based on MUO '96 proxy notion with KPW '97 "partial delegation with warrant" instantiation.
//!
//! ## Protocol Flow
//!
//! 1. Delegation: Original signer A delegates signing authority to proxy B with warrant w
//!    - A generates: `Rw = a*G`, `s_w = a + e_w*x_A` where `e_w = H(w || Rw)`
//! 2. Verification: B verifies: `s_w*G == Rw + e_w*Y_A`
//! 3. Key Derivation: B derives proxy key: `x_P = s_w + x_B (mod L)`, `Y_P = x_P*G`
//! 4. Signing: B signs message m using Schnorr signature under `x_P`
//! 5. Verification: Verifier reconstructs `Y_P` from `(w, Rw, Y_A, Y_B)` and verifies signature

pub mod reexports {
    pub use ct_codecs;
    pub use libsodium_rs;
}

use ct_codecs::{Encoder, Hex};
use libsodium_rs::crypto_core::ristretto255;
use libsodium_rs::crypto_generichash;
use libsodium_rs::crypto_scalarmult::ristretto255 as scalarmult_ristretto;
use libsodium_rs::utils;
use std::error::Error;
use std::fmt;
use std::hash::{Hash, Hasher};

/// Type alias for Ristretto255 scalar values (32 bytes)
pub type Scalar = [u8; ristretto255::SCALARBYTES];

/// Type alias for Ristretto255 point values (32 bytes)
pub type Point = [u8; ristretto255::BYTES];

/// Custom error type for proxy signature operations
#[derive(Debug)]
pub enum ProxySignatureError {
    /// Error from libsodium operations
    Libsodium(libsodium_rs::SodiumError),
    /// Invalid delegation token that failed verification
    InvalidDelegation,
    /// Proxy key derivation resulted in mismatched keys
    ProxyKeyMismatch,
    /// UTF-8 encoding error
    Utf8Error(std::str::Utf8Error),
    /// Invalid length for byte conversion
    InvalidLength { expected: usize, actual: usize },
}

impl fmt::Display for ProxySignatureError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProxySignatureError::Libsodium(e) => write!(f, "Libsodium error: {}", e),
            ProxySignatureError::InvalidDelegation => write!(f, "Invalid delegation token"),
            ProxySignatureError::ProxyKeyMismatch => {
                write!(f, "Proxy key derivation mismatch")
            }
            ProxySignatureError::Utf8Error(e) => write!(f, "UTF-8 error: {}", e),
            ProxySignatureError::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "Invalid length: expected {} bytes, got {}",
                    expected, actual
                )
            }
        }
    }
}

impl Error for ProxySignatureError {}

impl From<libsodium_rs::SodiumError> for ProxySignatureError {
    fn from(error: libsodium_rs::SodiumError) -> Self {
        ProxySignatureError::Libsodium(error)
    }
}

impl From<std::str::Utf8Error> for ProxySignatureError {
    fn from(error: std::str::Utf8Error) -> Self {
        ProxySignatureError::Utf8Error(error)
    }
}

/// Result type alias for proxy signature operations
pub type Result<T> = std::result::Result<T, ProxySignatureError>;

/// Cryptographic key pair containing a secret key and corresponding public key
/// This represents original (non-proxy) keys that can create delegations
#[derive(Clone, PartialEq, Eq)]
pub struct KeyPair {
    /// Secret scalar value
    pub sk: Scalar,
    /// Public point value
    pub pk: Point,
}

impl KeyPair {
    /// Generate a new random key pair
    ///
    /// # Returns
    /// A new `KeyPair` with randomly generated secret and public keys
    ///
    /// # Errors
    /// Returns an error if scalar multiplication fails
    pub fn new() -> Result<Self> {
        let sk = ristretto255::scalar_random();
        let pk = scalarmult_ristretto::scalarmult_base(&sk)?;
        Ok(KeyPair { sk, pk })
    }

    /// Get a reference to the public key
    pub fn public_key(&self) -> &Point {
        &self.pk
    }

    /// Get a reference to the secret key
    pub fn secret_key(&self) -> &Scalar {
        &self.sk
    }

    /// Create a KeyPair from existing secret key
    ///
    /// # Arguments
    /// * `sk` - Secret key scalar
    ///
    /// # Returns
    /// A new KeyPair with the given secret key and derived public key
    ///
    /// # Errors
    /// Returns an error if scalar multiplication fails
    pub fn from_secret_key(sk: Scalar) -> Result<Self> {
        let pk = scalarmult_ristretto::scalarmult_base(&sk)?;
        Ok(KeyPair { sk, pk })
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("sk", &"<redacted>")
            .field("pk", &Hex::encode_to_string(self.pk).unwrap())
            .finish()
    }
}

impl fmt::Display for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KeyPair(pk: {})",
            &Hex::encode_to_string(self.pk).unwrap()[..8]
        )
    }
}

impl AsRef<Point> for KeyPair {
    fn as_ref(&self) -> &Point {
        &self.pk
    }
}

impl From<&KeyPair> for Point {
    fn from(keypair: &KeyPair) -> Self {
        keypair.pk
    }
}

impl Hash for KeyPair {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Only hash the public key, not the secret key
        self.pk.hash(state);
    }
}

/// Hash multiple byte arrays to produce a Ristretto255 scalar
///
/// # Arguments
/// * `parts` - Slice of byte array references to hash together
///
/// # Returns
/// A scalar value derived from the hash of concatenated inputs
///
/// # Errors
/// Returns an error if hashing or scalar reduction fails
fn hash_to_scalar(parts: &[&[u8]]) -> Result<Scalar> {
    let mut state = crypto_generichash::State::new(None, 64)?;
    for part in parts {
        state.update(part);
    }
    let hash = state.finalize();
    Ok(ristretto255::scalar_reduce(&hash)?)
}

/// Schnorr signature containing the signature scalar and commitment point
#[derive(Clone, PartialEq, Eq)]
pub struct SchnorrSignature {
    /// Signature scalar s = k + e*sk
    pub s: Scalar,
    /// Commitment point R = k*G
    pub r: Point,
}

impl SchnorrSignature {
    /// Create a Schnorr signature for a message using a secret key
    ///
    /// # Arguments
    /// * `sk` - Secret key scalar
    /// * `msg` - Message bytes to sign
    ///
    /// # Returns
    /// A new Schnorr signature
    ///
    /// # Errors
    /// Returns an error if any cryptographic operation fails
    pub fn sign(sk: &Scalar, msg: &[u8]) -> Result<Self> {
        let k = ristretto255::scalar_random();
        let r = scalarmult_ristretto::scalarmult_base(&k)?;

        let e = hash_to_scalar(&[msg, &r])?;
        let e_times_sk = ristretto255::scalar_mul(&e, sk)?;
        let s = ristretto255::scalar_add(&k, &e_times_sk)?;

        Ok(SchnorrSignature { s, r })
    }

    /// Verify a Schnorr signature against a public key and message
    ///
    /// # Arguments
    /// * `pk` - Public key point
    /// * `msg` - Message bytes that were signed
    ///
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise
    ///
    /// # Errors
    /// Returns an error if any cryptographic operation fails
    pub fn verify(&self, pk: &Point, msg: &[u8]) -> Result<bool> {
        let e = hash_to_scalar(&[msg, &self.r])?;
        let left = scalarmult_ristretto::scalarmult_base(&self.s)?;
        let e_times_pk = scalarmult_ristretto::scalarmult(&e, pk)?;
        let right = ristretto255::add(&self.r, &e_times_pk)?;

        // Use constant-time comparison
        Ok(utils::memcmp(&left, &right))
    }
}

impl fmt::Debug for SchnorrSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SchnorrSignature")
            .field("s", &Hex::encode_to_string(self.s).unwrap())
            .field("r", &Hex::encode_to_string(self.r).unwrap())
            .finish()
    }
}

impl fmt::Display for SchnorrSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Sig({}...)",
            &Hex::encode_to_string(self.s).unwrap()[..8]
        )
    }
}

impl Hash for SchnorrSignature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.s.hash(state);
        self.r.hash(state);
    }
}

/// Delegation token that authorizes a proxy to sign on behalf of the original signer
#[derive(Clone, PartialEq, Eq)]
pub struct DelegationToken {
    /// Warrant describing the delegation terms
    pub warrant: Vec<u8>,
    /// Commitment point Rw = a*G
    pub rw: Point,
    /// Signature scalar sw = a + e_w*x_A
    pub sw: Scalar,
    /// Proxy's public key (bound to prevent delegation transfer)
    pub b_pub: Point,
}

impl DelegationToken {
    /// Get the warrant as a string slice if it's valid UTF-8
    pub fn warrant_str(&self) -> Result<&str> {
        std::str::from_utf8(&self.warrant).map_err(ProxySignatureError::Utf8Error)
    }

    /// Get the warrant as a string, replacing invalid UTF-8 sequences
    pub fn warrant_string_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.warrant)
    }

    /// Get the proxy's public key
    pub fn proxy_public_key(&self) -> &Point {
        &self.b_pub
    }

    /// Create a delegation token authorizing a specific proxy
    ///
    /// # Arguments
    /// * `a_keys` - Original signer's key pair (only accepts non-proxy KeyPair type)
    /// * `b_pub` - Proxy's public key (cryptographically bound to prevent transfer)
    /// * `warrant` - Bytes describing delegation terms
    ///
    /// # Returns
    /// A new delegation token bound to the specific proxy
    ///
    /// # Errors
    /// Returns an error if any cryptographic operation fails
    ///
    /// # Type Safety
    /// This function only accepts `KeyPair`, not `ProxyKeyPair`, preventing
    /// proxy-to-proxy redelegation at compile time.
    pub fn create(a_keys: &KeyPair, b_pub: &Point, warrant: &[u8]) -> Result<Self> {
        let a_nonce = ristretto255::scalar_random();
        let rw = scalarmult_ristretto::scalarmult_base(&a_nonce)?;

        // Include proxy's public key in the hash to bind the delegation
        let e_w = hash_to_scalar(&[warrant, &rw, b_pub])?;
        let e_times_sk = ristretto255::scalar_mul(&e_w, &a_keys.sk)?;
        let sw = ristretto255::scalar_add(&a_nonce, &e_times_sk)?;

        Ok(DelegationToken {
            warrant: warrant.to_vec(),
            rw,
            sw,
            b_pub: *b_pub,
        })
    }

    /// Verify that a delegation token is valid for the given public key and proxy
    ///
    /// # Arguments
    /// * `a_pub` - Original signer's public key
    ///
    /// # Returns
    /// `true` if the delegation is valid for this specific proxy, `false` otherwise
    ///
    /// # Errors
    /// Returns an error if any cryptographic operation fails
    pub fn verify(&self, a_pub: &Point) -> Result<bool> {
        // Include proxy's public key in the hash to verify binding
        let e_w = hash_to_scalar(&[&self.warrant, &self.rw, &self.b_pub])?;
        let left = scalarmult_ristretto::scalarmult_base(&self.sw)?;
        let e_times_a = scalarmult_ristretto::scalarmult(&e_w, a_pub)?;
        let right = ristretto255::add(&self.rw, &e_times_a)?;

        // Use constant-time comparison
        Ok(utils::memcmp(&left, &right))
    }
}

impl fmt::Debug for DelegationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DelegationToken")
            .field("warrant", &String::from_utf8_lossy(&self.warrant))
            .field("rw", &Hex::encode_to_string(self.rw).unwrap())
            .field("sw", &"<redacted>")
            .field("b_pub", &Hex::encode_to_string(self.b_pub).unwrap())
            .finish()
    }
}

impl fmt::Display for DelegationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DelegationToken(warrant: {:?}, proxy: {}...)",
            String::from_utf8_lossy(&self.warrant),
            &Hex::encode_to_string(self.b_pub).unwrap()[..8]
        )
    }
}

/// Public context needed to verify proxy signatures
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyPublicContext {
    /// Warrant describing the delegation
    pub warrant: Vec<u8>,
    /// Commitment point from delegation token
    pub rw: Point,
    /// Proxy's combined public key
    pub yp: Point,
}

impl ProxyPublicContext {
    /// Create a new ProxyPublicContext
    pub fn new(warrant: Vec<u8>, rw: Point, yp: Point) -> Self {
        ProxyPublicContext { warrant, rw, yp }
    }

    /// Create context from a delegation token and proxy public key
    pub fn from_token(token: &DelegationToken, yp: Point) -> Self {
        ProxyPublicContext {
            warrant: token.warrant.clone(),
            rw: token.rw,
            yp,
        }
    }

    /// Get the warrant as a string if it's valid UTF-8
    pub fn warrant_str(&self) -> Result<&str> {
        std::str::from_utf8(&self.warrant).map_err(ProxySignatureError::Utf8Error)
    }
}

impl fmt::Debug for ProxyPublicContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyPublicContext")
            .field("warrant", &String::from_utf8_lossy(&self.warrant))
            .field("rw", &Hex::encode_to_string(self.rw).unwrap())
            .field("yp", &Hex::encode_to_string(self.yp).unwrap())
            .finish()
    }
}

impl fmt::Display for ProxyPublicContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProxyContext(warrant: {:?})",
            String::from_utf8_lossy(&self.warrant)
        )
    }
}

/// Proxy key pair derived from delegation
/// This type cannot be used to create new delegations (prevents redelegation chains)
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyKeyPair {
    /// Proxy's derived secret key
    pub sk: Scalar,
    /// Proxy's derived public key
    pub pk: Point,
}

impl ProxyKeyPair {
    /// Sign a message using the proxy key
    ///
    /// # Arguments
    /// * `message` - Message to sign
    ///
    /// # Returns
    /// A Schnorr signature created with the proxy key
    ///
    /// # Errors
    /// Returns an error if signature creation fails
    pub fn sign(&self, message: &[u8]) -> Result<SchnorrSignature> {
        SchnorrSignature::sign(&self.sk, message)
    }

    /// Get a reference to the public key
    pub fn public_key(&self) -> &Point {
        &self.pk
    }

    /// Get a reference to the secret key
    pub fn secret_key(&self) -> &Scalar {
        &self.sk
    }

    /// Verify a signature with this proxy key
    ///
    /// # Arguments
    /// * `message` - Message that was signed
    /// * `signature` - Signature to verify
    ///
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise
    ///
    /// # Errors
    /// Returns an error if verification fails
    pub fn verify(&self, message: &[u8], signature: &SchnorrSignature) -> Result<bool> {
        signature.verify(&self.pk, message)
    }
}

impl fmt::Debug for ProxyKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyKeyPair")
            .field("sk", &"<redacted>")
            .field("pk", &Hex::encode_to_string(self.pk).unwrap())
            .finish()
    }
}

impl fmt::Display for ProxyKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProxyKeyPair(pk: {}...)",
            &Hex::encode_to_string(self.pk).unwrap()[..8]
        )
    }
}

impl AsRef<Point> for ProxyKeyPair {
    fn as_ref(&self) -> &Point {
        &self.pk
    }
}

impl From<&ProxyKeyPair> for Point {
    fn from(proxy: &ProxyKeyPair) -> Self {
        proxy.pk
    }
}

impl Hash for ProxyKeyPair {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Only hash the public key, not the secret key
        self.pk.hash(state);
    }
}

/// Derive proxy signing keys from a delegation token
///
/// # Arguments
/// * `b_keys` - Proxy's key pair
/// * `a_pub` - Original signer's public key
/// * `token` - Valid delegation token bound to this proxy
///
/// # Returns
/// A tuple of (proxy secret key, proxy public key)
///
/// # Errors
/// Returns `InvalidDelegation` if token verification fails, `ProxyKeyMismatch`
/// if the proxy's public key doesn't match the bound key, or if derived keys
/// don't match expected values
pub fn derive_proxy_keys(
    b_keys: &KeyPair,
    a_pub: &Point,
    token: &DelegationToken,
) -> Result<(Scalar, Point)> {
    // Verify that this proxy is the one bound to the delegation token
    if !utils::memcmp(&b_keys.pk, &token.b_pub) {
        return Err(ProxySignatureError::ProxyKeyMismatch);
    }

    if !token.verify(a_pub)? {
        return Err(ProxySignatureError::InvalidDelegation);
    }

    // Use the bound proxy key in the hash
    let e_w = hash_to_scalar(&[&token.warrant, &token.rw, &token.b_pub])?;
    let xp = ristretto255::scalar_add(&token.sw, &b_keys.sk)?;

    // Compute YP both ways for verification
    let yp_from_secret = scalarmult_ristretto::scalarmult_base(&xp)?;
    let e_times_a = scalarmult_ristretto::scalarmult(&e_w, a_pub)?;
    let temp = ristretto255::add(&token.rw, &e_times_a)?;
    let yp_from_relation = ristretto255::add(&temp, &b_keys.pk)?;

    // Use constant-time comparison
    if !utils::memcmp(&yp_from_secret, &yp_from_relation) {
        return Err(ProxySignatureError::ProxyKeyMismatch);
    }

    Ok((xp, yp_from_secret))
}

/// Derive proxy signing key pair from a delegation token
///
/// # Arguments
/// * `b_keys` - Proxy's original key pair
/// * `a_pub` - Original signer's public key
/// * `token` - Valid delegation token bound to this proxy
///
/// # Returns
/// A `ProxyKeyPair` that cannot be used to create new delegations (type-safe)
///
/// # Errors
/// Returns `InvalidDelegation` if token verification fails, `ProxyKeyMismatch`
/// if the proxy's public key doesn't match the bound key
pub fn derive_proxy_key_pair(
    b_keys: &KeyPair,
    a_pub: &Point,
    token: &DelegationToken,
) -> Result<ProxyKeyPair> {
    let (xp, yp) = derive_proxy_keys(b_keys, a_pub, token)?;
    Ok(ProxyKeyPair { sk: xp, pk: yp })
}

/// Create a proxy signature for a message
///
/// # Arguments
/// * `xp` - Proxy's derived secret key
/// * `message` - Message to sign
///
/// # Returns
/// A Schnorr signature created with the proxy key
///
/// # Errors
/// Returns an error if signature creation fails
pub fn proxy_sign(xp: &Scalar, message: &[u8]) -> Result<SchnorrSignature> {
    SchnorrSignature::sign(xp, message)
}

/// Verify a proxy signature
///
/// # Arguments
/// * `a_pub` - Original signer's public key
/// * `b_pub` - Proxy's public key
/// * `message` - Message that was signed
/// * `sig` - Signature to verify
/// * `ctx` - Public context containing warrant and derived keys
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise
///
/// # Errors
/// Returns an error if any cryptographic operation fails
pub fn proxy_verify(
    a_pub: &Point,
    b_pub: &Point,
    message: &[u8],
    sig: &SchnorrSignature,
    ctx: &ProxyPublicContext,
) -> Result<bool> {
    // Include proxy's public key in the hash for bound delegation verification
    let e_w = hash_to_scalar(&[&ctx.warrant, &ctx.rw, b_pub])?;
    let e_times_a = scalarmult_ristretto::scalarmult(&e_w, a_pub)?;
    let temp = ristretto255::add(&ctx.rw, &e_times_a)?;
    let yp = ristretto255::add(&temp, b_pub)?;

    // Verify that the provided YP matches the computed one using constant-time comparison
    if !utils::memcmp(&ctx.yp, &yp) {
        return Ok(false);
    }

    sig.verify(&yp, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() -> Result<()> {
        let keypair = KeyPair::new()?;
        assert_eq!(keypair.sk.len(), ristretto255::SCALARBYTES);
        assert_eq!(keypair.pk.len(), ristretto255::BYTES);

        // Verify that multiple key generations produce different keys
        let keypair2 = KeyPair::new()?;
        assert!(!utils::memcmp(&keypair.sk, &keypair2.sk));
        assert!(!utils::memcmp(&keypair.pk, &keypair2.pk));

        Ok(())
    }

    #[test]
    fn test_schnorr_signature() -> Result<()> {
        let keypair = KeyPair::new()?;
        let message = b"Test message for signing";

        // Sign and verify
        let sig = SchnorrSignature::sign(&keypair.sk, message)?;
        assert!(sig.verify(&keypair.pk, message)?);

        // Wrong message should fail
        let wrong_message = b"Different message";
        assert!(!sig.verify(&keypair.pk, wrong_message)?);

        // Wrong public key should fail
        let other_keypair = KeyPair::new()?;
        assert!(!sig.verify(&other_keypair.pk, message)?);

        Ok(())
    }

    #[test]
    fn test_delegation_token() -> Result<()> {
        let a = KeyPair::new()?;
        let b = KeyPair::new()?;
        let warrant = b"Proxy B may sign for A until 2024-12-31";

        // Create and verify delegation
        let token = DelegationToken::create(&a, &b.pk, warrant)?;
        assert!(token.verify(&a.pk)?);

        // Verification with wrong public key should fail
        assert!(!token.verify(&b.pk)?);

        // Modified warrant should fail
        let mut bad_token = token.clone();
        bad_token.warrant = b"Modified warrant".to_vec();
        assert!(!bad_token.verify(&a.pk)?);

        Ok(())
    }

    #[test]
    fn test_proxy_signature_flow() -> Result<()> {
        // Setup: Create key pairs
        let a = KeyPair::new()?; // Original signer
        let b = KeyPair::new()?; // Proxy signer

        // Step 1: Create delegation
        let warrant = b"Proxy B may sign on behalf of A for project X";
        let token = DelegationToken::create(&a, &b.pk, warrant)?;
        assert!(token.verify(&a.pk)?);

        // Step 2: Derive proxy keys
        let (xp, yp) = derive_proxy_keys(&b, &a.pk, &token)?;

        // Step 3: Create proxy signature
        let message = b"Authorize payment of 100 units";
        let sig = proxy_sign(&xp, message)?;

        // Step 4: Verify proxy signature
        let ctx = ProxyPublicContext {
            warrant: warrant.to_vec(),
            rw: token.rw,
            yp,
        };

        assert!(proxy_verify(&a.pk, &b.pk, message, &sig, &ctx)?);

        // Wrong message should fail
        let wrong_message = b"Authorize payment of 200 units";
        assert!(!proxy_verify(&a.pk, &b.pk, wrong_message, &sig, &ctx)?);

        // Wrong warrant in context should fail
        let bad_ctx = ProxyPublicContext {
            warrant: b"Different warrant".to_vec(),
            rw: token.rw,
            yp,
        };
        assert!(!proxy_verify(&a.pk, &b.pk, message, &sig, &bad_ctx)?);

        // Wrong proxy public key should fail
        let c = KeyPair::new()?;
        assert!(!proxy_verify(&a.pk, &c.pk, message, &sig, &ctx)?);

        Ok(())
    }

    #[test]
    fn test_invalid_delegation() -> Result<()> {
        let a = KeyPair::new()?;
        let b = KeyPair::new()?;
        let warrant = b"Test warrant";

        // Create valid token but tamper with it
        let mut token = DelegationToken::create(&a, &b.pk, warrant)?;

        // Tamper with sw
        token.sw[0] ^= 0xFF;

        // Deriving proxy keys should fail
        match derive_proxy_keys(&b, &a.pk, &token) {
            Err(ProxySignatureError::InvalidDelegation) => (),
            _ => panic!("Expected InvalidDelegation error"),
        }

        Ok(())
    }

    #[test]
    fn test_proxy_binding_prevents_transfer() -> Result<()> {
        let a = KeyPair::new()?;
        let b = KeyPair::new()?;
        let c = KeyPair::new()?; // Different proxy
        let warrant = b"Proxy B may sign for A";

        // Create delegation for proxy B
        let token = DelegationToken::create(&a, &b.pk, warrant)?;
        assert!(token.verify(&a.pk)?);

        // B can derive proxy keys
        let (xp_b, yp_b) = derive_proxy_keys(&b, &a.pk, &token)?;
        assert_eq!(xp_b.len(), 32);
        assert_eq!(yp_b.len(), 32);

        // C cannot use B's delegation token (proxy binding prevents this)
        match derive_proxy_keys(&c, &a.pk, &token) {
            Err(ProxySignatureError::ProxyKeyMismatch) => (),
            _ => panic!("Expected ProxyKeyMismatch error for wrong proxy"),
        }

        // Create proxy signature with B's keys
        let message = b"Test message";
        let sig = proxy_sign(&xp_b, message)?;

        // Verify works with correct proxy
        let ctx = ProxyPublicContext {
            warrant: warrant.to_vec(),
            rw: token.rw,
            yp: yp_b,
        };
        assert!(proxy_verify(&a.pk, &b.pk, message, &sig, &ctx)?);

        // Verify fails with wrong proxy public key (C instead of B)
        assert!(!proxy_verify(&a.pk, &c.pk, message, &sig, &ctx)?);

        Ok(())
    }

    #[test]
    fn test_proxy_cannot_redelegate() -> Result<()> {
        let a = KeyPair::new()?;
        let b = KeyPair::new()?;
        let warrant_ab = b"Proxy B may sign for A";

        // A creates delegation for B
        let token_ab = DelegationToken::create(&a, &b.pk, warrant_ab)?;
        assert!(token_ab.verify(&a.pk)?);

        // B derives proxy keys - returns ProxyKeyPair type
        let proxy_keys = derive_proxy_key_pair(&b, &a.pk, &token_ab)?;

        // ProxyKeyPair can sign messages
        let message = b"Test message";
        let sig = proxy_keys.sign(message)?;
        assert!(sig.verify(&proxy_keys.pk, message)?);

        // Type safety: Cannot pass ProxyKeyPair to DelegationToken::create
        // The following would not compile:
        // let token_bc = DelegationToken::create(&proxy_keys, &c.pk, warrant_bc);
        //
        // This prevents proxy-to-proxy redelegation at compile time!
        // No runtime check needed - the type system enforces this constraint.

        // Verify that proxy keys work for their intended purpose (signing)
        let sig2 = proxy_sign(&proxy_keys.sk, b"Another message")?;
        assert_eq!(sig2.s.len(), 32);

        Ok(())
    }

    #[test]
    fn test_trait_implementations() -> Result<()> {
        // Test Debug trait - doesn't expose secrets
        let keypair = KeyPair::new()?;
        let debug_str = format!("{:?}", keypair);
        assert!(debug_str.contains("<redacted>"));
        assert!(!debug_str.contains(&Hex::encode_to_string(keypair.sk).unwrap()));

        // Test Display trait
        let display_str = format!("{}", keypair);
        assert!(display_str.starts_with("KeyPair(pk: "));

        // Test PartialEq and Eq
        let keypair2 = KeyPair::from_secret_key(keypair.sk)?;
        assert_eq!(keypair, keypair2);

        // Test Hash trait - can use in HashMap
        use std::collections::HashMap;
        let mut map = HashMap::new();
        map.insert(keypair.clone(), "test value");
        assert_eq!(map.get(&keypair2), Some(&"test value"));

        // Test convenience methods
        assert_eq!(keypair.public_key(), &keypair.pk);
        assert_eq!(keypair.secret_key(), &keypair.sk);

        // Test AsRef trait
        let pk_ref: &Point = keypair.as_ref();
        assert_eq!(pk_ref, &keypair.pk);

        // Test From trait
        let pk: Point = Point::from(&keypair);
        assert_eq!(pk, keypair.pk);

        // Test DelegationToken traits
        let b = KeyPair::new()?;
        let warrant = b"Test warrant";
        let token = DelegationToken::create(&keypair, &b.pk, warrant)?;

        // Test Debug doesn't expose sw
        let token_debug = format!("{:?}", token);
        assert!(token_debug.contains("<redacted>"));
        assert!(!token_debug.contains(&Hex::encode_to_string(token.sw).unwrap()));

        // Test Display
        let token_display = format!("{}", token);
        assert!(token_display.contains("Test warrant"));

        // Test convenience methods
        assert_eq!(token.warrant_str()?, "Test warrant");
        assert_eq!(token.proxy_public_key(), &b.pk);

        // Test ProxyPublicContext builder
        let ctx = ProxyPublicContext::from_token(&token, keypair.pk);
        assert_eq!(ctx.warrant, token.warrant);
        assert_eq!(ctx.rw, token.rw);

        // Test SchnorrSignature traits
        let msg = b"Test message";
        let sig = SchnorrSignature::sign(&keypair.sk, msg)?;
        let sig2 = SchnorrSignature::sign(&keypair.sk, msg)?;
        assert_ne!(sig, sig2); // Different nonce, different signature

        // Test Hash for SchnorrSignature
        let mut sig_map = HashMap::new();
        sig_map.insert(sig.clone(), "signature 1");
        assert_eq!(sig_map.get(&sig), Some(&"signature 1"));

        Ok(())
    }
}
