//! blind_sig.rs — RSA blind signature scheme (Chaum, 1983)
//!
//! # Why blind signatures?
//!
//! The critical property of Nothing is *unlinkability*: the issuer (mint) signs
//! a token serial number, but they never see the serial number.  This means that
//! when a valid token appears later for settlement, the mint cannot tell which
//! signing event produced it.
//!
//! # How it works (plain English)
//!
//!   Alice (requester) wants the Mint to sign her serial `m` without the Mint
//!   ever seeing `m`.
//!
//!   1. Alice picks a random *blinding factor* `r`.
//!   2. Alice computes the *blinded message*:  m' = H(m) * r^e  mod n
//!      (She multiplied her hash by a random mask.  It looks like noise.)
//!   3. Alice sends m' to the Mint.
//!   4. Mint signs it:  s' = (m')^d mod n   (applies the private key)
//!   5. Alice *unblinds*: s = s' * r^(-1) mod n
//!      Because:  s' = (m')^d = (H(m) * r^e)^d = H(m)^d * r^(e*d) = H(m)^d * r
//!      So:       s = H(m)^d * r * r^(-1) = H(m)^d mod n
//!      Which is a valid RSA signature on H(m)!
//!   6. Anyone can verify: s^e mod n == H(m)  ✓
//!
//! The Mint signed m' (a random-looking number) and has no record of what m was.
//!
//! # Important caveat
//!
//! This implementation uses *raw*, unpadded RSA for educational clarity.
//! Production systems should use RSA-PSS or PKCS#1 v1.5 padding.  Without
//! padding, RSA has multiplicative homomorphism vulnerabilities.  Do NOT use
//! this code to protect real value without adding proper padding.
//!
//! # Note on BigUint types
//!
//! The `rsa` crate uses `num-bigint-dig` (a fork of num-bigint) as its big
//! integer library.  We use the same crate so our `BigUint` is the exact same
//! type as `rsa`'s — no conversion needed when working with key components.

use anyhow::{anyhow, Context, Result};
// num_bigint_dig is the same crate that rsa 0.9 uses internally.
// BigUint from here is identical to rsa::BigUint.
use num_bigint_dig::{BigInt, BigUint, ModInverse, RandBigInt, ToBigInt};
use num_traits::One;
use rand::thread_rng;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

// ─── RSA mint keypair ─────────────────────────────────────────────────────────

/// The Mint keypair: an RSA private/public key pair used for blind signing.
///
/// In Nothing, the same user is both minter and (initially) holder — the mint
/// key proves a token was legitimately generated, not forged.
pub struct MintKeypair {
    pub private_key: RsaPrivateKey,
    pub public_key: RsaPublicKey,
}

/// Disk-serialisable form of the mint keypair.
#[derive(Serialize, Deserialize)]
struct MintKeypairStorage {
    /// PKCS#8 PEM of the private key.
    /// WARNING: keep this file secret — it controls token issuance.
    private_key_pem: String,
    /// RSA public modulus n in hex (big-endian bytes).
    pub_n_hex: String,
    /// RSA public exponent e in hex (big-endian bytes).
    pub_e_hex: String,
}

impl MintKeypair {
    /// Generate a new RSA mint keypair.
    ///
    /// `bits` is the key size. 2048 is the minimum; use 4096 for production.
    pub fn generate(bits: usize) -> Result<Self> {
        let mut rng = thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, bits)
            .map_err(|e| anyhow!("RSA key generation failed: {}", e))?;
        let public_key = RsaPublicKey::from(&private_key);
        Ok(MintKeypair {
            private_key,
            public_key,
        })
    }

    /// Save to a JSON file.
    pub fn save(&self, path: &Path) -> Result<()> {
        let pem = self
            .private_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| anyhow!("PKCS#8 encode failed: {}", e))?;

        let storage = MintKeypairStorage {
            private_key_pem: pem.to_string(),
            // to_bytes_be() converts BigUint to big-endian bytes Vec<u8>
            pub_n_hex: hex::encode(self.public_key.n().to_bytes_be()),
            pub_e_hex: hex::encode(self.public_key.e().to_bytes_be()),
        };

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_string_pretty(&storage)?)
            .with_context(|| format!("writing mint keypair to {:?}", path))
    }

    /// Load from a JSON file.
    pub fn load(path: &Path) -> Result<Self> {
        let data = fs::read_to_string(path)
            .with_context(|| format!("reading mint keypair from {:?}", path))?;
        let storage: MintKeypairStorage =
            serde_json::from_str(&data).context("deserialising mint keypair")?;

        let private_key = RsaPrivateKey::from_pkcs8_pem(&storage.private_key_pem)
            .map_err(|e| anyhow!("PKCS#8 decode failed: {}", e))?;
        let public_key = RsaPublicKey::from(&private_key);

        Ok(MintKeypair {
            private_key,
            public_key,
        })
    }

    /// Public key as a serialisable struct for embedding in tokens.
    pub fn public_key_info(&self) -> MintPublicKeyInfo {
        MintPublicKeyInfo {
            n_hex: hex::encode(self.public_key.n().to_bytes_be()),
            e_hex: hex::encode(self.public_key.e().to_bytes_be()),
        }
    }
}

// ─── Public key info (embeddable in tokens) ───────────────────────────────────

/// The mint's public key, embedded in every token so anyone can verify.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MintPublicKeyInfo {
    /// RSA modulus n, hex-encoded big-endian.
    pub n_hex: String,
    /// RSA public exponent e, hex-encoded big-endian.
    pub e_hex: String,
}

impl MintPublicKeyInfo {
    /// Reconstruct the RsaPublicKey from stored n and e.
    pub fn to_rsa_public_key(&self) -> Result<RsaPublicKey> {
        let n = BigUint::from_bytes_be(&hex::decode(&self.n_hex)?);
        let e = BigUint::from_bytes_be(&hex::decode(&self.e_hex)?);
        // RsaPublicKey::new takes num_bigint_dig::BigUint — same type we imported.
        RsaPublicKey::new(n, e).map_err(|e| anyhow!("invalid RSA public key: {}", e))
    }
}

// ─── Blinding state (kept by requester) ──────────────────────────────────────

/// Secret state the requester holds during the blinding phase.
/// `r_inv` is the modular inverse of the blinding factor: r^(-1) mod n.
/// NEVER sent to the mint.
pub struct BlindingState {
    r_inv: BigUint,
    n: BigUint,
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Compute the modular inverse of `a` modulo `m`.
///
/// Uses num_bigint_dig's built-in `ModInverse` trait (extended Euclidean
/// algorithm underneath).  Returns `None` if gcd(a, m) ≠ 1.
fn mod_inverse_biguint(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    // ModInverse::mod_inverse returns Option<BigInt> (signed).
    // We normalise to [0, m) in case the result is negative.
    let result: BigInt = a.clone().mod_inverse(m)?;
    let m_signed: BigInt = m.to_bigint().expect("always converts");
    let normalised = ((result % &m_signed) + &m_signed) % &m_signed;
    normalised.to_biguint()
}

/// Hash the serial number to a BigUint in [0, n-1].
///
/// Domain-separated so the hash is specific to this protocol.
///
/// NOTE: For production, apply RSA-PSS padding here instead of the raw hash.
/// This unpadded version is for educational clarity only.
fn hash_serial_to_biguint(serial: &[u8], n: &BigUint) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(b"nothing-v1|serial|"); // domain separator
    hasher.update(serial);
    let digest = hasher.finalize();
    BigUint::from_bytes_be(&digest) % n
}

// ─── Core blind signature operations ─────────────────────────────────────────

/// **Step 1 (requester)**: Blind a serial number before sending to the mint.
///
/// Returns:
///   - `blinded_bytes`: bytes to send to the mint for signing (looks random).
///   - `state`:         private blinding state — keep this, needed to unblind.
pub fn blind_serial(serial: &[u8], mint_pubkey: &RsaPublicKey) -> (Vec<u8>, BlindingState) {
    let mut rng = thread_rng();

    // Clone the key components into owned BigUint values for arithmetic.
    // These are num_bigint_dig::BigUint — the same type as rsa's internals.
    let n: BigUint = mint_pubkey.n().clone();
    let e: BigUint = mint_pubkey.e().clone();

    // Hash the serial into the RSA group.
    let m = hash_serial_to_biguint(serial, &n);

    // Choose random blinding factor r in [2, n-2].
    // gcd(r, n) = 1 with overwhelming probability for 2048-bit RSA.
    let r = rng.gen_biguint_range(&BigUint::from(2u64), &(n.clone() - BigUint::one()));

    // Blinded message: m' = m * r^e  mod n
    // To the mint, m' looks like a uniformly random element of Z_n.
    let r_e = r.modpow(&e, &n);
    let blinded = (m * &r_e) % &n;

    // Precompute r^(-1) mod n for the unblinding step.
    let r_inv =
        mod_inverse_biguint(&r, &n).expect("r is coprime to n with overwhelming probability");

    let state = BlindingState { r_inv, n };
    (blinded.to_bytes_be(), state)
}

/// **Step 2 (mint/issuer)**: Sign a blinded message without knowing the serial.
///
/// Applies the RSA private exponent: s' = blinded^d mod n.
pub fn mint_sign_blinded(blinded_bytes: &[u8], mint_keypair: &MintKeypair) -> Result<Vec<u8>> {
    let n: BigUint = mint_keypair.private_key.n().clone();
    let d: BigUint = mint_keypair.private_key.d().clone();

    let blinded = BigUint::from_bytes_be(blinded_bytes);

    // s' = blinded^d mod n
    // This is raw RSA "decryption" repurposed for signing.
    let blind_sig = blinded.modpow(&d, &n);

    Ok(blind_sig.to_bytes_be())
}

/// **Step 3 (requester)**: Unblind the signature.
///
/// s = s' * r^(-1) mod n = H(serial)^d mod n
/// This is a valid RSA signature that the mint cannot link to the blinding event.
pub fn unblind_signature(blind_sig_bytes: &[u8], state: &BlindingState) -> Vec<u8> {
    let blind_sig = BigUint::from_bytes_be(blind_sig_bytes);
    let sig = (blind_sig * &state.r_inv) % &state.n;
    sig.to_bytes_be()
}

/// **Verify** a token's blind signature.
///
/// Raises the signature to the public exponent and checks it equals H(serial).
/// Anyone can verify — only the public key is required.
pub fn verify_blind_signature(
    serial: &[u8],
    signature_bytes: &[u8],
    mint_pubkey: &RsaPublicKey,
) -> bool {
    let n: BigUint = mint_pubkey.n().clone();
    let e: BigUint = mint_pubkey.e().clone();

    let sig = BigUint::from_bytes_be(signature_bytes);
    let expected = hash_serial_to_biguint(serial, &n);

    // s^e mod n == H(serial) — only valid if the private exponent was applied.
    sig.modpow(&e, &n) == expected
}
