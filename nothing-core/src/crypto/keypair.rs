//! keypair.rs — identity and encryption key generation
//!
//! Two key types exist in Nothing:
//!
//!   1. SignKeypair  — Ed25519 (signing + libp2p peer identity)
//!      libsodium equivalent: crypto_sign keypair
//!      Used to prove "I am this peer" and to sign tokens as a minter.
//!
//!   2. BoxKeypair   — X25519 (asymmetric sealed-box encryption)
//!      libsodium equivalent: crypto_box keypair
//!      Used to *receive* tokens.  When someone mints a token for you they
//!      encrypt it to your box public key.  Only you — with the secret key —
//!      can read it.  In transit it is indistinguishable from random noise.
//!
//! Both types are stored as JSON files in ~/.nothing/keys/.

use anyhow::{Context, Result};
use dryoc::classic::crypto_box::crypto_box_keypair;
use dryoc::classic::crypto_sign::crypto_sign_keypair;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

// ─── Ed25519 signing keypair ──────────────────────────────────────────────────

/// An Ed25519 signing keypair.
///
/// The *public key* (32 bytes) is your peer identifier on the network and is
/// safe to share freely.
///
/// The *secret key* (64 bytes) is: 32-byte private seed || 32-byte public key.
/// Keep it secret; it controls everything that can be signed in your name.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignKeypair {
    /// 32-byte Ed25519 public key, hex-encoded for human readability.
    pub public_key_hex: String,
    /// 64-byte Ed25519 secret key (seed || pubkey), hex-encoded.
    /// NOTE: In production this should be encrypted at rest with a passphrase.
    pub secret_key_hex: String,
}

impl SignKeypair {
    /// Generate a fresh Ed25519 keypair using dryoc's CSPRNG.
    /// Equivalent to libsodium's `crypto_sign_keypair()`.
    pub fn generate() -> Self {
        // crypto_sign_keypair() returns two fixed-size byte arrays.
        // pk is 32 bytes (CRYPTO_SIGN_PUBLICKEYBYTES).
        // sk is 64 bytes (CRYPTO_SIGN_SECRETKEYBYTES = seed || pk).
        let (pk, sk) = crypto_sign_keypair();
        SignKeypair {
            public_key_hex: hex::encode(pk.as_ref()),
            secret_key_hex: hex::encode(sk.as_ref()),
        }
    }

    /// Raw public key bytes (32 bytes).
    pub fn public_key_bytes(&self) -> Result<Vec<u8>> {
        hex::decode(&self.public_key_hex).context("sign pubkey hex decode failed")
    }

    /// Raw secret key bytes (64 bytes: seed || pubkey).
    pub fn secret_key_bytes(&self) -> Result<Vec<u8>> {
        hex::decode(&self.secret_key_hex).context("sign seckey hex decode failed")
    }

    /// The 32-byte private *seed* (first half of the secret key).
    /// This is what libp2p expects when converting to a transport identity.
    pub fn seed_bytes(&self) -> Result<[u8; 32]> {
        let sk = self.secret_key_bytes()?;
        let seed: [u8; 32] = sk[..32]
            .try_into()
            .context("secret key too short for seed extraction")?;
        Ok(seed)
    }

    /// Save to a JSON file.  Creates parent directories if they don't exist.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_string_pretty(self)?)
            .with_context(|| format!("writing sign keypair to {:?}", path))
    }

    /// Load from a JSON file.
    pub fn load(path: &Path) -> Result<Self> {
        let data = fs::read_to_string(path)
            .with_context(|| format!("reading sign keypair from {:?}", path))?;
        serde_json::from_str(&data).context("deserialising sign keypair")
    }
}

// ─── X25519 box keypair ───────────────────────────────────────────────────────

/// An X25519 keypair used for receiving sealed tokens.
///
/// Share your *public key* with anyone who might send you Nothing.
/// Guard your *secret key* — it is the only way to open tokens addressed to you.
///
/// This is libsodium's `crypto_box` keypair (Curve25519 DH).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BoxKeypair {
    /// 32-byte X25519 public key, hex-encoded.  Share freely with senders.
    pub public_key_hex: String,
    /// 32-byte X25519 secret key, hex-encoded.  Keep private.
    pub secret_key_hex: String,
}

impl BoxKeypair {
    /// Generate a fresh X25519 keypair using dryoc's CSPRNG.
    /// Equivalent to libsodium's `crypto_box_keypair()`.
    pub fn generate() -> Self {
        // pk is 32 bytes (CRYPTO_BOX_PUBLICKEYBYTES).
        // sk is 32 bytes (CRYPTO_BOX_SECRETKEYBYTES).
        let (pk, sk) = crypto_box_keypair();
        BoxKeypair {
            public_key_hex: hex::encode(pk.as_ref()),
            secret_key_hex: hex::encode(sk.as_ref()),
        }
    }

    /// Raw public key bytes (32 bytes).
    pub fn public_key_bytes(&self) -> Result<Vec<u8>> {
        hex::decode(&self.public_key_hex).context("box pubkey hex decode failed")
    }

    /// Raw secret key bytes (32 bytes).
    pub fn secret_key_bytes(&self) -> Result<Vec<u8>> {
        hex::decode(&self.secret_key_hex).context("box seckey hex decode failed")
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_string_pretty(self)?)
            .with_context(|| format!("writing box keypair to {:?}", path))
    }

    pub fn load(path: &Path) -> Result<Self> {
        let data = fs::read_to_string(path)
            .with_context(|| format!("reading box keypair from {:?}", path))?;
        serde_json::from_str(&data).context("deserialising box keypair")
    }
}
