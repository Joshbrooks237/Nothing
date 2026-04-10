//! token.rs — the NothingToken structure and sealed-box encryption/decryption
//!
//! # What a Nothing token looks like
//!
//! A token has two layers:
//!
//!   Layer 1 — The *credential*: a random serial number + a blind RSA signature
//!             over that serial.  Anyone who knows the mint's public key can
//!             verify the signature is legitimate.
//!
//!   Layer 2 — The *sealed payload*: arbitrary metadata (note, timestamp, etc.)
//!             encrypted to the *recipient's* X25519 public key using libsodium's
//!             sealed-box construction.  Only the intended recipient can read it.
//!             During transit this layer is opaque ciphertext — indistinguishable
//!             from random noise.
//!
//! # Why it has "no identity in transit"
//!
//!   Before settlement the token is just a blob of bytes.  There is no ticker
//!   symbol embedded, no ledger entry, no account number.  The only way to
//!   confirm what it *is* is to decrypt + verify it — at which point it has
//!   already arrived.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use dryoc::classic::crypto_box::{
    crypto_box_seal, crypto_box_seal_open, PublicKey as DryocBoxPK, SecretKey as DryocBoxSK,
};
use dryoc::constants::CRYPTO_BOX_SEALBYTES;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::blind_sig::{
    blind_serial, mint_sign_blinded, unblind_signature, verify_blind_signature, MintKeypair,
    MintPublicKeyInfo,
};
use crate::crypto::keypair::BoxKeypair;

// ─── Sealed payload (readable only by the recipient) ─────────────────────────

/// The inner payload sealed to the recipient.
/// Encrypted with libsodium-compatible sealed-box (X25519 + XSalsa20-Poly1305).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SealedPayload {
    /// A human-readable note from the minter.  Not visible during transit.
    pub note: String,
    /// Unix timestamp (seconds) when this token was minted.
    pub minted_at: u64,
    /// Hex-encoded X25519 public key of the minter (optional provenance info).
    pub minter_box_pubkey_hex: String,
}

// ─── NothingToken ─────────────────────────────────────────────────────────────

/// A Nothing token — a cryptographic bearer instrument.
///
/// The token is serialised to a `.nothing` JSON file on disk.  The file can
/// be sent to anyone; only the intended recipient (who holds the matching box
/// secret key) can decrypt and verify the inner payload.
///
/// The *blind signature* proves the token was legitimately minted.
/// The *sealed payload* addresses the token to a specific recipient.
///
/// Before successful receipt + verification, the token classifies as nothing.
/// The moment it lands, it has already arrived.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NothingToken {
    /// Protocol version — bump when the format changes.
    pub version: u8,

    /// Random 32-byte serial number, hex-encoded.
    /// This is what the mint blindly signed.  It is the token's unique identity.
    pub serial_hex: String,

    /// RSA blind signature over H("nothing-v1|serial|" || serial), hex-encoded.
    /// Verify this against `mint_pubkey` to confirm the token is genuine.
    pub blind_signature_hex: String,

    /// The mint's RSA public key.  Anyone can use this to verify the signature
    /// without contacting the mint (no central server needed).
    pub mint_pubkey: MintPublicKeyInfo,

    /// The sealed payload (note + timestamp), encrypted to the recipient's
    /// X25519 public key.  Base64-encoded ciphertext.
    /// Opaque to everyone except the recipient.
    pub sealed_payload_b64: String,
}

impl NothingToken {
    /// Mint a new token.
    ///
    /// - `mint_keypair`:     the issuer's RSA blind-signature keypair.
    /// - `recipient_box_pk_hex`: hex-encoded X25519 public key of the recipient.
    /// - `minter_box_pk_hex`:    hex-encoded X25519 public key of the minter
    ///                           (embedded in the payload for provenance).
    /// - `note`:             a short message from the minter.
    ///
    /// The blind signature is computed here without the mint ever seeing the
    /// serial number in cleartext (the blinding step happens before signing).
    pub fn mint(
        mint_keypair: &MintKeypair,
        recipient_box_pk_hex: &str,
        minter_box_pk_hex: &str,
        note: &str,
    ) -> Result<Self> {
        // ── 1. Generate a cryptographically random 32-byte serial number.
        //    This is the unique identity of the token.  It will be blinded
        //    before the mint sees it.
        let mut serial = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut serial);

        // ── 2. Blind the serial and sign it.
        //    blind_serial() returns:
        //      - blinded_bytes: what we send to the mint for signing
        //      - blinding_state: our private state for unblinding
        let (blinded_bytes, blinding_state) = blind_serial(&serial, &mint_keypair.public_key);

        // ── 3. Mint signs the *blinded* bytes — never sees the plain serial.
        let blind_sig_bytes = mint_sign_blinded(&blinded_bytes, mint_keypair)
            .context("mint signing failed")?;

        // ── 4. Unblind: produce a valid RSA signature on H(serial).
        let signature_bytes = unblind_signature(&blind_sig_bytes, &blinding_state);

        // ── 5. Quick self-check: verify the signature we just produced.
        //    If this fails something is catastrophically wrong.
        debug_assert!(
            verify_blind_signature(&serial, &signature_bytes, &mint_keypair.public_key),
            "self-verification of blind signature failed — this is a bug"
        );

        // ── 6. Build the sealed payload and encrypt it to the recipient.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let payload = SealedPayload {
            note: note.to_string(),
            minted_at: now,
            minter_box_pubkey_hex: minter_box_pk_hex.to_string(),
        };

        let payload_json = serde_json::to_vec(&payload)?;

        // Decode the recipient's X25519 public key.
        let recipient_pk_bytes =
            hex::decode(recipient_box_pk_hex).context("recipient pubkey hex decode failed")?;

        // Seal the payload.  Uses libsodium's sealed_box construction:
        //   - Ephemeral X25519 keypair is generated internally.
        //   - ECDH(ephemeral_sk, recipient_pk) → shared secret.
        //   - XSalsa20-Poly1305 encrypts the payload.
        //   - Output: ephemeral_pk (32 bytes) || ciphertext || MAC.
        //
        // The sender (minter) is anonymous — the ephemeral key is discarded.
        // Only the recipient's X25519 secret key can open this box.
        let sealed_bytes = seal_box(&payload_json, &recipient_pk_bytes)
            .context("sealed-box encryption failed")?;

        Ok(NothingToken {
            version: 1,
            serial_hex: hex::encode(serial),
            blind_signature_hex: hex::encode(&signature_bytes),
            mint_pubkey: mint_keypair.public_key_info(),
            sealed_payload_b64: B64.encode(&sealed_bytes),
        })
    }

    /// Verify the blind signature on this token.
    ///
    /// Call this first upon receiving a token.  If this returns `false` the
    /// token is forged or corrupted.
    pub fn verify_signature(&self) -> Result<bool> {
        let serial = hex::decode(&self.serial_hex).context("serial hex decode")?;
        let sig = hex::decode(&self.blind_signature_hex).context("signature hex decode")?;
        let pubkey = self
            .mint_pubkey
            .to_rsa_public_key()
            .context("reconstruct mint pubkey")?;

        Ok(verify_blind_signature(&serial, &sig, &pubkey))
    }

    /// Decrypt and return the sealed payload.
    ///
    /// Requires the recipient's BoxKeypair (the matching secret key).
    /// Returns an error if the keypair is wrong or the ciphertext is corrupted.
    pub fn open_payload(&self, box_keypair: &BoxKeypair) -> Result<SealedPayload> {
        let sealed_bytes = B64
            .decode(&self.sealed_payload_b64)
            .context("base64 decode sealed payload")?;

        let pk_bytes = box_keypair
            .public_key_bytes()
            .context("box pubkey bytes")?;
        let sk_bytes = box_keypair
            .secret_key_bytes()
            .context("box seckey bytes")?;

        let plaintext = open_box(&sealed_bytes, &pk_bytes, &sk_bytes)
            .context("sealed-box decryption failed — wrong keypair or tampered ciphertext")?;

        serde_json::from_slice(&plaintext).context("deserialising payload")
    }

    /// Save this token to a `.nothing` JSON file.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_string_pretty(self)?)
            .with_context(|| format!("writing token to {:?}", path))
    }

    /// Load a token from a `.nothing` JSON file.
    pub fn load(path: &Path) -> Result<Self> {
        let data = fs::read_to_string(path)
            .with_context(|| format!("reading token from {:?}", path))?;
        serde_json::from_str(&data).context("deserialising token")
    }

    /// Raw bytes of this token (what gets sent over the wire).
    /// Looks like a JSON blob; the sealed payload inside is opaque ciphertext.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Parse a token from raw bytes (received over the wire).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).context("deserialising token from bytes")
    }

    /// A short fingerprint for display — first 8 bytes of the serial.
    pub fn short_id(&self) -> &str {
        &self.serial_hex[..16]
    }
}

// ─── Sealed-box helpers ───────────────────────────────────────────────────────
//
// These wrap dryoc's classic crypto_box_seal / crypto_box_seal_open API.
//
// libsodium sealed-box algorithm (what dryoc implements):
//   seal:
//     1. Generate ephemeral X25519 keypair (epk, esk).
//     2. Compute nonce = Blake2b(epk || recipient_pk), first 24 bytes.
//     3. Compute ciphertext = crypto_box_easy(message, nonce, recipient_pk, esk).
//        (This is Curve25519 DH + XSalsa20-Poly1305.)
//     4. Output: epk (32 bytes) || ciphertext || MAC (16 bytes).
//     5. Discard esk — sender is anonymous.
//
//   open:
//     1. Extract epk from the first 32 bytes.
//     2. Re-derive the nonce using Blake2b(epk || our_pk).
//     3. Decrypt with our secret key.
//
// The sender is fully anonymous.  Only the recipient (with our_sk) can open it.

/// Encrypt `plaintext` for the holder of `recipient_pk` (32-byte X25519).
///
/// Output layout: ephemeral_pk (32) || MAC (16) || ciphertext
/// Total overhead = CRYPTO_BOX_SEALBYTES = 48 bytes.
fn seal_box(plaintext: &[u8], recipient_pk_bytes: &[u8]) -> Result<Vec<u8>> {
    let pk: DryocBoxPK = recipient_pk_bytes
        .try_into()
        .map_err(|_| anyhow!("recipient pubkey must be exactly 32 bytes, got {}", recipient_pk_bytes.len()))?;

    // Allocate output buffer: plaintext + seal overhead.
    let mut ciphertext = vec![0u8; plaintext.len() + CRYPTO_BOX_SEALBYTES];

    crypto_box_seal(&mut ciphertext, plaintext, &pk)
        .map_err(|e| anyhow!("crypto_box_seal failed: {:?}", e))?;

    Ok(ciphertext)
}

/// Decrypt sealed ciphertext using our X25519 keypair (both 32-byte values).
fn open_box(ciphertext: &[u8], our_pk_bytes: &[u8], our_sk_bytes: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < CRYPTO_BOX_SEALBYTES {
        return Err(anyhow!(
            "ciphertext is too short: {} bytes, need at least {}",
            ciphertext.len(),
            CRYPTO_BOX_SEALBYTES
        ));
    }

    let pk: DryocBoxPK = our_pk_bytes
        .try_into()
        .map_err(|_| anyhow!("our pubkey must be exactly 32 bytes"))?;
    let sk: DryocBoxSK = our_sk_bytes
        .try_into()
        .map_err(|_| anyhow!("our seckey must be exactly 32 bytes"))?;

    // Allocate output buffer: ciphertext minus seal overhead.
    let mut plaintext = vec![0u8; ciphertext.len() - CRYPTO_BOX_SEALBYTES];

    crypto_box_seal_open(&mut plaintext, ciphertext, &pk, &sk)
        .map_err(|e| anyhow!("crypto_box_seal_open failed (wrong key or tampered): {:?}", e))?;

    Ok(plaintext)
}
