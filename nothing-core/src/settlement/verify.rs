//! verify.rs — Groth16 proof verification for Nothing settlement
//!
//! # What Groth16 verification does (briefly)
//!
//! A Groth16 proof consists of three points on the BN254 elliptic curve:
//!   π_a ∈ G1,  π_b ∈ G2,  π_c ∈ G1
//!
//! Verification checks the pairing equation:
//!   e(π_a, π_b) == e(α, β) · e(vk_x, γ) · e(π_c, δ)
//!
//! where:
//!   - (α, β, γ, δ) are from the verification key (generated during trusted setup)
//!   - vk_x = IC[0] + Σᵢ public_input[i] · IC[i+1]
//!   - e() is the BN254 ate-pairing
//!
//! This equation holds if and only if the prover knew a valid witness for the
//! NothingSettle circuit — meaning they knew a (serial, signature) pair
//! satisfying the RSA constraint and matching the nullifier.
//!
//! # Proof format
//!
//! snarkjs outputs proofs as JSON with decimal-encoded field elements.
//! BN254 field elements are ~77-digit decimal numbers.
//! G1 points use Fq (base field), G2 points use Fq2 (quadratic extension).
//!
//! We parse these into ark-groth16 types for verification.

use anyhow::{anyhow, Context, Result};
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_snark::SNARK;
// num_bigint_dig is already a dependency (used by the `rsa` crate).
// We use it here to parse large decimal strings into byte arrays
// that ark-ff can then convert to field elements.
use num_bigint_dig::BigUint;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

// ─── snarkjs JSON structures ──────────────────────────────────────────────────
//
// These mirror the exact JSON format that snarkjs outputs.
// All field elements are decimal-encoded strings.

/// snarkjs proof file (pi_a, pi_b, pi_c in decimal coords).
#[derive(Debug, Deserialize)]
struct SnarkjsProof {
    pi_a: Vec<String>,
    pi_b: Vec<Vec<String>>,
    pi_c: Vec<String>,
}

/// Metadata embedded in the proof bundle by prove.js.
#[derive(Debug, Deserialize, Serialize)]
pub struct ProofMeta {
    /// Hex-encoded nullifier (Poseidon hash of serial).
    pub nullifier: String,
    pub token_path: String,
    pub circuit: String,
}

/// The full proof bundle written by prove.js.
/// Contains the proof, public signals, and metadata.
#[derive(Debug, Deserialize)]
pub struct ProofBundle {
    proof: SnarkjsProof,
    /// The public inputs as decimal strings, in the same order as declared
    /// in the circuit's `{public [...]}` annotation.
    /// For NothingSettle(64,32): [modulus[0..31], serial_nullifier]
    pub public_signals: Vec<String>,
    pub meta: ProofMeta,
}

/// snarkjs verification key JSON format.
#[derive(Debug, Deserialize)]
struct SnarkjsVk {
    /// α in G1 (pairing input)
    vk_alpha_1: Vec<String>,
    /// β in G2 (pairing input)
    vk_beta_2: Vec<Vec<String>>,
    /// γ in G2 (pairing input)
    vk_gamma_2: Vec<Vec<String>>,
    /// δ in G2 (pairing input)
    vk_delta_2: Vec<Vec<String>>,
    /// IC — "input commitments": one G1 point per public signal + 1.
    /// IC[0] is for the implicit constant 1; IC[i] is for public_signal[i-1].
    #[serde(rename = "IC")]
    ic: Vec<Vec<String>>,
}

// ─── Field element parsers ────────────────────────────────────────────────────

/// Parse an Fq (BN254 base field) element from a decimal string.
///
/// snarkjs outputs decimal strings like "123456789...".
/// We parse via BigUint → big-endian bytes → Fq::from_be_bytes_mod_order.
fn parse_fq(s: &str) -> Result<Fq> {
    let n = s
        .parse::<BigUint>()
        .with_context(|| format!("parse Fq decimal: {:?}", &s[..s.len().min(20)]))?;
    let bytes = n.to_bytes_be();
    // Fq needs exactly 32 bytes (256-bit).
    let mut padded = [0u8; 32];
    let offset = 32usize.saturating_sub(bytes.len());
    padded[offset..].copy_from_slice(&bytes[..bytes.len().min(32)]);
    // from_be_bytes_mod_order: treats the byte array as a big-endian integer
    // and reduces modulo the field prime.  Since snarkjs outputs canonical
    // field elements, no actual reduction occurs here.
    Ok(Fq::from_be_bytes_mod_order(&padded))
}

/// Parse an Fr (BN254 scalar field) element from a decimal string.
///
/// Fr is the field of public inputs and witness values (not curve coordinates).
fn parse_fr(s: &str) -> Result<Fr> {
    let n = s
        .parse::<BigUint>()
        .with_context(|| format!("parse Fr decimal: {:?}", &s[..s.len().min(20)]))?;
    let bytes = n.to_bytes_be();
    let mut padded = [0u8; 32];
    let offset = 32usize.saturating_sub(bytes.len());
    padded[offset..].copy_from_slice(&bytes[..bytes.len().min(32)]);
    Ok(Fr::from_be_bytes_mod_order(&padded))
}

// ─── Curve point parsers ──────────────────────────────────────────────────────

/// Parse a G1 affine point from snarkjs's [x, y, "1"] format.
///
/// G1 is the "small" subgroup of BN254 — points (x, y) where x, y ∈ Fq.
/// The third coordinate "1" indicates this is an affine (not projective) point.
fn parse_g1(coords: &[String]) -> Result<G1Affine> {
    if coords.len() < 2 {
        return Err(anyhow!("G1 point needs at least 2 coordinates"));
    }
    let x = parse_fq(&coords[0]).context("G1 x coordinate")?;
    let y = parse_fq(&coords[1]).context("G1 y coordinate")?;
    // new_unchecked does NOT check if the point is on the curve.
    // We check below.
    let pt = G1Affine::new_unchecked(x, y);
    if !pt.is_on_curve() {
        return Err(anyhow!("G1 point not on BN254 curve"));
    }
    Ok(pt)
}

/// Parse a G2 affine point from snarkjs's [[x0,x1],[y0,y1],["1","0"]] format.
///
/// G2 is the "large" subgroup of BN254 — points defined over Fq2 (the
/// degree-2 extension of Fq).  Each Fq2 element is a pair (c0, c1) where
/// the element represents c0 + c1·u (with u² = non-residue in Fq).
///
/// snarkjs layout: coords[0] = [x_c0, x_c1], coords[1] = [y_c0, y_c1].
fn parse_g2(coords: &[Vec<String>]) -> Result<G2Affine> {
    if coords.len() < 2 {
        return Err(anyhow!("G2 point needs at least 2 coordinate pairs"));
    }
    let x = Fq2::new(
        parse_fq(&coords[0][0]).context("G2 x.c0")?,
        parse_fq(&coords[0][1]).context("G2 x.c1")?,
    );
    let y = Fq2::new(
        parse_fq(&coords[1][0]).context("G2 y.c0")?,
        parse_fq(&coords[1][1]).context("G2 y.c1")?,
    );
    let pt = G2Affine::new_unchecked(x, y);
    if !pt.is_on_curve() {
        return Err(anyhow!("G2 point not on BN254 curve"));
    }
    Ok(pt)
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Load and parse a proof bundle from a JSON file written by prove.js.
pub fn load_proof_bundle(path: &Path) -> Result<ProofBundle> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading proof from {:?}", path))?;
    serde_json::from_str(&raw).context("parsing proof bundle JSON")
}

/// Load and parse the Groth16 verification key from a JSON file.
///
/// The verification key is generated during `node zk/setup.js` and stored
/// at `~/.nothing/settlement/verification_key.json`.
pub fn load_verification_key(path: &Path) -> Result<VerifyingKey<Bn254>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading verification key from {:?}", path))?;
    let snark_vk: SnarkjsVk =
        serde_json::from_str(&raw).context("parsing verification key JSON")?;

    // Map each snarkjs field to the corresponding ark-groth16 field.
    // The conversion is purely syntactic: same mathematical objects,
    // different encoding (snarkjs decimal vs ark-groth16 field types).

    let alpha_g1 = parse_g1(&snark_vk.vk_alpha_1).context("vk alpha_g1")?;
    let beta_g2  = parse_g2(&snark_vk.vk_beta_2).context("vk beta_g2")?;
    let gamma_g2 = parse_g2(&snark_vk.vk_gamma_2).context("vk gamma_g2")?;
    let delta_g2 = parse_g2(&snark_vk.vk_delta_2).context("vk delta_g2")?;

    // IC: one G1 point per public signal, plus one for the constant term.
    let gamma_abc_g1: Result<Vec<G1Affine>> = snark_vk
        .ic
        .iter()
        .enumerate()
        .map(|(i, coords)| parse_g1(coords).with_context(|| format!("IC[{}]", i)))
        .collect();

    Ok(VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1: gamma_abc_g1?,
    })
}

/// Verify a Groth16 proof against a verification key.
///
/// Returns `true` if the proof is valid, `false` otherwise.
///
/// # How verification works
///
/// Groth16 verification is a pairing check on the BN254 curve.
/// The BN254 curve supports an efficient bilinear pairing
///   e: G1 × G2 → GT
/// where GT is a degree-12 extension field.
///
/// The check:
///   e(π_a, π_b) · e(-α, β) · e(-vk_x, γ) · e(-π_c, δ) == 1 in GT
///
/// This is equivalent to the longer form shown in the module doc comment.
/// ark-groth16 computes this using a multi-Miller loop for efficiency.
///
/// If this check passes, it is computationally infeasible for the prover
/// to have produced the proof without knowing a satisfying witness —
/// i.e., without knowing a (serial, signature) pair that satisfies the
/// NothingSettle circuit.
pub fn verify_groth16(vk: &VerifyingKey<Bn254>, bundle: &ProofBundle) -> Result<bool> {
    // ── Parse the proof π = (π_a, π_b, π_c) ─────────────────────────────────
    let pi_a = parse_g1(&bundle.proof.pi_a).context("proof pi_a")?;
    let pi_b = parse_g2(&bundle.proof.pi_b).context("proof pi_b")?;
    let pi_c = parse_g1(&bundle.proof.pi_c).context("proof pi_c")?;

    let ark_proof = Proof::<Bn254> {
        a: pi_a,
        b: pi_b,
        c: pi_c,
    };

    // ── Parse the public inputs as Fr elements ────────────────────────────────
    // public_signals is ordered as declared in the circuit:
    //   [modulus[0], modulus[1], …, modulus[31], serial_nullifier]
    // = 33 field elements total.
    //
    // ark-groth16's Groth16::verify expects these as &[Fr].
    let public_inputs: Result<Vec<Fr>> = bundle
        .public_signals
        .iter()
        .enumerate()
        .map(|(i, s)| parse_fr(s).with_context(|| format!("public_signal[{}]", i)))
        .collect();
    let public_inputs = public_inputs?;

    // ── Run the pairing check ─────────────────────────────────────────────────
    // Groth16::<Bn254>::verify computes the full pairing equation.
    // Returns Ok(true) if valid.
    let valid = Groth16::<Bn254>::verify(vk, &public_inputs, &ark_proof)
        .map_err(|e| anyhow!("ark-groth16 verify error: {:?}", e))?;

    Ok(valid)
}
