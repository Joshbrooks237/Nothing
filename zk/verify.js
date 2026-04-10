/**
 * verify.js — Verify a Nothing settlement proof (JavaScript side)
 *
 * WHAT THIS DOES
 * ──────────────
 * Loads a .proof.json file and a verification key, then checks whether
 * the Groth16 proof is valid.
 *
 * The Rust binary also verifies proofs via ark-groth16 — this JS script
 * is useful for debugging and for standalone verification without the
 * Rust binary.
 *
 * HOW GROTH16 VERIFICATION WORKS
 * ───────────────────────────────
 * Verification checks a pairing equation over the BN254 curve:
 *
 *   e(π_a, π_b) == e(α, β) · e(∑ᵢ xᵢ·γ_ABCᵢ, γ) · e(π_c, δ)
 *
 * where:
 *   - (α, β, γ, δ) are from the verification key
 *   - xᵢ are the public inputs (modulus limbs and nullifier)
 *   - e() is the BN254 pairing function
 *
 * This is constant time regardless of circuit size — verification is
 * always fast (milliseconds), even for circuits with millions of constraints.
 *
 * DOUBLE-SPEND PREVENTION
 * ────────────────────────
 * The verifier should also check that the nullifier (public_signals[-1])
 * has not been seen before.  This prevents the same token from being
 * settled twice.  In this implementation the Rust settlement module
 * maintains a nullifier registry in ~/.nothing/settled.json.
 *
 * USAGE
 * ─────
 *   node zk/verify.js <path/to/nullifier.proof.json>
 */

import snarkjs from 'snarkjs';
import { existsSync, readFileSync } from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const KEYS_DIR  = path.join(os.homedir(), '.nothing', 'settlement');
const VK_PATH   = path.join(KEYS_DIR, 'verification_key.json');

async function main() {
  const proofPath = process.argv[2];
  if (!proofPath) {
    console.error('Usage: node verify.js <path/to/nullifier.proof.json>');
    process.exit(1);
  }

  if (!existsSync(proofPath)) {
    console.error(`Proof file not found: ${proofPath}`);
    process.exit(1);
  }
  if (!existsSync(VK_PATH)) {
    console.error('Verification key not found.  Run:  node zk/setup.js');
    process.exit(1);
  }

  // Load the proof bundle
  const bundle = JSON.parse(readFileSync(proofPath, 'utf8'));
  const { proof, public_signals, meta } = bundle;

  // Load the verification key
  const vk = JSON.parse(readFileSync(VK_PATH, 'utf8'));

  console.log('');
  console.log('╔══════════════════════════════════════════╗');
  console.log('║   Nothing — Verifying Settlement Proof   ║');
  console.log('╚══════════════════════════════════════════╝');
  console.log('');
  console.log(`Proof:     ${proofPath}`);
  console.log(`Nullifier: ${meta?.nullifier ?? public_signals[public_signals.length - 1]}`);
  console.log('');

  // ── Verify the Groth16 proof ───────────────────────────────────────────────
  // snarkjs.groth16.verify:
  //   vk             — the verification key (from setup)
  //   public_signals — the public inputs (modulus limbs + nullifier)
  //   proof          — the proof (pi_a, pi_b, pi_c)
  // Returns: true if valid, false otherwise
  console.log('Running pairing check...');
  const valid = await snarkjs.groth16.verify(vk, public_signals, proof);

  if (valid) {
    console.log('');
    console.log('✓ PROOF VALID');
    console.log('');
    console.log('  The prover has demonstrated knowledge of:');
    console.log('    - A 32-byte serial number');
    console.log('    - A valid RSA blind signature over that serial');
    console.log('    - From the mint identified by the public modulus');
    console.log('');
    console.log('  Nothing has classified as a coin.');
    console.log('');
    // Exit 0 for the Rust caller
    process.exit(0);
  } else {
    console.log('');
    console.log('✗ PROOF INVALID');
    console.log('');
    console.log('  The proof did not pass verification.');
    console.log('  Possible reasons:');
    console.log('    - The circuit or setup was changed after the proof was generated.');
    console.log('    - The proof file was tampered with.');
    console.log('    - The token was not issued by the mint with the claimed modulus.');
    console.log('');
    process.exit(1);
  }
}

main().catch(err => {
  console.error('Verification failed:', err);
  process.exit(1);
});
