/**
 * prove.js — Generate a Groth16 settlement proof for a Nothing token
 *
 * WHAT THIS DOES
 * ──────────────
 * Takes a .nothing token file (or a circuit input JSON), runs the
 * witness generator to compute the intermediate signals, then runs
 * the Groth16 prover to produce a proof.
 *
 * The output is a .proof.json file containing:
 *   - proof:         the actual Groth16 proof (pi_a, pi_b, pi_c)
 *   - public_inputs: the public inputs (modulus, nullifier)
 *
 * HOW GROTH16 PROVING WORKS
 * ─────────────────────────
 * 1. Witness generation:
 *    The witness is ALL signal values in the circuit — both the
 *    private inputs (serial, signature) and every intermediate
 *    computed signal.  The WASM witness generator computes this
 *    from the circuit inputs.
 *
 * 2. Proof computation:
 *    Given the witness and the proving key (.zkey), snarkjs produces
 *    a constant-size Groth16 proof: three elliptic curve points
 *    (pi_a in G1, pi_b in G2, pi_c in G1) on the BN254 curve.
 *
 *    The proof is 192 bytes regardless of the circuit size.
 *
 * 3. The proof can be verified by anyone with:
 *    - The verification key (small, public)
 *    - The public inputs (modulus, nullifier)
 *    - The proof itself
 *
 * USAGE
 * ─────
 *   node zk/prove.js ~/.nothing/tokens/<token.nothing>
 *   # produces ~/.nothing/tokens/<token.nullifier>.proof.json
 */

import snarkjs from 'snarkjs';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';
import { generateInputs } from './input_gen.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CIRCUIT_BUILD = path.join(__dirname, '..', 'circuits', 'build');
const KEYS_DIR      = path.join(os.homedir(), '.nothing', 'settlement');

// ── Paths to compiled circuit and keys ───────────────────────────────────────
const WASM_PATH  = path.join(CIRCUIT_BUILD, 'nothing_settle_js', 'nothing_settle.wasm');
const ZKEY_PATH  = path.join(KEYS_DIR, 'nothing_settle_final.zkey');

async function main() {
  const tokenPath = process.argv[2];
  if (!tokenPath) {
    console.error('Usage: node prove.js <path/to/token.nothing>');
    process.exit(1);
  }

  // ── Sanity checks ──────────────────────────────────────────────────────────
  if (!existsSync(WASM_PATH)) {
    console.error('ERROR: Circuit not compiled.  Run:  bash zk/compile.sh');
    process.exit(1);
  }
  if (!existsSync(ZKEY_PATH)) {
    console.error('ERROR: Proving key not found.  Run:  node zk/setup.js');
    process.exit(1);
  }

  console.log('');
  console.log('╔══════════════════════════════════════════╗');
  console.log('║   Nothing — Generating Settlement Proof  ║');
  console.log('╚══════════════════════════════════════════╝');
  console.log('');
  console.log(`Token: ${tokenPath}`);
  console.log('');

  // ── Step 1: Generate circuit inputs from token file ───────────────────────
  console.log('── Step 1: Preparing circuit inputs ──');
  const { inputs, meta } = await generateInputs(tokenPath);
  console.log(`  Serial:    0x${meta.serial_hex}`);
  console.log(`  Nullifier: 0x${meta.nullifier_hex}`);

  // ── Step 2: Compute the witness ───────────────────────────────────────────
  // The witness is the assignment of values to ALL signals in the circuit,
  // including internal signals like the SHA256 intermediate values.
  // The WASM file (compiled from the circuit) computes this automatically.
  console.log('');
  console.log('── Step 2: Computing witness ──');
  console.log('  (This evaluates all ~210,000 constraints with your private inputs.)');
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    inputs,
    WASM_PATH,
    ZKEY_PATH
  );

  // ── Step 3: Save the proof ────────────────────────────────────────────────
  // The proof bundle contains the proof itself and the public inputs.
  // Anyone can verify this with the verification key.
  const proofBundle = {
    proof,
    public_signals: publicSignals,
    meta: {
      nullifier: '0x' + meta.nullifier_hex,
      token_path: meta.token_path,
      circuit: 'NothingSettle(64,32)',
      scheme: 'groth16',
      curve: 'bn254',
    },
  };

  // Derive proof output path from the nullifier
  const proofDir  = path.join(os.homedir(), '.nothing', 'proofs');
  mkdirSync(proofDir, { recursive: true });
  const proofPath = path.join(proofDir, `${meta.nullifier_hex}.proof.json`);
  writeFileSync(proofPath, JSON.stringify(proofBundle, null, 2));

  console.log('');
  console.log('── Step 3: Proof generated ──');
  console.log(`  Proof saved: ${proofPath}`);
  console.log('');
  console.log('  Proof components:');
  console.log(`    π_a = [${proof.pi_a.slice(0,2).map(x => x.substring(0,12) + '…').join(', ')}]`);
  console.log(`    π_b = [[${proof.pi_b[0].map(x => x.substring(0,8) + '…').join(', ')}], …]`);
  console.log(`    π_c = [${proof.pi_c.slice(0,2).map(x => x.substring(0,12) + '…').join(', ')}]`);
  console.log('');
  console.log('  The proof is 192 bytes.  It reveals nothing about the serial or');
  console.log('  signature — only that you know them and that they are valid.');
  console.log('');
  console.log('  Public signals (visible to verifier):');
  console.log(`    modulus limbs: [${publicSignals.slice(0,2).map(x => x.substring(0,10) + '…').join(', ')}…]`);
  console.log(`    nullifier:     ${publicSignals[publicSignals.length - 1]}`);
  console.log('');

  // Output the proof path for the Rust caller to consume
  process.stdout.write(`PROOF_PATH=${proofPath}\n`);
}

main().catch(err => {
  console.error('Proof generation failed:', err);
  process.exit(1);
});
