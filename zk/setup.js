/**
 * setup.js — Groth16 trusted setup for the Nothing settlement circuit
 *
 * WHAT THIS DOES
 * ──────────────
 * A Groth16 proof requires a one-time "trusted setup" that produces:
 *   - A proving key  (used by the prover to generate proofs)
 *   - A verification key  (used by the verifier to check proofs)
 *
 * The setup is specific to this circuit.  If the circuit changes,
 * you must redo the setup.
 *
 * POWERS OF TAU ("PTAU")
 * ──────────────────────
 * The first phase of the setup is the "Powers of Tau" ceremony.
 * It establishes cryptographic parameters that are independent of the
 * specific circuit.  In a real deployment, you'd use a multi-party
 * computation ceremony so no single party knows the toxic waste ("tau").
 *
 * Here we use a pre-generated ptau file from the Hermez ceremony (trusted,
 * widely used in production).  We download it if not already present.
 *
 * The number "18" in hermez_final_18.ptau means it supports up to
 * 2^18 = 262,144 constraints.  Our circuit has ~210,000 — this fits.
 *
 * RUNNING
 * ───────
 *   node zk/setup.js
 *
 * Outputs into ~/.nothing/settlement/:
 *   nothing_settle_final.zkey   — proving key
 *   verification_key.json       — verification key (used by Rust verifier)
 */

import snarkjs from 'snarkjs';
import { readFileSync, mkdirSync, existsSync } from 'fs';
import { createWriteStream } from 'fs';
import { get as httpsGet } from 'https';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CIRCUIT_BUILD = path.join(__dirname, '..', 'circuits', 'build');
const KEYS_DIR = path.join(os.homedir(), '.nothing', 'settlement');

// Hermez powers-of-tau ceremony — 2^18 constraints max.
// Source: https://hermez.s3-eu-west-1.amazonaws.com/
const PTAU_URL = 'https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_18.ptau';
const PTAU_PATH = path.join(KEYS_DIR, 'pot18_final.ptau');

// ─────────────────────────────────────────────────────────────────────────────

async function downloadFile(url, destPath) {
  return new Promise((resolve, reject) => {
    console.log(`  Downloading ${url}`);
    console.log(`  → ${destPath}`);
    const file = createWriteStream(destPath);
    httpsGet(url, (res) => {
      if (res.statusCode === 302 || res.statusCode === 301) {
        // Follow redirect
        httpsGet(res.headers.location, (res2) => {
          const total = parseInt(res2.headers['content-length'] || '0', 10);
          let downloaded = 0;
          res2.on('data', (chunk) => {
            downloaded += chunk.length;
            if (total > 0) {
              process.stdout.write(`\r  Progress: ${Math.round(downloaded / total * 100)}%`);
            }
          });
          res2.pipe(file);
          res2.on('end', () => { process.stdout.write('\n'); resolve(); });
          res2.on('error', reject);
        }).on('error', reject);
      } else {
        const total = parseInt(res.headers['content-length'] || '0', 10);
        let downloaded = 0;
        res.on('data', (chunk) => {
          downloaded += chunk.length;
          if (total > 0) {
            process.stdout.write(`\r  Progress: ${Math.round(downloaded / total * 100)}%`);
          }
        });
        res.pipe(file);
        res.on('end', () => { process.stdout.write('\n'); resolve(); });
        res.on('error', reject);
      }
    }).on('error', reject);
    file.on('error', reject);
  });
}

async function main() {
  console.log('');
  console.log('╔═══════════════════════════════════════════╗');
  console.log('║   Nothing — ZK Settlement Setup (Phase 2) ║');
  console.log('╚═══════════════════════════════════════════╝');
  console.log('');

  // ── Check that the circuit was compiled ──────────────────────────────────
  const r1csPath = path.join(CIRCUIT_BUILD, 'nothing_settle.r1cs');
  if (!existsSync(r1csPath)) {
    console.error('ERROR: Circuit not compiled yet.');
    console.error('Run:  bash zk/compile.sh');
    process.exit(1);
  }

  mkdirSync(KEYS_DIR, { recursive: true });

  // ── Step 1: Powers of Tau ─────────────────────────────────────────────────
  console.log('── Step 1: Powers of Tau ceremony ──');
  if (existsSync(PTAU_PATH)) {
    console.log('  Found existing ptau file, skipping download.');
  } else {
    console.log('  Downloading Hermez ptau file (~300 MB)...');
    await downloadFile(PTAU_URL, PTAU_PATH);
  }

  // ── Step 2: Circuit-specific setup (Groth16 phase 2) ─────────────────────
  console.log('');
  console.log('── Step 2: Groth16 circuit-specific setup ──');
  console.log('  This generates a proving key and verification key for the circuit.');
  console.log('  It uses the ptau file as the source of randomness.');

  const zkey0Path = path.join(KEYS_DIR, 'nothing_settle_0000.zkey');
  const zkeyFinal = path.join(KEYS_DIR, 'nothing_settle_final.zkey');
  const vkPath    = path.join(KEYS_DIR, 'verification_key.json');

  console.log('  Generating initial proving key...');
  // groth16.setup creates the initial zkey from the r1cs and ptau.
  await snarkjs.zKey.newZKey(r1csPath, PTAU_PATH, zkey0Path);

  // In production: multiple parties would each contribute randomness here,
  // using snarkjs.zKey.contribute(...).  For dev, we contribute once with
  // a hardcoded entropy string.  The security of the proof depends on at
  // least ONE contributor keeping their randomness secret.
  console.log('  Contributing randomness (dev mode — single contributor)...');
  await snarkjs.zKey.contribute(
    zkey0Path,
    zkeyFinal,
    'Nothing dev setup',
    'nothing-dev-entropy-replace-in-production'
  );

  // ── Step 3: Export the verification key ──────────────────────────────────
  console.log('');
  console.log('── Step 3: Exporting verification key ──');
  console.log(`  → ${vkPath}`);
  const vk = await snarkjs.zKey.exportVerificationKey(zkeyFinal);
  const { writeFileSync } = await import('fs');
  writeFileSync(vkPath, JSON.stringify(vk, null, 2));

  console.log('');
  console.log('✓ Setup complete!');
  console.log('');
  console.log(`  Proving key:      ${zkeyFinal}`);
  console.log(`  Verification key: ${vkPath}`);
  console.log('');
  console.log('Next step: run  nothing settle <token.nothing>');
  console.log('');
}

main().catch(err => {
  console.error('Setup failed:', err);
  process.exit(1);
});
