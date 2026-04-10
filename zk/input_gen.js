/**
 * input_gen.js — Convert a .nothing token file into circuit inputs
 *
 * WHAT THIS DOES
 * ──────────────
 * Reads a .nothing token file and produces the JSON input object that the
 * circuit's witness generator needs.
 *
 * The circuit has:
 *   Private: serial[32]     — 32 bytes, one per field element
 *            signature[32]  — 2048-bit RSA sig as 32 × 64-bit limbs
 *   Public:  modulus[32]    — 2048-bit RSA modulus as 32 × 64-bit limbs
 *            serial_nullifier — Poseidon(packed_lo, packed_hi)
 *
 * BIGINT LIMB FORMAT
 * ──────────────────
 * @zk-email/circuits uses little-endian limbs: limb[0] is the LEAST
 * significant 64-bit chunk.  So for a hex string "AABB...":
 *
 *   BigInt('0x' + hex) → split into 32 chunks of 64 bits, LSB first
 *
 * THE SHA256 / MODULAR ARITHMETIC NOTE
 * ─────────────────────────────────────
 * The Phase 1 blind signature scheme signs:
 *   SHA256("nothing-v1|serial|" ‖ serial) mod n
 *
 * Since SHA256 output is 256 bits and n is 2048 bits, the SHA256 value is
 * always smaller than n, so the "mod n" reduction is a no-op.  The circuit
 * treats the SHA256 hash directly as the RSA message.
 *
 * The circuit independently computes the SHA256 of the private serial and
 * checks it matches what sig^65537 mod n decrypts to.
 *
 * USAGE
 * ─────
 *   node zk/input_gen.js ~/.nothing/tokens/<token.nothing>
 *   # or import as a module:
 *   import { generateInputs } from './input_gen.js';
 */

import { readFileSync, writeFileSync } from 'fs';
import { createHash } from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import { buildPoseidon } from 'circomlibjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── Utility: convert a hex string to an array of k 64-bit BigInt limbs ───────
// little-endian: limb[0] is least significant
function hexToLimbs(hex, k = 32) {
  // Remove 0x prefix if present
  hex = hex.replace(/^0x/, '');
  const value = BigInt('0x' + hex);
  const limbs = [];
  const mask = (1n << 64n) - 1n;
  for (let i = 0; i < k; i++) {
    limbs.push(((value >> (64n * BigInt(i))) & mask).toString());
  }
  return limbs;
}

// ── Utility: convert a Buffer to an array of BigInt limbs (little-endian) ───
function bufferToLimbs(buf, k = 32) {
  return hexToLimbs(buf.toString('hex'), k);
}

// ── Compute SHA256("nothing-v1|serial|" ‖ serial_bytes) ─────────────────────
function computeSerialHash(serialBytes) {
  const prefix = Buffer.from('nothing-v1|serial|', 'utf8');
  const msg    = Buffer.concat([prefix, serialBytes]);
  return createHash('sha256').update(msg).digest();
}

// ── Pack 16 bytes into a BigInt (big-endian) ─────────────────────────────────
function pack16Bytes(bytes) {
  let val = 0n;
  for (let i = 0; i < 16; i++) {
    val = (val << 8n) | BigInt(bytes[i]);
  }
  return val;
}

// ── Main: generate the circuit inputs from a token file ──────────────────────
export async function generateInputs(tokenPath) {
  // Load the token
  const raw   = readFileSync(tokenPath, 'utf8');
  const token = JSON.parse(raw);

  // ── Decode serial ──────────────────────────────────────────────────────────
  // serial_hex is the 32-byte serial number stored as hex in the token file.
  const serialHex   = token.serial_hex;
  const serialBytes = Buffer.from(serialHex, 'hex');
  if (serialBytes.length !== 32) {
    throw new Error(`Expected 32-byte serial, got ${serialBytes.length}`);
  }

  // Serial as array of 32 field elements (one byte each, value 0-255)
  const serialArr = Array.from(serialBytes).map(b => b.toString());

  // ── Decode RSA signature ───────────────────────────────────────────────────
  // blind_signature_hex is the unblinded RSA signature.
  // It's a 256-byte (2048-bit) big integer stored as hex.
  const sigHex   = token.blind_signature_hex;
  const sigLimbs = hexToLimbs(sigHex, 32);

  // ── Decode RSA modulus ─────────────────────────────────────────────────────
  // mint_pubkey.n_hex is the mint's RSA public key modulus.
  const modHex   = token.mint_pubkey.n_hex;
  const modLimbs = hexToLimbs(modHex, 32);

  // ── Compute nullifier: Poseidon(packed_lo, packed_hi) ────────────────────
  // We use circomlibjs to compute the same Poseidon hash as the circuit.
  // This must match EXACTLY — same BN254 field, same Poseidon parameters.
  const poseidon   = await buildPoseidon();
  const packed_lo  = pack16Bytes(serialBytes.slice(0, 16));
  const packed_hi  = pack16Bytes(serialBytes.slice(16, 32));
  // poseidon expects BigInts or Buffers; returns a BigInt
  const nullifier  = poseidon.F.toString(poseidon([packed_lo, packed_hi]));

  // ── Assemble the circuit input object ────────────────────────────────────
  const inputs = {
    // Private inputs
    serial:    serialArr,
    signature: sigLimbs,
    // Public inputs
    modulus:   modLimbs,
    serial_nullifier: nullifier,
  };

  return {
    inputs,
    meta: {
      token_path:     tokenPath,
      serial_hex:     serialHex,
      nullifier_hex:  BigInt(nullifier).toString(16).padStart(64, '0'),
    },
  };
}

// ── CLI usage ─────────────────────────────────────────────────────────────────
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const tokenPath = process.argv[2];
  if (!tokenPath) {
    console.error('Usage: node input_gen.js <path/to/token.nothing>');
    process.exit(1);
  }

  generateInputs(tokenPath).then(({ inputs, meta }) => {
    const outPath = tokenPath.replace(/\.nothing$/, '.circuit_input.json');
    writeFileSync(outPath, JSON.stringify(inputs, null, 2));
    console.log(`Circuit inputs written to: ${outPath}`);
    console.log(`Nullifier: 0x${meta.nullifier_hex}`);
  }).catch(err => {
    console.error('Error:', err.message);
    process.exit(1);
  });
}
