pragma circom 2.1.5;

// ── External libraries ────────────────────────────────────────────────────────
//
// circomlib: battle-tested ZK utility templates maintained by iden3.
//   Poseidon — a ZK-friendly hash function (cheap in R1CS constraints).
//   Num2Bits — decomposes a field element into an array of bits.
//   Bits2Num — packs an array of bits back into a single field element.
//   Sha256   — implements the SHA-256 hash standard inside a circuit.
//
// @zk-email/circuits: open-source RSA bigint verification circuits.
//   RSAVerify65537 — proves sig^65537 ≡ msg (mod n) for 2048-bit RSA.
//   The "65537" means the public exponent e = 65537 = 2^16 + 1 (standard).
//
// Both libraries are resolved from node_modules at compile time.
// Compile with: circom nothing_settle.circom -l ../zk/node_modules ...

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/sha256/sha256.circom";
include "circomlib/circuits/bitify.circom";
include "@zk-email/circuits/lib/rsa.circom";

// ─────────────────────────────────────────────────────────────────────────────
//
//  NothingSettle(n, k)
//
//  The settlement circuit for Nothing — the cryptographic event that
//  classifies the bearer instrument as a coin upon successful arrival.
//
//  WHAT THIS CIRCUIT PROVES
//  ─────────────────────────
//  The holder knows a (serial, signature) pair such that:
//
//    1. RSA blind signature is valid:
//         signature^65537 mod modulus
//           == SHA256("nothing-v1|serial|" ‖ serial)
//
//    2. The serial hashes to the committed nullifier:
//         Poseidon(pack_lo(serial[0..15]), pack_hi(serial[16..31]))
//           == serial_nullifier
//
//  WHY THIS MATTERS
//  ─────────────────
//  The proof is zero-knowledge: the verifier learns nothing about
//  serial or signature.  They only learn:
//    - Which mint issued the token (via the public modulus).
//    - The nullifier — a unique fingerprint of the serial that enables
//      double-spend detection without revealing the serial itself.
//
//  BIGINT REPRESENTATION
//  ──────────────────────
//  RSA-2048 numbers (2048 bits) cannot fit in a single BN254 field element
//  (~254 bits).  We represent them as k=32 "limbs" of n=64 bits each:
//
//    value = limb[0] * 2^0
//          + limb[1] * 2^64
//          + limb[2] * 2^128
//          + ...
//          + limb[31] * 2^(31*64)
//
//  limb[0] is the LEAST significant 64-bit chunk (little-endian by limb).
//  The @zk-email/circuits RSAVerify65537 template uses the same convention.
//
//  PARAMETERS
//  ───────────
//  n = 64   bits per limb
//  k = 32   limbs  (so n*k = 2048 bits — matches our RSA key size)
//
// ─────────────────────────────────────────────────────────────────────────────

template NothingSettle(n, k) {

    // ── PRIVATE inputs (never revealed to the verifier) ───────────────────────

    // The 32-byte random serial number, one byte per field element.
    // These are integers in [0, 255].
    signal input serial[32];

    // The RSA blind signature, represented as k=32 limbs of n=64 bits each.
    // This is the output of Phase 1 minting: the unblinded RSA signature
    // sig = (blinded_sig * r_inverse) mod n, where r was the blinding factor.
    signal input signature[k];

    // ── PUBLIC inputs (visible to the verifier) ────────────────────────────────

    // The mint's RSA public key modulus, same bigint limb format.
    // Identifying the modulus identifies the issuing mint.
    signal input modulus[k];

    // The nullifier: Poseidon(pack_lo, pack_hi) where pack_lo and pack_hi
    // are the serial packed into two 128-bit field elements.
    //
    // Purpose: the verifier records this nullifier to prevent double-spend.
    // Two proofs with the same nullifier came from the same serial.
    // But the nullifier reveals nothing about the actual serial value.
    signal input serial_nullifier;


    // ── STEP 1: Range-check each serial byte ──────────────────────────────────
    //
    // Each serial[i] must be in [0, 255].  Num2Bits(8) enforces this:
    // it decomposes the input into 8 bits, which only succeeds if the
    // value fits in 8 bits (i.e., is in [0, 255]).
    //
    // Num2Bits(8).out[j] gives bit j, with j=0 being the LEAST significant bit.

    component byte_bits[32];
    for (var i = 0; i < 32; i++) {
        byte_bits[i] = Num2Bits(8);
        byte_bits[i].in <== serial[i];
    }


    // ── STEP 2: Build the SHA256 message ──────────────────────────────────────
    //
    // Message = "nothing-v1|serial|" (18 bytes, constant) ‖ serial (32 bytes)
    // Total  = 50 bytes = 400 bits.
    //
    // SHA256 processes bits in big-endian order: the first bit (index 0) is
    // the MSB of the first byte.  So for byte value v, bit b of that byte is:
    //   bit = (v >> (7 - b)) & 1      (b=0 → MSB, b=7 → LSB)
    //
    // ASCII codes for "nothing-v1|serial|":
    //   n=110 o=111 t=116 h=104 i=105 n=110 g=103 -=45
    //   v=118 1=49  |=124 s=115 e=101 r=114 i=105 a=97 l=108 |=124

    var PREFIX_LEN = 18;
    var SERIAL_LEN = 32;
    var MSG_BITS   = (PREFIX_LEN + SERIAL_LEN) * 8;  // = 400

    var PREFIX[18] = [110, 111, 116, 104, 105, 110, 103,  45,
                      118,  49, 124, 115, 101, 114, 105,  97,
                      108, 124];

    component sha = Sha256(MSG_BITS);

    // Assign prefix bits as compile-time constants.
    // These create constraints of the form: sha.in[i] === 0 or 1.
    for (var i = 0; i < PREFIX_LEN; i++) {
        for (var b = 0; b < 8; b++) {
            sha.in[i * 8 + b] <== (PREFIX[i] >> (7 - b)) & 1;
        }
    }

    // Assign serial bits from the private witness.
    // byte_bits[i].out[j] is bit j (LSB-first), so bit b in MSB-first order
    // is byte_bits[i].out[7 - b].
    for (var i = 0; i < SERIAL_LEN; i++) {
        for (var b = 0; b < 8; b++) {
            sha.in[PREFIX_LEN * 8 + i * 8 + b] <== byte_bits[i].out[7 - b];
        }
    }

    // sha.out[0..255] are the 256 SHA256 output bits, MSB-first.
    // sha.out[0] is the MSB of the first output byte.


    // ── STEP 3: Pack SHA256 output into RSA bigint format ─────────────────────
    //
    // The RSA bigint representation needs k=32 limbs of n=64 bits.
    // SHA256 produces 256 bits; these occupy the FIRST 4 limbs (least significant).
    // The remaining 28 limbs are 0.
    //
    // To pack 256 bits into 4 little-endian 64-bit limbs:
    //
    //   limb[0] = SHA256 bits 192..255  (the least significant 64 bits)
    //   limb[1] = SHA256 bits 128..191
    //   limb[2] = SHA256 bits  64..127
    //   limb[3] = SHA256 bits   0.. 63  (the most significant 64 bits)
    //
    // sha.out is MSB-first, so sha.out[0] is the highest bit of limb[3].
    //
    // Bits2Num(64).out = in[0]*2^0 + in[1]*2^1 + ... + in[63]*2^63
    // So for limb i: we want in[b] = sha.out[ 64*(3-i) + (63-b) ]
    //   (the MSB of each limb group becomes in[63], LSB becomes in[0])

    signal msg_hash[k];

    component sha_limb[4];
    for (var i = 0; i < 4; i++) {
        sha_limb[i] = Bits2Num(64);
        for (var b = 0; b < 64; b++) {
            sha_limb[i].in[b] <== sha.out[ 64 * (3 - i) + (63 - b) ];
        }
        msg_hash[i] <== sha_limb[i].out;
    }

    // Upper 28 limbs are 0 (SHA256 output is 256 bits < 2048-bit modulus).
    for (var i = 4; i < k; i++) {
        msg_hash[i] <== 0;
    }


    // ── STEP 4: Verify the RSA blind signature ────────────────────────────────
    //
    // This is the core of the settlement proof.
    //
    // RSAVerify65537(n, k) checks:
    //   signature^65537 mod modulus === base_message
    //
    // How sig^65537 is computed efficiently inside the circuit:
    //   65537 = 2^16 + 1
    //   sig^65537 = sig^(2^16) * sig  (mod n)
    //   sig^(2^16) = (((...(sig^2)^2)...)^2)  ← 16 squarings
    //
    // Each squaring is a BigMultModP operation: multiply two 2048-bit numbers
    // mod n, represented as 32 64-bit limbs.  The @zk-email library implements
    // this using the "hint-and-verify" pattern:
    //   - The prover computes q and r such that a*b = q*n + r  (off-circuit)
    //   - The circuit verifies: a*b - q*n = r  AND  r < n
    //   - This requires ~300,000 R1CS constraints for 2048-bit RSA.
    //
    // See circuits/BIGINT.md for a detailed walkthrough of the arithmetic.

    component rsa = RSAVerify65537(n, k);
    for (var i = 0; i < k; i++) {
        rsa.signature[i]    <== signature[i];
        rsa.modulus[i]      <== modulus[i];
        rsa.base_message[i] <== msg_hash[i];
    }


    // ── STEP 5: Compute and verify the serial nullifier ───────────────────────
    //
    // WHY A NULLIFIER?
    // The settlement system needs to track which tokens have been settled
    // to prevent double-spending.  We can't store the serial itself (that
    // would break privacy).  Instead we store a hash — the nullifier.
    //
    // WHY POSEIDON?
    // SHA256 would work, but it costs ~28,000 constraints per call in R1CS.
    // Poseidon is a ZK-native hash function designed to be cheap in circuits:
    // a Poseidon(2) call costs only ~300 constraints.  Same security level.
    //
    // HOW WE PACK 32 BYTES INTO 2 FIELD ELEMENTS
    // A BN254 field element holds ~254 bits.  16 bytes = 128 bits fits easily.
    // We pack serial[0..15] into packed_lo and serial[16..31] into packed_hi.
    //
    //   packed = serial[0] * 256^15 + serial[1] * 256^14 + ... + serial[15]
    //          = serial[0] * 2^120  + serial[1] * 2^112  + ... + serial[15]
    //
    // The accumulated multiplication is done step by step with constraints.

    // Accumulate serial[0..15] into packed_lo
    signal acc_lo[17];
    acc_lo[0] <== 0;
    for (var i = 0; i < 16; i++) {
        acc_lo[i + 1] <== acc_lo[i] * 256 + serial[i];
    }
    signal packed_lo <== acc_lo[16];

    // Accumulate serial[16..31] into packed_hi
    signal acc_hi[17];
    acc_hi[0] <== 0;
    for (var i = 0; i < 16; i++) {
        acc_hi[i + 1] <== acc_hi[i] * 256 + serial[i + 16];
    }
    signal packed_hi <== acc_hi[16];

    // Compute Poseidon(packed_lo, packed_hi)
    // Poseidon(2) takes 2 field elements and outputs 1.
    // The output is deterministic and ZK-friendly.
    component pos = Poseidon(2);
    pos.inputs[0] <== packed_lo;
    pos.inputs[1] <== packed_hi;

    // Constrain the nullifier to match the computed Poseidon hash.
    // If the prover provides a wrong serial, pos.out ≠ serial_nullifier
    // and the constraint fails — the proof would be invalid.
    pos.out === serial_nullifier;
}

// ─────────────────────────────────────────────────────────────────────────────
//
//  Main component declaration
//
//  {public [...]} lists the signals that are PUBLIC inputs.
//  Everything else is PRIVATE (zero-knowledge).
//
//  Public:  modulus (identifies the mint), serial_nullifier (for double-spend)
//  Private: serial (the secret), signature (the blind sig)
//
//  Instantiated with n=64, k=32 → 2048-bit RSA.
//
// ─────────────────────────────────────────────────────────────────────────────

component main {public [modulus, serial_nullifier]} = NothingSettle(64, 32);
