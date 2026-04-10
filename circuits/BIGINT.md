# BigInt RSA Arithmetic in ZK Circuits — How It Works

This document explains how `@zk-email/circuits` verifies a 2048-bit RSA
signature inside a Groth16 proof, for anyone learning as they build.

---

## The Problem: Big Numbers in Small Fields

A Groth16 proof operates over the BN254 elliptic curve.  Every computation
happens inside the BN254 **scalar field** — a prime field with elements up to
roughly 2^254.

RSA-2048 uses numbers up to 2^2048.  That's about 2^1794 times larger than
what the field can hold.  We need a way to do 2048-bit arithmetic inside a
254-bit field.

---

## The Solution: Limb Representation

Break the 2048-bit number into 32 chunks ("limbs") of 64 bits each:

```
value = limb[0]·2⁰    +  limb[1]·2⁶⁴  +  limb[2]·2¹²⁸  + … +  limb[31]·2^(31·64)
```

Each `limb[i]` is a 64-bit integer, comfortably smaller than 2^254.  
`limb[0]` is the **least significant** chunk (little-endian by limb).

For a 256-bit SHA256 hash used as the RSA message, only the first 4 limbs are
non-zero; limbs 4–31 are 0.

---

## BigMult: Multiplying Two Big Integers

To multiply `a[k] × b[k]` (schoolbook method):

```
product[s] = Σ  a[i] · b[j]   for all i, j where  i + j = s
```

Each `a[i] · b[j]` is one R1CS constraint (a single multiplication gate).  
For k=32 that's 32²= **1024 multiplication gates**.

The raw sum at each position can overflow 64 bits, so we propagate carries:

```
total[s]    = raw_sum[s] + carry[s]
out[s]      = total[s] mod 2^64      ← low 64 bits
carry[s+1]  = total[s] / 2^64        ← high bits
```

The carry decomposition is enforced by `Num2Bits` constraints.

---

## BigMultModP: Modular Multiplication

We want `(a · b) mod p`.  The circuit can't perform general division, so the
prover **hints** the quotient and remainder:

```
q, r  such that  a · b = q · p + r   and   0 ≤ r < p
```

The circuit then **verifies** this claim with three checks:

1. **Equality**: `a·b == q·p + r`  (computed with BigMult on both sides)  
2. **Range**: `r < p`  (using a BigLessThan comparator on limbs)  
3. **Validity**: range checks ensure no limb overflows

If an adversarial prover tries to fake `q` or `r`, check 1 or 2 will fail.

---

## FpPow65537Mod: Fast Exponentiation

The RSA public exponent e = 65537 = 2^16 + 1.  This lets us compute
`sig^65537 mod n` with only **17 multiplications**:

```
t₀  = sig
t₁  = t₀² mod n       (square)
t₂  = t₁² mod n       (square)
…
t₁₆ = t₁₅² mod n      (16th square = sig^(2^16))
out = t₁₆ · sig mod n  (one extra multiply: sig^(2^16) · sig^1 = sig^65537)
```

Each of the 17 steps is one BigMultModP call.

---

## RSAVerify65537: Putting It Together

```
sig^65537 mod n  ==  msg_hash
```

The circuit computes the left side via FpPow65537Mod and then asserts
limb-by-limb equality with `msg_hash`.

---

## Constraint Count (approximate)

| Component           | Constraints      |
|---------------------|------------------|
| SHA256(400 bits)    | ~28,000          |
| BigMult per call    | ~10,000          |
| 17× FpPow squarings | ~170,000         |
| Poseidon(2)         | ~300             |
| Byte range checks   | ~300             |
| **Total**           | **~210,000**     |

This fits within a 2^18 powers-of-tau ceremony (262,144 constraints max).

---

## Further Reading

- [Groth16 paper](https://eprint.iacr.org/2016/260.pdf)
- [Poseidon hash paper](https://eprint.iacr.org/2019/458.pdf)
- [@zk-email/circuits source](https://github.com/zkemail/zk-email-verify)
- [circomlib source](https://github.com/iden3/circomlib)
