# Nothing

> *"Say what you will about the tenets of cryptography, Dude — at least it's an ethos."*

---

Look, man. I've been bowling since 1987. Tuesdays, Thursdays, and the occasional Sunday when my knees cooperate. I've thrown strikes. I've thrown gutter balls. I once threw a perfect game and felt nothing. Absolutely nothing. And somewhere in that void — between the release and the pins — I understood something important about the nature of value.

**Nothing is that thing.**

---

## What is Nothing?

Nothing is a peer-to-peer cryptographic bearer instrument.

It has no ticker. No ledger. No exchange listing. No central server. No registration. No database anyone can query. No identity during transit.

It does not classify as a coin until the moment of successful settlement — at which point it has already arrived.

You can't stop it. You can't track it. You can't regulate what you can't name. And you can't name what has no identity.

*That's not a bug. That's the whole point, man.*

---

## The Philosophy

The nihilists — and I've bowled against nihilists, they cheat — they say nothing matters. They're wrong. Nothing *is* the matter. There's a difference.

When a token moves between peers it is **nothing**. It's encrypted bytes. Random noise. It could be anything or it could be literally nothing. The wire doesn't know. The nodes don't know. The network doesn't know.

Then it lands.

Then it verifies.

**Then** — and only then — it becomes something. The blind signature resolves. The sealed box opens. The zero-knowledge proof settles. The coin arrives having never existed in transit.

You weren't robbed. You weren't surveilled. You weren't even there, man.

---

## How It Works

### The Cryptographic Stack

```
Ed25519 (identity)        — dryoc, pure Rust libsodium implementation
X25519 + XSalsa20-Poly1305 — sealed-box: only the recipient can read it
RSA Blind Signatures       — Chaum (1983): the mint signs without seeing the serial
libp2p (TCP + Noise + Yamux) — mesh transport, Noise XX handshake, double encryption
snarkjs / circom (Phase 2) — zero-knowledge settlement proofs
```

### The Blind Signature (how the mint can't trace its own tokens)

```
1.  Alice generates a random 32-byte serial   s
2.  Alice computes:  m = SHA256("nothing-v1|serial|" || s)  mod n
3.  Alice picks random r.  Blinded:  m' = m · r^e  mod n
4.  Alice sends m' to the Mint.  Mint sees noise.
5.  Mint signs:  σ' = (m')^d  mod n
6.  Alice unblinds:  σ = σ' · r⁻¹  mod n  =  m^d  mod n
7.  σ is a valid RSA signature on m that the Mint cannot link to step 4.
8.  Token = (s, σ, Mint.pubkey)
9.  Verify:  σ^e  mod n  ==  SHA256("nothing-v1|serial|" || s)  ✓
```

The Mint signed a random-looking number. It has no record of what `s` was. The receipt cannot be traced back to the issuance. That's the whole game.

### In Transit

The token rides inside:
1. **Sealed-box encryption** — addressed to the recipient's X25519 public key. Random noise to everyone else.
2. **Noise protocol transport** — every TCP connection is Noise XX authenticated. Random noise at the wire level too.

Two layers of "what is this." Neither layer has a name on it.

---

## Project Structure

```
Nothing/
├── nothing-core/          Rust — all the cryptography and networking
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs              CLI (keygen / mint / listen / send / wallet)
│       ├── crypto/
│       │   ├── keypair.rs       Ed25519 + X25519 key generation
│       │   ├── blind_sig.rs     RSA blind signature scheme, fully commented
│       │   └── token.rs         NothingToken struct + sealed-box encrypt/decrypt
│       ├── transport/
│       │   └── node.rs          libp2p Swarm: TCP + Noise + Yamux + RPC
│       └── storage/
│           └── wallet.rs        ~/.nothing/ — flat files, no database
│
├── cli/                   Node.js — thin wrapper for nicer terminal output
│   ├── package.json
│   └── index.js
│
├── setup.sh               One command to build everything
└── README.md              You are here, man.
```

Keys and tokens live in `~/.nothing/`. That's it. No cloud. No sync. No telemetry. Lose the directory, lose the tokens — like cash in a wallet, except the wallet is mathematical and the cash has no face.

---

## Setup

```bash
bash setup.sh
```

Installs Rust if you don't have it. Compiles the binary. Takes 2-5 minutes on the first build while Cargo pulls the universe in.

Add to your PATH:
```bash
export PATH="$PATH:$(pwd)/nothing-core/target/release"
```

---

## Quick Start

**Generate your keys (once):**
```bash
nothing keygen
```
This gives you:
- An Ed25519 signing keypair (your peer identity on the network)
- An X25519 box keypair (how people address Nothing to you — share this pubkey)
- A 2048-bit RSA mint keypair (how you issue tokens)

**Mint a token:**
```bash
nothing mint --recipient <their-box-pubkey> --note "one Nothing"
```
Outputs a `.nothing` file. Encrypted. Addressed. Identity-free until opened.

**Two terminals. Two peers.**

Terminal A — receive:
```bash
nothing listen --port 7777
# Prints:
# Listening on: /ip4/127.0.0.1/tcp/7777/p2p/12D3KooW...
```

Terminal B — send:
```bash
nothing send /ip4/127.0.0.1/tcp/7777/p2p/12D3KooW... <token>.nothing
```

Terminal A when it lands:
```
Nothing received. Token ID: a3f8c1d2
  Note:      one Nothing
  Minted at: 1775850950
  From:      <minter-pubkey>
```

**Check your wallet:**
```bash
nothing wallet
```

---

## Phase Roadmap

| Phase | Status | What |
|-------|--------|------|
| 1 | ✅ Done | Key generation, blind signatures, P2P transport |
| 2 | 🎳 Up next | Circom circuit + snarkjs ZK settlement proofs |
| 3 | — | Multi-hop routing (token passes through intermediate peers) |
| 4 | — | Atomic swap / settlement protocol |

---

## On Nihilism and Nothing

The nihilists in the parking lot said they believed in nothing. I said I believed in *something* — the rules, the line, the foul if you go over it.

But here's the thing, man. Those nihilists were onto something they didn't understand. When you build a system where value is untraceable until it arrives — where the act of measurement destroys the trail — you've built something that *proves* it was nothing. Cryptographically.

The blind signature is the Schrödinger's box. The token is both nothing and something until observed by the recipient's private key. The ZK proof will be the moment the box opens without showing you the cat.

We didn't build a currency. We built the *absence* of one that functions identically.

*"The Dude abides."*

---

## Cryptographic Honesty Corner

*(Walter would want me to be clear about the rules.)*

- The blind signature scheme uses **raw unpadded RSA** for educational clarity. Production use should add RSA-PSS. The math is correct; the padding is for your protection.
- The `dryoc` crate is a pure-Rust implementation of libsodium's NaCl API — same primitives (X25519, Ed25519, XSalsa20-Poly1305), no C dependency.
- This is Phase 1. The ZK settlement proof (snarkjs/circom) is Phase 2. Until then, settlement is cryptographic but not zero-knowledge.
- **Do not put real value on this until Phase 4.** I'm serious, man. This is not 'Nam. There are rules.

---

## License

Nothing. Obviously.

*(MIT, technically. But philosophically: nothing.)*

---

*Built on a Tuesday. Between frames.*
