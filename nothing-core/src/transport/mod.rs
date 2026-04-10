//! transport — peer-to-peer mesh networking for Nothing
//!
//! Powered by libp2p: TCP + Noise encryption + Yamux multiplexing.
//! Tokens in transit are double-encrypted:
//!   1. Transport layer (Noise — authenticated per-connection encryption).
//!   2. Token layer (sealed-box — addressed to recipient's X25519 key).

pub mod node;
