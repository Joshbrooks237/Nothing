//! nothing-core — library crate
//!
//! Exposes crypto, transport, and storage modules so the binary (main.rs) and
//! any external tests or FFI wrappers can import them.

pub mod crypto;
pub mod storage;
pub mod transport;
