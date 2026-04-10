//! nothing-core — library crate
//!
//! Exposes crypto, transport, storage, and settlement modules so the binary
//! (main.rs) and any external tests or FFI wrappers can import them.

pub mod crypto;
pub mod settlement;
pub mod storage;
pub mod transport;
