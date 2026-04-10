//! storage/wallet.rs — file-based token store
//!
//! Nothing has no database anyone can query.  The wallet is just a directory
//! on disk: ~/.nothing/tokens/.  Each token is a standalone .nothing JSON file.
//! Losing the directory means losing the tokens — like cash in a wallet.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::token::NothingToken;

// ─── Directory helpers ────────────────────────────────────────────────────────

/// The root directory for all Nothing data: ~/.nothing/
pub fn nothing_dir() -> Result<PathBuf> {
    dirs::home_dir()
        .context("cannot determine home directory")
        .map(|h| h.join(".nothing"))
}

/// The keys subdirectory: ~/.nothing/keys/
pub fn keys_dir() -> Result<PathBuf> {
    nothing_dir().map(|d| d.join("keys"))
}

/// The tokens subdirectory: ~/.nothing/tokens/
pub fn tokens_dir() -> Result<PathBuf> {
    nothing_dir().map(|d| d.join("tokens"))
}

// ─── Wallet ───────────────────────────────────────────────────────────────────

/// A handle to the local token store (~/.nothing/tokens/).
pub struct Wallet {
    dir: PathBuf,
}

impl Wallet {
    /// Open (or create) the wallet directory.
    pub fn open() -> Result<Self> {
        let dir = tokens_dir()?;
        fs::create_dir_all(&dir).context("creating tokens directory")?;
        Ok(Wallet { dir })
    }

    /// Save a token to the wallet.
    ///
    /// The file name is the token's serial hex (first 16 chars) + ".nothing".
    /// This is deterministic so saving the same token twice is idempotent.
    pub fn store(&self, token: &NothingToken) -> Result<PathBuf> {
        let filename = format!("{}.nothing", token.short_id());
        let path = self.dir.join(&filename);
        token.save(&path)?;
        Ok(path)
    }

    /// List all tokens in the wallet.
    pub fn list(&self) -> Result<Vec<NothingToken>> {
        let mut tokens = Vec::new();
        for entry in fs::read_dir(&self.dir).context("reading tokens dir")? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("nothing") {
                match NothingToken::load(&path) {
                    Ok(t) => tokens.push(t),
                    Err(e) => eprintln!("Warning: could not load {:?}: {}", path, e),
                }
            }
        }
        Ok(tokens)
    }

    /// Return the wallet directory path.
    pub fn path(&self) -> &Path {
        &self.dir
    }
}
