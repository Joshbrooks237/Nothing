//! main.rs — Nothing CLI entry point
//!
//! Commands:
//!   keygen  — generate keypairs (Ed25519 sign + X25519 box + RSA mint)
//!   mint    — create a blind-signed token addressed to a recipient
//!   listen  — start a P2P listener node
//!   send    — send a token to a peer
//!   info    — print your public keys
//!   wallet  — list tokens in your local wallet

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use nothing_core::crypto::blind_sig::MintKeypair;
use nothing_core::crypto::keypair::{BoxKeypair, SignKeypair};
use nothing_core::crypto::token::NothingToken;
use nothing_core::storage::wallet::{keys_dir, Wallet};
use nothing_core::transport::node::{cmd_listen, cmd_send};

// ─── CLI definition ───────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name    = "nothing",
    version = "0.1.0",
    about   = "A cryptographic bearer instrument with no identity in transit.",
    long_about = "Nothing has no ticker, no ledger, no exchange listing.\n\
                  It does not classify as a coin until the moment of successful\n\
                  settlement — at which point it has already arrived."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate all keypairs (sign, box, mint) and save to ~/.nothing/keys/.
    ///
    /// Run this once on first use.  Your box public key is what you share with
    /// anyone who wants to send you Nothing.
    Keygen,

    /// Mint a new Nothing token addressed to a recipient.
    ///
    /// The recipient is identified by their X25519 box public key (printed by
    /// their `nothing keygen` or `nothing info`).  The token is encrypted so
    /// only they can read the inner payload.
    ///
    /// Example:
    ///   nothing mint --recipient <hex-pubkey> --note "one Nothing unit"
    Mint {
        /// Recipient's X25519 box public key (64-char hex string).
        #[arg(long, short = 'r')]
        recipient: String,

        /// A short note to include in the sealed payload.
        #[arg(long, short = 'n', default_value = "one Nothing")]
        note: String,

        /// Output file path.  Defaults to <token-short-id>.nothing in the CWD.
        #[arg(long, short = 'o')]
        output: Option<String>,
    },

    /// Start a P2P listener node.
    ///
    /// Prints the multiaddr (including your peer ID) after binding.
    /// Copy that address and give it to the sender so they can `nothing send`.
    ///
    /// Example:
    ///   nothing listen --port 7777
    Listen {
        /// TCP port to listen on.  Use 0 for a random OS-assigned port.
        #[arg(long, short = 'p', default_value = "0")]
        port: u16,
    },

    /// Send a token file to a listening peer.
    ///
    /// Example:
    ///   nothing send /ip4/127.0.0.1/tcp/7777/p2p/12D3KooW... token.nothing
    Send {
        /// Target peer's multiaddr (printed by `nothing listen`).
        peer: String,

        /// Path to the .nothing token file to send.
        token: String,
    },

    /// Print your public keys.
    Info,

    /// List tokens in your local wallet.
    Wallet,
}

// ─── main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // Initialise the tracing subscriber.  Set RUST_LOG=debug for verbose output.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("nothing_core=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen => cmd_keygen(),
        Commands::Mint { recipient, note, output } => cmd_mint(&recipient, &note, output),
        Commands::Listen { port } => cmd_listen(port).await,
        Commands::Send { peer, token } => cmd_send(&peer, &token).await,
        Commands::Info => cmd_info(),
        Commands::Wallet => cmd_wallet(),
    }
}

// ─── keygen ───────────────────────────────────────────────────────────────────

fn cmd_keygen() -> Result<()> {
    let dir = keys_dir()?;

    // ── Ed25519 signing keypair (also drives the libp2p peer ID).
    let sign_kp = SignKeypair::generate();
    sign_kp.save(&dir.join("sign.json"))?;
    println!("Sign keypair  → {:?}", dir.join("sign.json"));
    println!("  Public key: {}", sign_kp.public_key_hex);

    // ── X25519 box keypair (for receiving sealed tokens).
    let box_kp = BoxKeypair::generate();
    box_kp.save(&dir.join("box.json"))?;
    println!("\nBox keypair   → {:?}", dir.join("box.json"));
    println!("  Public key: {}", box_kp.public_key_hex);

    // ── RSA mint keypair (for blind-signing tokens you issue).
    //    2048-bit is fast enough for local dev; use 4096 for anything real.
    println!("\nGenerating 2048-bit RSA mint keypair (this takes a moment)...");
    let mint_kp = MintKeypair::generate(2048)?;
    mint_kp.save(&dir.join("mint.json"))?;
    println!("Mint keypair  → {:?}", dir.join("mint.json"));
    println!("  n (first 16 bytes): {}...", &mint_kp.public_key_info().n_hex[..32]);

    println!("\nAll keys saved to {:?}", dir);
    println!("\nShare your BOX public key with anyone who wants to send you Nothing:");
    println!("  {}", box_kp.public_key_hex);

    Ok(())
}

// ─── mint ─────────────────────────────────────────────────────────────────────

fn cmd_mint(recipient_hex: &str, note: &str, output: Option<String>) -> Result<()> {
    let dir = keys_dir()?;

    // Load the minter's box keypair (for embedding provenance in the payload).
    let minter_box_kp = BoxKeypair::load(&dir.join("box.json"))
        .context("load box keypair — did you run `nothing keygen` first?")?;

    // Load the mint (RSA) keypair.
    let mint_kp = MintKeypair::load(&dir.join("mint.json"))
        .context("load mint keypair")?;

    println!("Minting token for recipient: {}...", &recipient_hex[..16]);

    // Mint the token.
    // Internally this:
    //   1. Generates a random 32-byte serial.
    //   2. Blinds the serial hash.
    //   3. Signs the blinded hash with the RSA private key.
    //   4. Unblinds to produce a valid RSA signature.
    //   5. Seals a payload to the recipient's X25519 public key.
    let token = NothingToken::mint(
        &mint_kp,
        recipient_hex,
        &minter_box_kp.public_key_hex,
        note,
    )
    .context("minting failed")?;

    // Determine the output path.
    let output_path = output.unwrap_or_else(|| format!("{}.nothing", token.short_id()));

    token.save(std::path::Path::new(&output_path))?;

    println!("Token minted.");
    println!("  Short ID:  {}", token.short_id());
    println!("  File:      {}", output_path);
    println!("\nIn transit this token has no identity.");
    println!("It becomes something only when the recipient decrypts and verifies it.");

    Ok(())
}

// ─── info ─────────────────────────────────────────────────────────────────────

fn cmd_info() -> Result<()> {
    let dir = keys_dir()?;

    let sign_kp = SignKeypair::load(&dir.join("sign.json"))
        .context("no sign keypair — run `nothing keygen` first")?;
    let box_kp = BoxKeypair::load(&dir.join("box.json"))
        .context("no box keypair")?;

    println!("Sign pubkey (peer ID basis):");
    println!("  {}", sign_kp.public_key_hex);
    println!("\nBox pubkey (share this to receive tokens):");
    println!("  {}", box_kp.public_key_hex);

    Ok(())
}

// ─── wallet ───────────────────────────────────────────────────────────────────

fn cmd_wallet() -> Result<()> {
    let wallet = Wallet::open()?;
    let tokens = wallet.list()?;

    if tokens.is_empty() {
        println!("Wallet is empty.  Receive some Nothing first.");
        return Ok(());
    }

    println!("Tokens in wallet ({} total):", tokens.len());
    for token in &tokens {
        println!(
            "  {} — mint n: {}...",
            token.short_id(),
            &token.mint_pubkey.n_hex[..16]
        );
    }

    Ok(())
}
