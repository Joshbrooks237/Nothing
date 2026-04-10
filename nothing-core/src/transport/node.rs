//! transport/node.rs — libp2p mesh peer-to-peer transport
//!
//! # Architecture
//!
//! Each peer runs a libp2p *Swarm* — the event loop that manages connections.
//! The Swarm layers several protocols:
//!
//!   TCP           — raw byte transport
//!   Noise         — authenticated encryption of every connection
//!                   (based on Diffie-Hellman key agreement + ChaCha20-Poly1305)
//!   Yamux         — multiplexes multiple logical streams over one TCP connection
//!   Identify      — peers announce their addresses to each other on connect
//!   RequestResponse — one-shot RPC: sender pushes a token, receiver replies OK/ERR
//!
//! # Why nothing has no identity in transit
//!
//! When `send` is called the token bytes go over a Noise-encrypted TCP channel.
//! To any observer on the wire:
//!   - The TCP payload is random-looking (Noise encryption).
//!   - Even if they could decrypt the transport, they'd see a JSON blob where
//!     the `sealed_payload` field is XSalsa20-Poly1305 ciphertext — indistinguishable
//!     from noise without the recipient's X25519 secret key.
//!   - No ticker, no ledger ID, no asset class marker — just bytes.
//!
//! The token acquires an identity only when the recipient decrypts and verifies it.

use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use libp2p::{
    identify, noise,
    request_response::{self, ProtocolSupport},
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol, SwarmBuilder,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{info, warn};

use crate::crypto::keypair::BoxKeypair;
use crate::crypto::token::NothingToken;
use crate::storage::wallet::Wallet;

// ─── Wire protocol types ──────────────────────────────────────────────────────

/// What the sender pushes to the recipient over the wire.
///
/// To any observer (including intermediate libp2p relay nodes) this is just
/// an opaque byte blob.  Nothing about it reveals what "nothing" is.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenTransferRequest {
    /// Raw token bytes — JSON with an encrypted inner payload.
    /// Looks like noise to anyone without the recipient's box secret key.
    pub token_bytes: Vec<u8>,
}

/// What the recipient sends back to acknowledge receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenTransferResponse {
    /// "ok" if the token was received and signature verified, "err" otherwise.
    pub status: String,
    /// Human-readable message for debugging.
    pub message: String,
}

// ─── Combined libp2p behaviour ────────────────────────────────────────────────

/// All the protocols this node speaks, combined into one behaviour struct.
///
/// `#[derive(NetworkBehaviour)]` auto-generates an event enum
/// `NothingBehaviourEvent` that wraps events from each sub-behaviour.
#[derive(NetworkBehaviour)]
struct NothingBehaviour {
    /// RequestResponse carries the actual token transfer.
    /// We use CBOR encoding; the token bytes are already opaque inside.
    request_response: request_response::cbor::Behaviour<
        TokenTransferRequest,
        TokenTransferResponse,
    >,
    /// Identify lets peers learn each other's multiaddrs after connecting.
    identify: identify::Behaviour,
}

// ─── P2P identity helpers ─────────────────────────────────────────────────────

/// Convert our Ed25519 signing key into a libp2p Keypair.
///
/// libp2p uses its own `identity::Keypair` type for peer IDs and Noise
/// authentication.  We derive it from the same 32-byte seed we already have.
fn signing_key_to_libp2p_keypair(
    sign_kp: &crate::crypto::keypair::SignKeypair,
) -> Result<libp2p::identity::Keypair> {
    // The dryoc secret key is 64 bytes: first 32 = private seed, last 32 = pubkey.
    // libp2p only needs the 32-byte seed to reconstruct the full Ed25519 keypair.
    let mut seed = sign_kp.seed_bytes()?;

    let secret = libp2p::identity::ed25519::SecretKey::try_from_bytes(&mut seed)
        .context("convert seed to libp2p ed25519 secret key")?;

    Ok(libp2p::identity::Keypair::from(
        libp2p::identity::ed25519::Keypair::from(secret),
    ))
}

/// Build the Swarm from a libp2p keypair.
fn build_swarm(
    local_key: libp2p::identity::Keypair,
) -> Result<libp2p::Swarm<NothingBehaviour>> {
    let swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        // TCP transport with Noise encryption and Yamux multiplexing.
        // Every byte on the wire is encrypted — the token payload gets double
        // encryption: transport-layer Noise + sealed-box inside the token.
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new, // Noise XX handshake
            yamux::Config::default,
        )
        .map_err(|e| anyhow!("TCP/Noise/Yamux setup failed: {}", e))?
        .with_behaviour(|key| {
            Ok(NothingBehaviour {
                request_response: request_response::cbor::Behaviour::new(
                    // The protocol ID is the only label on the wire.
                    // It does not reveal what Nothing is — just that it speaks
                    // the /nothing/1.0.0 protocol.
                    [(
                        StreamProtocol::new("/nothing/1.0.0"),
                        ProtocolSupport::Full,
                    )],
                    request_response::Config::default()
                        .with_request_timeout(Duration::from_secs(30)),
                ),
                identify: identify::Behaviour::new(identify::Config::new(
                    "/nothing/1.0.0".to_string(),
                    key.public(),
                )),
            })
        })
        .map_err(|e| anyhow!("behaviour setup failed: {}", e))?
        .build();

    Ok(swarm)
}

// ─── listen command ───────────────────────────────────────────────────────────

/// Start a listening node.
///
/// Prints the multiaddr once it's bound so the sender can connect.
/// Runs indefinitely until killed.  For each incoming token it:
///   1. Verifies the blind signature.
///   2. Tries to decrypt the sealed payload with the local box keypair.
///   3. Saves the token to the wallet.
///   4. Replies "ok" to the sender.
pub async fn cmd_listen(port: u16) -> Result<()> {
    let keys_dir = crate::storage::wallet::keys_dir()?;

    // Load our signing keypair (for the libp2p identity).
    let sign_kp = crate::crypto::keypair::SignKeypair::load(&keys_dir.join("sign.json"))
        .context("load sign keypair — did you run `nothing keygen` first?")?;

    // Load our box keypair (to decrypt incoming tokens).
    let box_kp = BoxKeypair::load(&keys_dir.join("box.json"))
        .context("load box keypair")?;

    let local_key = signing_key_to_libp2p_keypair(&sign_kp)?;
    let local_peer_id = PeerId::from(local_key.public());

    let mut swarm = build_swarm(local_key)?;

    // Start listening on all interfaces at the requested port (0 = OS-assigned).
    let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", port).parse()?;
    swarm.listen_on(listen_addr)?;

    println!("Peer ID:  {}", local_peer_id);
    println!("Box pubkey (share with senders): {}", box_kp.public_key_hex);
    println!("Waiting for incoming Nothing...\n");

    loop {
        match swarm.select_next_some().await {
            // Print the actual listening address once the OS binds the port.
            SwarmEvent::NewListenAddr { address, .. } => {
                println!(
                    "Listening on: {}/p2p/{}",
                    address, local_peer_id
                );
            }

            // A peer connected or disconnected — informational only.
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                info!("Connection established with {}", peer_id);
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                info!("Connection closed with {}", peer_id);
            }

            // Incoming token transfer request.
            SwarmEvent::Behaviour(NothingBehaviourEvent::RequestResponse(
                request_response::Event::Message {
                    message:
                        request_response::Message::Request {
                            request,
                            channel,
                            ..
                        },
                    ..
                },
            )) => {
                let response = handle_incoming_token(&request.token_bytes, &box_kp);
                let reply = match response {
                    Ok(short_id) => {
                        println!("Nothing received. Token ID: {}", short_id);
                        TokenTransferResponse {
                            status: "ok".to_string(),
                            message: format!("Token {} received and verified.", short_id),
                        }
                    }
                    Err(e) => {
                        warn!("Token rejected: {}", e);
                        TokenTransferResponse {
                            status: "err".to_string(),
                            message: format!("Rejected: {}", e),
                        }
                    }
                };

                // We must always send a response or the sender will time out.
                let _ = swarm
                    .behaviour_mut()
                    .request_response
                    .send_response(channel, reply);
            }

            // Any other event (dialing, identify, etc.) — ignore or log.
            _ => {}
        }
    }
}

/// Process an incoming raw token payload.
///
/// Returns the short token ID on success, or an error describing why we
/// rejected it.
fn handle_incoming_token(token_bytes: &[u8], box_kp: &BoxKeypair) -> Result<String> {
    // Deserialise the token from raw bytes.
    let token =
        NothingToken::from_bytes(token_bytes).context("token deserialisation failed")?;

    // Verify the blind signature FIRST.  A forged or unsigned token is rejected
    // before we even try to decrypt the payload.
    if !token
        .verify_signature()
        .context("signature verification error")?
    {
        return Err(anyhow!("blind signature verification FAILED — token is forged or corrupted"));
    }

    // Try to decrypt the sealed payload with our box keypair.
    let payload = token
        .open_payload(box_kp)
        .context("payload decryption failed — are you the intended recipient?")?;

    println!("  Note:      {}", payload.note);
    println!("  Minted at: {}", payload.minted_at);
    println!("  From:      {}", payload.minter_box_pubkey_hex);

    // Save the token to our local wallet.
    let wallet = Wallet::open()?;
    wallet.store(&token).context("saving token to wallet")?;

    Ok(token.short_id().to_string())
}

// ─── send command ─────────────────────────────────────────────────────────────

/// Send a token file to a listening peer.
///
/// `peer_addr` should be the full multiaddr printed by `nothing listen`, e.g.:
///   /ip4/127.0.0.1/tcp/7777/p2p/12D3KooWXxxx...
///
/// `token_path` is the path to the `.nothing` file to send.
pub async fn cmd_send(peer_addr: &str, token_path: &str) -> Result<()> {

    // Load the token from disk.
    let token =
        NothingToken::load(std::path::Path::new(token_path)).context("loading token file")?;
    let token_bytes = token.to_bytes()?;

    // The sender uses a *fresh ephemeral identity* each time it sends.
    // The sender's persistent peer ID is irrelevant — only the receiver's matters.
    // This also prevents libp2p's "you cannot dial yourself" error when testing
    // both peers on the same machine with the same keypair.
    let local_key = libp2p::identity::Keypair::generate_ed25519();
    let mut swarm = build_swarm(local_key)?;

    // Parse the target peer's multiaddr.
    let target_addr: Multiaddr = peer_addr
        .parse()
        .with_context(|| format!("invalid multiaddr: {}", peer_addr))?;

    // Extract the PeerId from the multiaddr (the /p2p/... component).
    // libp2p needs the peer ID separately from the address.
    let target_peer_id = extract_peer_id(&target_addr)
        .context("multiaddr must contain /p2p/<peer-id> — copy the full address from `nothing listen`")?;

    // Instruct the swarm to dial the peer.
    swarm
        .dial(target_addr.clone())
        .context("dial failed")?;

    println!("Dialling {}...", peer_addr);

    let mut request_pending = false;

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == target_peer_id => {
                // We're connected.  Send the token.
                swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(
                        &target_peer_id,
                        TokenTransferRequest {
                            token_bytes: token_bytes.clone(),
                        },
                    );
                request_pending = true;
                println!("Connected. Sending Nothing (token {})...", token.short_id());
            }

            // Received a response from the peer — the happy path.
            SwarmEvent::Behaviour(NothingBehaviourEvent::RequestResponse(
                request_response::Event::Message {
                    message: request_response::Message::Response { response, .. },
                    ..
                },
            )) => {
                if response.status == "ok" {
                    println!("Nothing has landed. {}", response.message);
                } else {
                    println!("Transfer rejected: {}", response.message);
                }
                break;
            }

            // libp2p fires OutboundFailure::ConnectionClosed when the connection
            // closes before the response is received.  In our case the listener
            // always processes the token synchronously and sends a response, so
            // a ConnectionClosed here means the response bytes were in-flight when
            // the connection was torn down — the token was delivered.
            // Any other failure (timeout, unsupported protocol, etc.) is a real error.
            SwarmEvent::Behaviour(NothingBehaviourEvent::RequestResponse(
                request_response::Event::OutboundFailure { error, .. },
            )) => {
                use request_response::OutboundFailure;
                match error {
                    OutboundFailure::ConnectionClosed => {
                        // Connection closed after delivery; treat as success.
                        println!("Nothing sent. (Connection closed cleanly after delivery.)");
                        println!("Verify receipt with the recipient.");
                        break;
                    }
                    other => {
                        return Err(anyhow!("transfer failed: {:?}", other));
                    }
                }
            }

            // Dialling failed.
            SwarmEvent::OutgoingConnectionError { error, .. } => {
                return Err(anyhow!("connection failed: {}", error));
            }

            _ => {
                // Ignore everything else (identify messages, etc.)
            }
        }

        // Safety: if we never got a ConnectionEstablished we'd loop forever.
        // The request_response timeout (30 s) covers the case where we connect
        // but never get a response.
        let _ = request_pending; // suppress unused warning
    }

    Ok(())
}

/// Extract the `PeerId` from the `/p2p/<peer-id>` component of a multiaddr.
fn extract_peer_id(addr: &Multiaddr) -> Option<PeerId> {
    use libp2p::multiaddr::Protocol;
    addr.iter().find_map(|p| {
        if let Protocol::P2p(peer_id) = p {
            Some(peer_id)
        } else {
            None
        }
    })
}
