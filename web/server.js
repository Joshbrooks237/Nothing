/**
 * server.js — local web interface for Nothing
 *
 * Runs a tiny Express server on localhost:3131.
 * Reads keys and tokens from ~/.nothing/ and shells out to the
 * nothing binary for minting operations.
 *
 * Nothing never phones home — this server is entirely local.
 */

import express from 'express';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { readFileSync, readdirSync, existsSync } from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';

const execFileAsync = promisify(execFile);
const __dirname    = path.dirname(fileURLToPath(import.meta.url));

// ── Paths ─────────────────────────────────────────────────────────────────────

const NOTHING_DIR  = path.join(os.homedir(), '.nothing');
const KEYS_DIR     = path.join(NOTHING_DIR, 'keys');
const TOKENS_DIR   = path.join(NOTHING_DIR, 'tokens');
const SETTLED_PATH = path.join(NOTHING_DIR, 'settled.json');

// Look for the binary: debug build first, then release build.
const BINARY = (() => {
  const debug   = path.join(__dirname, '..', 'nothing-core', 'target', 'debug',   'nothing');
  const release = path.join(__dirname, '..', 'nothing-core', 'target', 'release', 'nothing');
  if (existsSync(release)) return release;
  if (existsSync(debug))   return debug;
  return null;
})();

const PORT = 3131;

// ── Express setup ─────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── API: info ─────────────────────────────────────────────────────────────────

app.get('/api/info', (req, res) => {
  try {
    const box  = JSON.parse(readFileSync(path.join(KEYS_DIR, 'box.json'),  'utf8'));
    const sign = JSON.parse(readFileSync(path.join(KEYS_DIR, 'sign.json'), 'utf8'));
    const mint = JSON.parse(readFileSync(path.join(KEYS_DIR, 'mint.json'), 'utf8'));
    res.json({
      box_pubkey:   box.public_key_hex,
      sign_pubkey:  sign.public_key_hex,
      mint_n_prefix: (mint.pub_n_hex ?? mint.n_hex ?? '').slice(0, 32) + '…',
      binary_found: !!BINARY,
    });
  } catch (e) {
    res.status(500).json({ error: `Keys not found. Run: nothing keygen\n(${e.message})` });
  }
});

// ── API: wallet ───────────────────────────────────────────────────────────────

app.get('/api/wallet', (req, res) => {
  try {
    if (!existsSync(TOKENS_DIR)) return res.json([]);

    const settled = existsSync(SETTLED_PATH)
      ? new Set(Object.keys(JSON.parse(readFileSync(SETTLED_PATH, 'utf8'))))
      : new Set();

    const files = readdirSync(TOKENS_DIR)
      .filter(f => f.endsWith('.nothing'));

    const tokens = files.map(f => {
      try {
        const t = JSON.parse(readFileSync(path.join(TOKENS_DIR, f), 'utf8'));
        return {
          file:       f,
          short_id:   t.serial_hex?.slice(0, 16),
          serial_hex: t.serial_hex,
          mint_n:     t.mint_pubkey?.n_hex?.slice(0, 24) + '…',
          version:    t.version,
          settled:    false, // nullifier-based check would require poseidon; skip for display
        };
      } catch { return null; }
    }).filter(Boolean);

    res.json(tokens);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── API: token detail ─────────────────────────────────────────────────────────

app.get('/api/token/:filename', (req, res) => {
  try {
    const safe = path.basename(req.params.filename); // prevent path traversal
    const full = path.join(TOKENS_DIR, safe);
    if (!existsSync(full)) return res.status(404).json({ error: 'Token not found' });
    const t = JSON.parse(readFileSync(full, 'utf8'));
    res.json(t);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── API: mint ─────────────────────────────────────────────────────────────────

app.post('/api/mint', async (req, res) => {
  const { recipient, note } = req.body;

  if (!recipient || !/^[0-9a-f]{64}$/i.test(recipient)) {
    return res.status(400).json({ error: 'recipient must be a 64-char hex X25519 public key' });
  }
  if (!BINARY) {
    return res.status(500).json({
      error: 'nothing binary not found. Run: cd nothing-core && cargo build'
    });
  }

  try {
    const { stdout, stderr } = await execFileAsync(BINARY, [
      'mint',
      '--recipient', recipient,
      '--note',      note || 'one Nothing',
    ], { cwd: path.join(__dirname, '..') });

    // Binary prints "Short ID:  <id>" — extract it
    const match = stdout.match(/Short ID:\s+([0-9a-f]+)/);
    const shortId = match ? match[1] : null;

    res.json({
      success:  true,
      short_id: shortId,
      message:  stdout.trim(),
    });
  } catch (e) {
    res.status(500).json({ error: e.stderr || e.message });
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, '127.0.0.1', () => {
  console.log('');
  console.log('  ╔═══════════════════════════════════════╗');
  console.log('  ║   Nothing — local web interface        ║');
  console.log('  ╚═══════════════════════════════════════╝');
  console.log('');
  console.log(`  Open:  http://localhost:${PORT}`);
  console.log('');
  console.log('  This server is local only — nothing phones home.');
  console.log('  Stop with Ctrl+C');
  console.log('');
});
