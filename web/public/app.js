/* app.js — Nothing web interface client */

// ── Boot ──────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  loadKeys();
  loadWallet();
});

// ── Keys ──────────────────────────────────────────────────────────────────────

async function loadKeys() {
  const loading = document.getElementById('keys-loading');
  const error   = document.getElementById('keys-error');
  const panel   = document.getElementById('keys-panel');

  try {
    const data = await api('/api/info');

    document.getElementById('box-pubkey').textContent  = data.box_pubkey;
    document.getElementById('sign-pubkey').textContent = data.sign_pubkey;
    document.getElementById('mint-n').textContent      = data.mint_n_prefix;

    loading.style.display = 'none';
    panel.style.display   = 'block';
  } catch (e) {
    loading.style.display = 'none';
    error.style.display   = 'block';
    error.textContent     = e.message;
  }
}

// ── Wallet ────────────────────────────────────────────────────────────────────

async function loadWallet() {
  const loading = document.getElementById('wallet-loading');
  const empty   = document.getElementById('wallet-empty');
  const grid    = document.getElementById('wallet-grid');

  try {
    const tokens = await api('/api/wallet');

    loading.style.display = 'none';

    if (tokens.length === 0) {
      empty.style.display = 'block';
      return;
    }

    grid.style.display = 'grid';
    grid.innerHTML = tokens.map(t => `
      <div class="token-card" onclick="showToken('${t.file}')">
        <div class="token-card-id">${t.short_id}…</div>
        <div class="token-card-meta">
          <span class="token-card-label">mint</span>${t.mint_n}<br/>
          <span class="token-card-label">ver</span>${t.version}
        </div>
      </div>
    `).join('');
  } catch (e) {
    loading.style.display = 'none';
    empty.textContent  = `Could not load wallet: ${e.message}`;
    empty.style.display = 'block';
  }
}

// ── Token detail drawer ───────────────────────────────────────────────────────

async function showToken(filename) {
  const drawer  = document.getElementById('token-drawer');
  const content = document.getElementById('drawer-content');

  content.innerHTML = '<div class="loading-state">Loading…</div>';
  drawer.style.display = 'block';
  drawer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  try {
    const t = await api(`/api/token/${filename}`);

    content.innerHTML = `
      <div class="drawer-field">
        <div class="drawer-field-label">Serial (private)</div>
        <div class="drawer-field-value hi">${t.serial_hex}</div>
      </div>
      <div class="drawer-field">
        <div class="drawer-field-label">RSA Blind Signature</div>
        <div class="drawer-field-value">${t.blind_signature_hex}</div>
      </div>
      <div class="drawer-field">
        <div class="drawer-field-label">Mint modulus (n)</div>
        <div class="drawer-field-value">${t.mint_pubkey?.n_hex}</div>
      </div>
      <div class="drawer-field">
        <div class="drawer-field-label">Mint exponent (e)</div>
        <div class="drawer-field-value">${t.mint_pubkey?.e_hex}</div>
      </div>
      <div class="drawer-field">
        <div class="drawer-field-label">Sealed payload (opaque until decrypted)</div>
        <div class="drawer-field-value">${t.sealed_payload_b64}</div>
      </div>
      <div style="margin-top:16px; font-size:0.78rem; color:var(--text-dimmer); font-family:var(--font-mono);">
        To settle this token, run:<br/>
        <span style="color:var(--accent)">nothing settle ${filename}</span>
      </div>
    `;
  } catch (e) {
    content.innerHTML = `<div class="result-error">Error: ${e.message}</div>`;
  }
}

function closeDrawer() {
  document.getElementById('token-drawer').style.display = 'none';
}

// ── Mint ──────────────────────────────────────────────────────────────────────

async function mintToSelf() {
  try {
    const info = await api('/api/info');
    document.getElementById('mint-recipient').value = info.box_pubkey;
  } catch (e) {
    toast('Could not load your key: ' + e.message, true);
  }
}

async function doMint(event) {
  event.preventDefault();

  const recipientInput = document.getElementById('mint-recipient');
  const noteInput      = document.getElementById('mint-note');
  const btn            = document.getElementById('mint-btn');
  const resultEl       = document.getElementById('mint-result');

  let recipient = recipientInput.value.trim();
  const note    = noteInput.value.trim() || 'one Nothing';

  // If blank, mint to self
  if (!recipient) {
    try {
      const info = await api('/api/info');
      recipient = info.box_pubkey;
    } catch (e) {
      showResult(resultEl, false, 'Could not load your key: ' + e.message);
      return;
    }
  }

  if (!/^[0-9a-f]{64}$/i.test(recipient)) {
    showResult(resultEl, false, 'Recipient must be a 64-character hex string (X25519 public key).');
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Minting…';
  resultEl.style.display = 'none';

  try {
    const data = await api('/api/mint', {
      method: 'POST',
      body:   JSON.stringify({ recipient, note }),
    });

    showResult(resultEl, true, data.short_id, note, data.message);
    noteInput.value = '';
    // Reload wallet to show the new token
    await loadWallet();
    toast('Nothing minted. Check your wallet.');
  } catch (e) {
    showResult(resultEl, false, e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Mint Nothing';
  }
}

function showResult(el, success, shortIdOrError, note, raw) {
  el.style.display = 'block';
  if (success) {
    el.innerHTML = `
      <div class="result-success">
        <h4>✓ Nothing minted</h4>
        <div class="result-mono">Short ID: ${shortIdOrError}
Note:     ${note}

Saved to ~/.nothing/tokens/${shortIdOrError}.nothing

In transit, this token has no identity.
It becomes something only when the recipient decrypts and verifies it.</div>
      </div>
    `;
  } else {
    el.innerHTML = `<div class="result-error">${shortIdOrError}</div>`;
  }
}

// ── Key copy ──────────────────────────────────────────────────────────────────

function copyKey(elementId) {
  const el   = document.getElementById(elementId);
  const text = el.textContent;
  navigator.clipboard.writeText(text).then(() => {
    toast('Copied to clipboard');
  }).catch(() => {
    // Fallback
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    toast('Copied to clipboard');
  });
}

// ── Toast notification ────────────────────────────────────────────────────────

let _toastTimer = null;

function toast(message, isError = false) {
  const el = document.getElementById('toast');
  el.textContent = message;
  el.style.borderColor = isError ? 'rgba(239,68,68,0.4)' : '';
  el.classList.add('show');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => el.classList.remove('show'), 2800);
}

// ── API helper ────────────────────────────────────────────────────────────────

async function api(url, options = {}) {
  const defaults = {
    headers: { 'Content-Type': 'application/json' },
  };
  const res = await fetch(url, { ...defaults, ...options });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error || `HTTP ${res.status}`);
  return json;
}
