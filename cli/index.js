#!/usr/bin/env node
/**
 * nothing — Node.js CLI wrapper
 *
 * This file is the entry point.  It builds the command tree using `commander`
 * and delegates every action to the compiled Rust binary (nothing-core/target/
 * release/nothing).
 *
 * Why a Node.js wrapper at all?
 *   - Nicer terminal output (colours, spinners, formatted tables).
 *   - Easy to extend with ZK proof generation (snarkjs/circom) without
 *     recompiling Rust.
 *   - Familiar scripting environment for automation.
 *
 * The Rust binary does all the heavy lifting: crypto, P2P, file I/O.
 * Node is just the face.
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { existsSync } from 'fs';

// Derive __dirname equivalent in ESM.
const __dirname = dirname(fileURLToPath(import.meta.url));

// ── Locate the compiled Rust binary ──────────────────────────────────────────

/**
 * Resolve the path to the compiled `nothing` binary.
 * Checks release build first, then debug build, then PATH.
 */
function findBinary() {
  const release = join(__dirname, '..', 'nothing-core', 'target', 'release', 'nothing');
  const debug   = join(__dirname, '..', 'nothing-core', 'target', 'debug',   'nothing');

  if (existsSync(release)) return release;
  if (existsSync(debug))   return debug;

  // Fall back to PATH (useful if installed via `cargo install`).
  return 'nothing';
}

// ── Command runner ────────────────────────────────────────────────────────────

import { spawn } from 'child_process';

/**
 * Spawn the Rust binary with the given arguments and stream its output.
 *
 * Returns a Promise that resolves when the process exits with code 0, or
 * rejects with the exit code on failure.
 */
function run(args) {
  const bin = findBinary();

  // If the binary doesn't exist yet, give a helpful hint.
  if (bin === 'nothing' && !existsSync(bin)) {
    console.error(chalk.red('\nRust binary not found.'));
    console.error(chalk.yellow('Run `npm run build-core` to compile it first.\n'));
    console.error(chalk.dim('Or from the nothing-core directory: cargo build --release'));
    process.exit(1);
  }

  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, {
      stdio: 'inherit',   // pass through stdin/stdout/stderr directly
      shell: false,
    });

    child.on('exit', (code) => {
      if (code === 0) resolve();
      else reject(code);
    });

    child.on('error', (err) => {
      if (err.code === 'ENOENT') {
        console.error(chalk.red(`\nCould not find binary: ${bin}`));
        console.error(chalk.yellow('Run: cd nothing-core && cargo build --release\n'));
      } else {
        console.error(chalk.red(`Spawn error: ${err.message}`));
      }
      reject(1);
    });
  });
}

// ── CLI definition ────────────────────────────────────────────────────────────

const program = new Command();

program
  .name('nothing')
  .version('0.1.0')
  .description(
    chalk.bold('Nothing') + ' — a cryptographic bearer instrument with no identity in transit.\n\n' +
    chalk.dim('No ticker. No ledger. No exchange listing.\n') +
    chalk.dim('It becomes something only when it lands.')
  );

// ── keygen ────────────────────────────────────────────────────────────────────

program
  .command('keygen')
  .description('Generate all keypairs (sign, box, mint) — run once on first use.')
  .action(async () => {
    console.log(chalk.cyan('\nGenerating keypairs...\n'));
    try {
      await run(['keygen']);
    } catch {
      process.exit(1);
    }
  });

// ── mint ──────────────────────────────────────────────────────────────────────

program
  .command('mint')
  .description('Mint a new Nothing token, blind-signed and sealed for a recipient.')
  .requiredOption('-r, --recipient <hex>', "Recipient's X25519 box public key (64-char hex).")
  .option('-n, --note <text>',   'Short note inside the sealed payload.', 'one Nothing')
  .option('-o, --output <path>', 'Output .nothing file path.')
  .addHelpText('after', `
Example:
  nothing mint --recipient abc123... --note "sending one Nothing"
  nothing mint -r abc123... -o my-token.nothing
  `)
  .action(async (opts) => {
    const args = ['mint', '--recipient', opts.recipient, '--note', opts.note];
    if (opts.output) args.push('--output', opts.output);
    try {
      await run(args);
    } catch {
      process.exit(1);
    }
  });

// ── listen ────────────────────────────────────────────────────────────────────

program
  .command('listen')
  .description('Start a P2P listener.  Prints multiaddr — give it to the sender.')
  .option('-p, --port <number>', 'TCP port (0 = OS assigns one).', '0')
  .addHelpText('after', `
Example:
  nothing listen --port 7777

Copy the printed multiaddr and give it to the sender:
  /ip4/127.0.0.1/tcp/7777/p2p/12D3KooW...
  `)
  .action(async (opts) => {
    console.log(chalk.cyan('\nStarting Nothing listener...\n'));
    try {
      await run(['listen', '--port', opts.port]);
    } catch {
      process.exit(1);
    }
  });

// ── send ──────────────────────────────────────────────────────────────────────

program
  .command('send <peer> <token>')
  .description('Send a .nothing token file to a listening peer.')
  .addHelpText('after', `
Arguments:
  <peer>   Full multiaddr from \`nothing listen\`
           e.g. /ip4/127.0.0.1/tcp/7777/p2p/12D3KooW...
  <token>  Path to the .nothing file

Example:
  nothing send /ip4/127.0.0.1/tcp/7777/p2p/12D3KooW... abc12345.nothing
  `)
  .action(async (peer, token) => {
    console.log(chalk.cyan(`\nSending Nothing to ${peer}...\n`));
    try {
      await run(['send', peer, token]);
    } catch {
      process.exit(1);
    }
  });

// ── info ──────────────────────────────────────────────────────────────────────

program
  .command('info')
  .description('Print your public keys.')
  .action(async () => {
    try {
      await run(['info']);
    } catch {
      process.exit(1);
    }
  });

// ── wallet ────────────────────────────────────────────────────────────────────

program
  .command('wallet')
  .description('List tokens in your local wallet (~/.nothing/tokens/).')
  .action(async () => {
    console.log(chalk.cyan('\nLocal wallet contents:\n'));
    try {
      await run(['wallet']);
    } catch {
      process.exit(1);
    }
  });

// ── help footer ───────────────────────────────────────────────────────────────

program.addHelpText('after', `
${chalk.bold('Quick start (two terminals):')}

  Terminal A — generate keys and listen:
    $ nothing keygen
    $ nothing listen --port 7777
    > Listening on: /ip4/127.0.0.1/tcp/7777/p2p/12D3KooW...

  Terminal B — mint a token and send it:
    $ nothing mint --recipient <Box pubkey from A's keygen>
    $ nothing send /ip4/127.0.0.1/tcp/7777/p2p/12D3KooW... <token-file>

${chalk.dim('Binary: ' + findBinary())}
`);

program.parse(process.argv);
