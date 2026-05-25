# Physical Presence Verification (macOS Touch ID)

Some secrets are too sensitive to decrypt just because *something* with your
user ID asked nicely. A LLM agent under prompt injection, a compromised npm
postinstall script, a malicious VS Code extension, an `os.execve` from any
process with your UID — by default, any of them can ask agent-vault for the
plaintext of any stored secret and get it. The encryption-at-rest of the vault
file protects against **someone else** having your laptop; it does not protect
against **untrusted code already running as you**.

`--require-presence` raises the bar. When a secret is marked with this flag,
**every decrypt of that secret blocks on a macOS Touch ID system prompt**. The
biometric check runs in the Secure Enclave Processor (SEP), which user-space
code cannot subvert: there is no API that bypasses the prompt, no way to
auto-confirm, no way to silence it. The attacker has to either physically be
at your laptop touching the sensor, or wait until you do.

This is the highest-value mitigation available without buying a hardware
wallet. It does not replace one — see [Limitations](#limitations) below — but
for the typical hot-key threat (LLM agent + supply chain), it converts "any
code running as you can exfiltrate" into "any code running as you must trick
you into pressing your finger right now."

## Usage

```bash
# Enable when first storing the secret
agent-vault set wallet/mnemonic --require-presence \
    --reason "Sign Ethereum transaction"

# Or toggle on/off later without re-entering the secret
agent-vault require-presence wallet/mnemonic --on \
    --reason "Sign Ethereum transaction"
agent-vault require-presence wallet/mnemonic --off

# Inspect: gated keys are marked [presence] in list output
agent-vault list
# wallet/mnemonic  [presence]
# my-openai-key
```

The `--reason` string is rendered verbatim by macOS inside the Touch ID
dialog as *"agent-vault wants to {reason}"*. Pick something short and
specific to the operation — `"Sign Ethereum transaction"` beats `"Access
secret"`. If omitted, the default is `"Reveal {key}"`.

## What triggers a prompt

| Operation | Prompts for gated key? |
|---|---|
| `agent-vault has gated-key` | No (metadata-only) |
| `agent-vault list` | No (metadata-only) |
| `agent-vault get gated-key` (no `--reveal`) | No (metadata-only) |
| `agent-vault get gated-key --reveal` | **Yes** |
| `agent-vault write <file> --content "<agent-vault:gated-key>"` | **Yes** |
| `agent-vault read <file>` (file mentions gated value) | **Yes** (one prompt for all gated keys in this read) |
| `agent-vault scan <file>` | **Yes** (same batch semantics as `read`) |
| `agent-vault set gated-key ...` (overwrite) | No (overwrite replaces ciphertext, doesn't expose old plaintext) |
| `agent-vault rm gated-key` | No (delete doesn't decrypt) |
| `agent-vault require-presence gated-key --off` | No (flag flip doesn't decrypt) |

The `read` / `scan` batch semantics are deliberate: prompting once per gated
key in a file with several would train users to mash-tap through prompts,
defeating the gate. One prompt up front authorizes the whole read.

## Failure semantics

When Touch ID is denied, unavailable, or the helper binary can't be spawned,
the operation fails-closed: **no plaintext crosses the boundary**, the command
exits non-zero, and stderr explains why.

Exit-code behavior of the helper binary:

| Helper exit | Meaning | What agent-vault does |
|---|---|---|
| `0` | User authenticated | Proceeds to decrypt |
| `1` | User canceled, wrong finger ×5+, or auth failed | Throws `PresenceError(reason="denied")`, exit 1 |
| `2` | Sensor unavailable, SEP locked, policy unsupported | Throws `PresenceError(reason="unavailable")`, exit 1 |

On non-macOS platforms (Linux, Windows) the gate fails-closed with
`reason="platform-unsupported"`. Future versions may add `pam_u2f` on Linux
and Windows Hello support; the per-key flag is named `--require-presence`
rather than `--require-touch-id` to keep the API stable across that change.

The Touch ID dialog allows password fallback after biometric retries are
exhausted (Apple-enforced UX). A future `--strict-biometric-only` mode will
disable this — see [v2 roadmap](#v2-roadmap).

## Limitations

The gate raises the bar significantly. It does not raise it to "hardware
wallet" level. Be honest with yourself about what it does and doesn't cover.

**Not defended against:**

- **Binary replacement.** An attacker with write access to your homebrew /
  npm install dir can replace `bin/agent-vault-presence` with a shim that
  `exit 0`s without ever touching the SEP. v1 ships unsigned. v2 will codesign
  with an Apple Developer ID Application certificate and verify on every call,
  which makes this attack visible to Gatekeeper.
- **Process memory dump.** After a successful Touch ID, the plaintext lives
  briefly in agent-vault's V8 heap. A same-UID attacker with `vmmap` / `lldb`
  attached at exactly that moment can extract it. The window is short (one
  operation) but non-zero.
- **Touch ID fallback to login password.** Five failed biometric attempts
  fall through to a password prompt. If your account password is weak or
  recently typed somewhere observable, the gate degrades.
- **Prompt blindness.** Users trained to tap-and-forget on every system
  dialog (Touch ID for sudo, autofill, lock screen, etc.) defeat the gate by
  reflex. The `--reason` string is your only signal — make it specific enough
  that an unexpected prompt looks wrong.
- **Same-process compromise.** If the agent-vault Node process itself is
  compromised (e.g. via a malicious dependency in the dependency tree),
  bypassing the gate is trivial. agent-vault's tiny dependency surface
  (`commander` only) limits this, but does not eliminate it.

**Defended against:**

- Prompt-injected LLM agents running `agent-vault read` to exfiltrate.
- Supply-chain compromised packages that quietly call `agent-vault read`
  in a postinstall hook.
- Any non-interactive process under your UID trying to access gated secrets
  without a human pressing the sensor.
- Stolen vault file alone (encryption-at-rest still applies).

If you're holding meaningful funds, **the right tool is a hardware wallet**.
Touch ID gating is for the layer below that — the threshold where "a vault
file with file-permissions protection" stops being enough but "every
operation requires a device" is excessive friction.

## How it works (under the hood)

The flag is a per-secret boolean stored in `~/.agent-vault/vault.json`:

```json
{
  "version": 1,
  "secrets": {
    "wallet/mnemonic": {
      "value": "iv:tag:ciphertext",
      "createdAt": "2026-05-25T00:00:00.000Z",
      "requirePresence": true,
      "presenceReason": "Sign Ethereum transaction"
    }
  }
}
```

The flag is plaintext metadata (visible to anyone who reads `vault.json`),
which means an attacker can see *which* keys are gated. That's an information
leak about value, not about content — they can tell you have something worth
protecting, but cannot extract it without the gate.

Inside agent-vault, every decrypt path funnels through a single function in
`src/vault.ts`:

```typescript
function decryptSecret(entry: SecretEntry, keyName: string, masterKey: Buffer): string {
  if (entry.requirePresence) {
    requirePresence({ reason: entry.presenceReason ?? `Reveal ${keyName}` });
  }
  return decrypt(entry.value, masterKey);
}
```

`requirePresence` spawns `bin/agent-vault-presence`, a small Swift Mach-O
binary that calls `LAContext.evaluatePolicy(.deviceOwnerAuthentication, ...)`
and exits with status 0/1/2. The helper is the only code that touches the
SEP API; the TypeScript side just reads the exit code.

The helper does not communicate plaintext — it only signals "user is
present" via exit code. The plaintext flows the normal AES-GCM route inside
Node, gated on the helper's go-ahead.

## Testing your setup

```bash
# 1. Set a gated secret
agent-vault set test-gated --require-presence --reason "Test gate"

# 2. Try to write a file using it
agent-vault write /tmp/out.txt --content "<agent-vault:test-gated>"
# → Touch ID dialog appears: "agent-vault wants to Test gate"
# → Approve with fingerprint
# → /tmp/out.txt contains the real value

# 3. Try again, cancel the prompt this time
agent-vault write /tmp/out.txt --content "<agent-vault:test-gated>"
# → Touch ID dialog appears
# → Hit Cancel
# → exit code 1, stderr: "Touch ID verification denied"
# → /tmp/out.txt is NOT overwritten with the secret

# 4. Clean up
agent-vault rm test-gated
```

## v2 Roadmap

Not in v1, planned for follow-up releases:

- **Codesigning the helper binary** with an Apple Developer ID — closes the
  binary-replacement gap above.
- **`--strict-biometric-only`** mode — disables password fallback.
- **Audit log** at `~/.agent-vault/presence.log` — one line per prompt event
  with timestamp, key, and outcome. Useful for spotting prompts that fired
  when you weren't expecting them.
- **Linux support** via `pam_u2f` (YubiKey) or `polkit` (interactive
  desktop). The `--require-presence` API is already platform-neutral.
- **Windows support** via Windows Hello.
- **Optional grace period** per key — `--presence-ttl 300` for less
  sensitive secrets that need to survive a 5-minute test loop without 50
  prompts.
- **`agent-vault presence-status`** subcommand — show which keys are gated,
  recent access times, last denial.
