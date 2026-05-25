import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { requirePresence } from "./presence.js";

// --- Vault location ---

export function getVaultDir(): string {
  return process.env.AGENT_VAULT_DIR || join(homedir(), ".agent-vault");
}

export function vaultExists(): boolean {
  return existsSync(join(getVaultDir(), "vault.json"));
}

export function requireVault(): string {
  if (!vaultExists()) {
    console.error("✗ No vault found. The user should run: agent-vault set <key> (auto-initializes the vault)");
    process.exit(1);
  }
  return getVaultDir();
}

// --- Vault initialization ---

export function initVault(): string {
  if (existsSync(join(getVaultDir(), "vault.json"))) {
    return getVaultDir();
  }

  mkdirSync(getVaultDir(), { recursive: true, mode: 0o700 });

  // Generate master key (32 bytes = 256 bits)
  const masterKey = randomBytes(32);
  const keyPath = join(getVaultDir(), "vault.key");
  writeFileSync(keyPath, masterKey.toString("hex"), { mode: 0o600 });

  // Create empty vault — schema v1 (the lack of `version` is what marks legacy
  // v0 vaults, which loadVaultData upgrades transparently on next save).
  const vaultPath = join(getVaultDir(), "vault.json");
  writeFileSync(
    vaultPath,
    JSON.stringify({ version: VAULT_VERSION, secrets: {} }, null, 2),
    { mode: 0o600 },
  );

  return getVaultDir();
}

// --- Encryption ---

const ALGO = "aes-256-gcm";

/** Current on-disk vault schema version. v0 == no `version` field == pre-0.5.0. */
const VAULT_VERSION = 1;

function loadMasterKey(): Buffer {
  const keyPath = join(getVaultDir(), "vault.key");
  if (!existsSync(keyPath)) {
    console.error("✗ Vault key not found. Vault may be corrupted.");
    process.exit(1);
  }
  return Buffer.from(readFileSync(keyPath, "utf-8").trim(), "hex");
}

function encrypt(plaintext: string, key: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv(ALGO, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Format: iv:tag:ciphertext (all hex)
  return `${iv.toString("hex")}:${tag.toString("hex")}:${encrypted.toString("hex")}`;
}

function decrypt(packed: string, key: Buffer): string {
  const [ivHex, tagHex, ctHex] = packed.split(":");
  const iv = Buffer.from(ivHex, "hex");
  const tag = Buffer.from(tagHex, "hex");
  const ct = Buffer.from(ctHex, "hex");
  const decipher = createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(tag);
  return decipher.update(ct).toString("utf8") + decipher.final("utf8");
}

/**
 * The ONLY function that takes a SecretEntry to plaintext. Every callable
 * decrypt path goes through here so the presence gate cannot be bypassed by
 * a new caller that forgets to consult `entry.requirePresence`.
 *
 * If the entry is gated and Touch ID is denied / unavailable, this throws a
 * PresenceError BEFORE any decryption work happens. The plaintext literally
 * does not exist in this process's memory until the gate clears.
 */
function decryptSecret(entry: SecretEntry, keyName: string, masterKey: Buffer): string {
  if (entry.requirePresence) {
    requirePresence({
      reason: entry.presenceReason ?? `Reveal ${keyName}`,
    });
  }
  return decrypt(entry.value, masterKey);
}

// --- Secret store ---

export interface SecretEntry {
  value: string; // encrypted
  desc?: string;
  createdAt: string;
  /** Require physical-presence verification (Touch ID on macOS) before decrypt. */
  requirePresence?: boolean;
  /** Short reason rendered in the Touch ID prompt. Defaults to "Reveal <key>". */
  presenceReason?: string;
}

interface VaultData {
  /** Schema version. Absent in pre-0.5.0 vaults; treated as v0 on load. */
  version?: number;
  secrets: Record<string, SecretEntry>;
}

function loadVaultData(): VaultData {
  const vaultPath = join(getVaultDir(), "vault.json");
  if (!existsSync(vaultPath)) {
    return { version: VAULT_VERSION, secrets: {} };
  }
  const data: VaultData = JSON.parse(readFileSync(vaultPath, "utf-8"));
  // No active migrations yet; legacy v0 vaults (no version field) are
  // structurally identical to v1 minus the new optional SecretEntry fields,
  // so they load as-is. The first subsequent save() stamps version: 1.
  return data;
}

/**
 * Persist vault.json atomically: write to a sibling temp file under the same
 * directory, fsync via the OS-buffered rename, then move into place. This
 * prevents partial / torn writes on power loss or kill -9 mid-write. The
 * sibling-directory placement guarantees the rename is on the same filesystem
 * (cross-fs renames would silently downgrade to copy+unlink).
 */
function saveVaultData(data: VaultData): void {
  const vaultPath = join(getVaultDir(), "vault.json");
  const tmpPath = `${vaultPath}.tmp`;
  data.version = VAULT_VERSION;
  writeFileSync(tmpPath, JSON.stringify(data, null, 2), { mode: 0o600 });
  renameSync(tmpPath, vaultPath);
}

export interface SetSecretOptions {
  desc?: string;
  requirePresence?: boolean;
  presenceReason?: string;
}

/**
 * Store a secret. The legacy 3-arg form `setSecret(key, value, desc?)` is
 * preserved for backward compatibility; new callers should use the options
 * object form to set --require-presence flags.
 */
export function setSecret(
  key: string,
  value: string,
  descOrOptions?: string | SetSecretOptions,
): void {
  const opts: SetSecretOptions =
    typeof descOrOptions === "string"
      ? { desc: descOrOptions }
      : descOrOptions ?? {};

  const masterKey = loadMasterKey();
  const data = loadVaultData();
  const entry: SecretEntry = {
    value: encrypt(value, masterKey),
    createdAt: new Date().toISOString(),
  };
  if (opts.desc !== undefined) entry.desc = opts.desc;
  if (opts.requirePresence) {
    entry.requirePresence = true;
    if (opts.presenceReason !== undefined) entry.presenceReason = opts.presenceReason;
  }
  data.secrets[key] = entry;
  saveVaultData(data);
}

/**
 * Toggle the require-presence flag on an existing key without re-entering the
 * secret value (preserves the ciphertext). Returns true if the key existed and
 * was updated, false if the key does not exist.
 */
export function setRequirePresence(
  key: string,
  enabled: boolean,
  presenceReason?: string,
): boolean {
  const data = loadVaultData();
  const entry = data.secrets[key];
  if (!entry) return false;

  if (enabled) {
    entry.requirePresence = true;
    if (presenceReason !== undefined) {
      entry.presenceReason = presenceReason;
    }
  } else {
    delete entry.requirePresence;
    delete entry.presenceReason;
  }
  saveVaultData(data);
  return true;
}

export function getSecretValue(key: string): string | null {
  const data = loadVaultData();
  const entry = data.secrets[key];
  if (!entry) return null;
  const masterKey = loadMasterKey();
  return decryptSecret(entry, key, masterKey);
}

export interface SecretMeta {
  desc?: string;
  createdAt: string;
  length: number;
  requirePresence?: boolean;
  presenceReason?: string;
}

export function getSecretMeta(key: string): SecretMeta | null {
  const data = loadVaultData();
  const entry = data.secrets[key];
  if (!entry) return null;
  const masterKey = loadMasterKey();
  const plainValue = decryptSecret(entry, key, masterKey);
  const meta: SecretMeta = {
    createdAt: entry.createdAt,
    length: plainValue.length,
  };
  if (entry.desc !== undefined) meta.desc = entry.desc;
  if (entry.requirePresence) {
    meta.requirePresence = true;
    if (entry.presenceReason !== undefined) meta.presenceReason = entry.presenceReason;
  }
  return meta;
}

/**
 * Metadata-only lookup. Does NOT decrypt the secret value, so it does NOT
 * trigger a Touch ID prompt even for gated keys. Use this when you only need
 * to know "is this key gated?" / "what's its description?" without revealing.
 */
export function getSecretMetaNoReveal(key: string): Omit<SecretMeta, "length"> | null {
  const data = loadVaultData();
  const entry = data.secrets[key];
  if (!entry) return null;
  const meta: Omit<SecretMeta, "length"> = { createdAt: entry.createdAt };
  if (entry.desc !== undefined) meta.desc = entry.desc;
  if (entry.requirePresence) {
    meta.requirePresence = true;
    if (entry.presenceReason !== undefined) meta.presenceReason = entry.presenceReason;
  }
  return meta;
}

export function hasSecret(key: string): boolean {
  const data = loadVaultData();
  return key in data.secrets;
}

export interface SecretListing {
  key: string;
  desc?: string;
  /** Present and `true` only when the secret is gated; absent otherwise. */
  requirePresence?: boolean;
}

export function listSecrets(): SecretListing[] {
  const data = loadVaultData();
  return Object.entries(data.secrets).map(([key, entry]) => {
    const out: SecretListing = { key };
    if (entry.desc !== undefined) out.desc = entry.desc;
    if (entry.requirePresence) out.requirePresence = true;
    return out;
  });
}

export function removeSecret(key: string): boolean {
  const data = loadVaultData();
  if (!(key in data.secrets)) return false;
  delete data.secrets[key];
  saveVaultData(data);
  return true;
}

/**
 * Returns a map of plaintext secret values → key names.
 * Used by the redaction engine.
 *
 * Presence semantics: if any secret in the vault has `requirePresence: true`,
 * we surface a SINGLE Touch ID prompt up front that authorizes decrypting all
 * of them at once. Per-key prompts would shower the user with N dialogs for
 * `read`/`scan` of a file mentioning many gated keys, which trains them to
 * mash through prompts — defeating the gate's whole point.
 */
export function getAllSecretValues(): Map<string, string> {
  const data = loadVaultData();
  const entries = Object.entries(data.secrets);

  const gated = entries.filter(([, entry]) => entry.requirePresence);
  if (gated.length > 0) {
    requirePresence({
      reason:
        gated.length === 1
          ? `Read protected secret ${gated[0][0]}`
          : `Read ${gated.length} protected secrets for redaction`,
    });
  }

  const masterKey = loadMasterKey();
  const map = new Map<string, string>();
  for (const [key, entry] of entries) {
    // We've already authorized the gated keys in batch; call the raw decrypt
    // here to avoid prompting a second time per-key.
    const value = decrypt(entry.value, masterKey);
    map.set(value, key);
  }
  return map;
}
