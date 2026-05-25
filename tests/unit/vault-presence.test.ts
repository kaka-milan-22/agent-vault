import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { existsSync, readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { createTempVaultDir, removeTempVaultDir } from "../helpers/temp-vault.js";

const MOCK_HELPER = resolve(import.meta.dirname, "../helpers/mock-presence.sh");

let tempDir: string;
let logDir: string;
let logFile: string;

beforeEach(() => {
  tempDir = createTempVaultDir();
  logDir = mkdtempSync(join(tmpdir(), "agent-vault-presence-log-"));
  logFile = join(logDir, "calls.log");
  process.env.AGENT_VAULT_DIR = tempDir;
  process.env.AGENT_VAULT_PRESENCE_BINARY = MOCK_HELPER;
  process.env.AGENT_VAULT_TEST_PRESENCE_LOG = logFile;
  process.env.AGENT_VAULT_TEST_PRESENCE_RESULT = "0";
});

afterEach(() => {
  delete process.env.AGENT_VAULT_DIR;
  delete process.env.AGENT_VAULT_PRESENCE_BINARY;
  delete process.env.AGENT_VAULT_TEST_PRESENCE_LOG;
  delete process.env.AGENT_VAULT_TEST_PRESENCE_RESULT;
  removeTempVaultDir(tempDir);
  rmSync(logDir, { recursive: true, force: true });
});

async function loadVault() {
  return await import("../../src/vault.js");
}

function readLog(): string[] {
  if (!existsSync(logFile)) return [];
  return readFileSync(logFile, "utf-8")
    .split("\n")
    .filter((l) => l.length > 0);
}

describe("setSecret API back-compat", () => {
  it("still accepts the legacy 3-arg form setSecret(key, value, desc)", async () => {
    const { initVault, setSecret, getSecretMetaNoReveal } = await loadVault();
    initVault();
    setSecret("legacy", "value-12345678", "my description");
    const meta = getSecretMetaNoReveal("legacy");
    expect(meta?.desc).toBe("my description");
    expect(meta?.requirePresence).toBeUndefined();
  });

  it("accepts options-object form", async () => {
    const { initVault, setSecret, getSecretMetaNoReveal } = await loadVault();
    initVault();
    setSecret("opts", "value-12345678", { desc: "from-opts", requirePresence: true });
    const meta = getSecretMetaNoReveal("opts");
    expect(meta?.desc).toBe("from-opts");
    expect(meta?.requirePresence).toBe(true);
  });

  it("preserves presenceReason when set", async () => {
    const { initVault, setSecret } = await loadVault();
    initVault();
    setSecret("reason-key", "value-12345678", {
      requirePresence: true,
      presenceReason: "Sign Ethereum transaction",
    });
    const data = JSON.parse(readFileSync(join(tempDir, "vault.json"), "utf-8"));
    expect(data.secrets["reason-key"].presenceReason).toBe("Sign Ethereum transaction");
  });
});

describe("decryptSecret gate", () => {
  it("getSecretValue does NOT prompt for ungated key", async () => {
    const { initVault, setSecret, getSecretValue } = await loadVault();
    initVault();
    setSecret("plain", "plain-value-123456");
    expect(getSecretValue("plain")).toBe("plain-value-123456");
    expect(readLog()).toEqual([]);
  });

  it("getSecretValue prompts for gated key", async () => {
    const { initVault, setSecret, getSecretValue } = await loadVault();
    initVault();
    setSecret("gated", "secret-value-12345", { requirePresence: true });
    expect(getSecretValue("gated")).toBe("secret-value-12345");
    expect(readLog()).toHaveLength(1);
  });

  it("getSecretValue uses presenceReason in the prompt argv", async () => {
    const { initVault, setSecret, getSecretValue } = await loadVault();
    initVault();
    setSecret("reasoned", "secret-value-12345", {
      requirePresence: true,
      presenceReason: "Custom reason text",
    });
    getSecretValue("reasoned");
    expect(readLog()).toEqual(["Custom reason text"]);
  });

  it("getSecretValue uses default 'Reveal <key>' when presenceReason is unset", async () => {
    const { initVault, setSecret, getSecretValue } = await loadVault();
    initVault();
    setSecret("default-reason", "secret-value-12345", { requirePresence: true });
    getSecretValue("default-reason");
    expect(readLog()).toEqual(["Reveal default-reason"]);
  });

  it("getSecretValue throws and does NOT decrypt when presence is denied", async () => {
    const { initVault, setSecret, getSecretValue } = await loadVault();
    initVault();
    setSecret("denied", "secret-value-12345", { requirePresence: true });
    process.env.AGENT_VAULT_TEST_PRESENCE_RESULT = "1";
    expect(() => getSecretValue("denied")).toThrow(/denied|Touch ID/);
  });

  it("getSecretValue throws 'unavailable' when helper exits 2", async () => {
    const { initVault, setSecret, getSecretValue } = await loadVault();
    initVault();
    setSecret("unavail", "secret-value-12345", { requirePresence: true });
    process.env.AGENT_VAULT_TEST_PRESENCE_RESULT = "2";
    expect(() => getSecretValue("unavail")).toThrow(/not available|unavailable|Touch ID/);
  });
});

describe("getSecretMetaNoReveal", () => {
  it("never prompts even for gated keys", async () => {
    const { initVault, setSecret, getSecretMetaNoReveal } = await loadVault();
    initVault();
    setSecret("gated", "secret-value-12345", { requirePresence: true });
    const meta = getSecretMetaNoReveal("gated");
    expect(meta?.requirePresence).toBe(true);
    expect(meta?.desc).toBeUndefined();
    expect(readLog()).toEqual([]);
    // Critical: must not expose length (would require decrypt)
    expect(meta).not.toHaveProperty("length");
  });

  it("returns null for missing key", async () => {
    const { initVault, getSecretMetaNoReveal } = await loadVault();
    initVault();
    expect(getSecretMetaNoReveal("nope")).toBeNull();
  });
});

describe("getSecretMeta (full, with decrypt)", () => {
  it("prompts for gated key when computing length", async () => {
    const { initVault, setSecret, getSecretMeta } = await loadVault();
    initVault();
    setSecret("gated", "exactly-12ch", { requirePresence: true });
    const meta = getSecretMeta("gated");
    expect(meta?.length).toBe(12);
    expect(readLog()).toHaveLength(1);
  });
});

describe("getAllSecretValues batch prompt", () => {
  it("does not prompt when no keys are gated", async () => {
    const { initVault, setSecret, getAllSecretValues } = await loadVault();
    initVault();
    setSecret("a", "value-a-12345678");
    setSecret("b", "value-b-12345678");
    const map = getAllSecretValues();
    expect(map.size).toBe(2);
    expect(readLog()).toEqual([]);
  });

  it("prompts exactly once for multiple gated keys", async () => {
    const { initVault, setSecret, getAllSecretValues } = await loadVault();
    initVault();
    setSecret("g1", "value-g1-12345678", { requirePresence: true });
    setSecret("g2", "value-g2-12345678", { requirePresence: true });
    setSecret("g3", "value-g3-12345678", { requirePresence: true });
    setSecret("plain", "plain-value-12345");
    const map = getAllSecretValues();
    expect(map.size).toBe(4);
    expect(readLog()).toHaveLength(1);
    // Reason should mention the count
    expect(readLog()[0]).toContain("3");
    expect(readLog()[0]).toContain("protected");
  });

  it("singular reason text for exactly one gated key", async () => {
    const { initVault, setSecret, getAllSecretValues } = await loadVault();
    initVault();
    setSecret("solo", "value-solo-12345", { requirePresence: true });
    getAllSecretValues();
    expect(readLog()).toEqual(["Read protected secret solo"]);
  });

  it("denial blocks all reads, not just gated ones", async () => {
    const { initVault, setSecret, getAllSecretValues } = await loadVault();
    initVault();
    setSecret("plain", "plain-value-12345");
    setSecret("gated", "secret-value-12345", { requirePresence: true });
    process.env.AGENT_VAULT_TEST_PRESENCE_RESULT = "1";
    expect(() => getAllSecretValues()).toThrow(/denied|Touch ID/);
  });
});

describe("setRequirePresence", () => {
  it("toggles the flag ON for an existing key without re-encrypting", async () => {
    const { initVault, setSecret, setRequirePresence } = await loadVault();
    initVault();
    setSecret("k", "original-value-123");
    const before = JSON.parse(readFileSync(join(tempDir, "vault.json"), "utf-8"));
    const cipherBefore = before.secrets.k.value;

    const ok = setRequirePresence("k", true, "My reason");
    expect(ok).toBe(true);

    const after = JSON.parse(readFileSync(join(tempDir, "vault.json"), "utf-8"));
    expect(after.secrets.k.requirePresence).toBe(true);
    expect(after.secrets.k.presenceReason).toBe("My reason");
    // Ciphertext untouched — flag flip didn't re-encrypt.
    expect(after.secrets.k.value).toBe(cipherBefore);
  });

  it("toggles the flag OFF and drops reason", async () => {
    const { initVault, setSecret, setRequirePresence } = await loadVault();
    initVault();
    setSecret("k", "value-12345678", { requirePresence: true, presenceReason: "reason" });

    const ok = setRequirePresence("k", false);
    expect(ok).toBe(true);

    const after = JSON.parse(readFileSync(join(tempDir, "vault.json"), "utf-8"));
    expect(after.secrets.k.requirePresence).toBeUndefined();
    expect(after.secrets.k.presenceReason).toBeUndefined();
  });

  it("returns false for a missing key", async () => {
    const { initVault, setRequirePresence } = await loadVault();
    initVault();
    expect(setRequirePresence("does-not-exist", true)).toBe(false);
  });
});

describe("listSecrets exposes requirePresence conditionally", () => {
  it("absent on plain entries", async () => {
    const { initVault, setSecret, listSecrets } = await loadVault();
    initVault();
    setSecret("plain", "value-12345678");
    const result = listSecrets();
    expect(result[0]).not.toHaveProperty("requirePresence");
  });

  it("present and true on gated entries", async () => {
    const { initVault, setSecret, listSecrets } = await loadVault();
    initVault();
    setSecret("gated", "value-12345678", { requirePresence: true });
    const result = listSecrets();
    expect(result[0].requirePresence).toBe(true);
  });
});

describe("vault schema v0 → v1 migration", () => {
  it("loads a legacy v0 vault (no `version` field) without error", async () => {
    const { initVault, listSecrets, setSecret } = await loadVault();
    initVault();
    setSecret("preexisting", "value-12345678");

    // Now manually strip the version field to simulate a pre-0.5.0 vault.
    const vaultPath = join(tempDir, "vault.json");
    const data = JSON.parse(readFileSync(vaultPath, "utf-8"));
    delete data.version;
    writeFileSync(vaultPath, JSON.stringify(data, null, 2));

    // listSecrets should still work
    const result = listSecrets();
    expect(result).toHaveLength(1);
    expect(result[0].key).toBe("preexisting");
  });

  it("stamps version: 1 on the next save after loading a v0 vault", async () => {
    const { initVault, setSecret } = await loadVault();
    initVault();
    setSecret("first", "value-12345678");

    // Strip version
    const vaultPath = join(tempDir, "vault.json");
    const stripped = JSON.parse(readFileSync(vaultPath, "utf-8"));
    delete stripped.version;
    writeFileSync(vaultPath, JSON.stringify(stripped, null, 2));

    // Now save anything new
    setSecret("second", "value-12345678");

    const after = JSON.parse(readFileSync(vaultPath, "utf-8"));
    expect(after.version).toBe(1);
    expect(after.secrets.first).toBeDefined();
    expect(after.secrets.second).toBeDefined();
  });

  it("fresh initVault stamps version: 1", async () => {
    const { initVault } = await loadVault();
    initVault();
    const data = JSON.parse(readFileSync(join(tempDir, "vault.json"), "utf-8"));
    expect(data.version).toBe(1);
  });
});

describe("atomic saveVaultData", () => {
  it("does not leave a .tmp file behind after a successful set", async () => {
    const { initVault, setSecret } = await loadVault();
    initVault();
    setSecret("k", "value-12345678");
    expect(existsSync(join(tempDir, "vault.json.tmp"))).toBe(false);
    expect(existsSync(join(tempDir, "vault.json"))).toBe(true);
  });
});
