import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { writeFileSync, readFileSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import {
  createTempVaultDir,
  removeTempVaultDir,
  run,
  setupVault,
} from "../helpers/temp-vault.js";

const MOCK_HELPER = resolve(import.meta.dirname, "../helpers/mock-presence.sh");

let vaultDir: string;
let workDir: string;
let logDir: string;
let logFile: string;

beforeEach(() => {
  vaultDir = createTempVaultDir();
  workDir = createTempVaultDir();
  logDir = mkdtempSync(join(tmpdir(), "agent-vault-presence-log-"));
  logFile = join(logDir, "calls.log");
});

afterEach(() => {
  removeTempVaultDir(vaultDir);
  removeTempVaultDir(workDir);
  rmSync(logDir, { recursive: true, force: true });
});

function presenceEnv(result: "0" | "1" | "2" = "0"): Record<string, string> {
  return {
    AGENT_VAULT_PRESENCE_BINARY: MOCK_HELPER,
    AGENT_VAULT_TEST_PRESENCE_RESULT: result,
    AGENT_VAULT_TEST_PRESENCE_LOG: logFile,
  };
}

function readLog(): string[] {
  if (!existsSync(logFile)) return [];
  return readFileSync(logFile, "utf-8")
    .split("\n")
    .filter((l) => l.length > 0);
}

/**
 * Insert a gated secret into the test vault using the library API directly.
 * The CLI `set` command is TTY-gated and cannot be driven from a test process,
 * so we set AGENT_VAULT_DIR scoped to this call to populate the vault.
 */
async function seedGatedSecret(
  dir: string,
  key: string,
  value: string,
  opts: { presenceReason?: string } = {},
): Promise<void> {
  const prev = process.env.AGENT_VAULT_DIR;
  process.env.AGENT_VAULT_DIR = dir;
  try {
    const { initVault, setSecret, vaultExists } = await import("../../src/vault.js");
    if (!vaultExists()) initVault();
    setSecret(key, value, { requirePresence: true, presenceReason: opts.presenceReason });
  } finally {
    if (prev === undefined) delete process.env.AGENT_VAULT_DIR;
    else process.env.AGENT_VAULT_DIR = prev;
  }
}

async function seedPlainSecret(dir: string, key: string, value: string): Promise<void> {
  const prev = process.env.AGENT_VAULT_DIR;
  process.env.AGENT_VAULT_DIR = dir;
  try {
    const { initVault, setSecret, vaultExists } = await import("../../src/vault.js");
    if (!vaultExists()) initVault();
    setSecret(key, value);
  } finally {
    if (prev === undefined) delete process.env.AGENT_VAULT_DIR;
    else process.env.AGENT_VAULT_DIR = prev;
  }
}

describe("agent-vault write — gated key", () => {
  it("prompts presence and substitutes when authorized", async () => {
    await seedGatedSecret(vaultDir, "my-token", "real-token-value-12345");

    const filePath = join(workDir, "out.yaml");
    const { stdout, exitCode } = run(
      ["write", filePath, "--content", "token: <agent-vault:my-token>"],
      { vaultDir, env: presenceEnv("0") },
    );
    expect(exitCode).toBe(0);
    expect(stdout).toContain("Written");
    const content = readFileSync(filePath, "utf-8");
    expect(content).toBe("token: real-token-value-12345");
    // Presence helper was called exactly once with the default reason.
    expect(readLog()).toEqual(["Reveal my-token"]);
  });

  it("uses custom presenceReason in helper argv", async () => {
    await seedGatedSecret(vaultDir, "wallet-mnemonic", "twelve word phrase value", {
      presenceReason: "Sign Ethereum transaction",
    });
    const filePath = join(workDir, "out.txt");
    const { exitCode } = run(
      ["write", filePath, "--content", "<agent-vault:wallet-mnemonic>"],
      { vaultDir, env: presenceEnv("0") },
    );
    expect(exitCode).toBe(0);
    expect(readLog()).toEqual(["Sign Ethereum transaction"]);
  });

  it("exits non-zero and refuses to write when presence is denied", async () => {
    await seedGatedSecret(vaultDir, "denied-token", "real-token-value-12345");
    const filePath = join(workDir, "out.yaml");
    const { exitCode, stderr } = run(
      ["write", filePath, "--content", "token: <agent-vault:denied-token>"],
      { vaultDir, env: presenceEnv("1") },
    );
    expect(exitCode).not.toBe(0);
    expect(stderr).toMatch(/denied|Touch ID/);
    // File must NOT have been written.
    expect(existsSync(filePath)).toBe(false);
  });

  it("exits non-zero with 'not available' when helper exits 2", async () => {
    await seedGatedSecret(vaultDir, "unavail-token", "real-token-value-12345");
    const filePath = join(workDir, "out.yaml");
    const { exitCode, stderr } = run(
      ["write", filePath, "--content", "token: <agent-vault:unavail-token>"],
      { vaultDir, env: presenceEnv("2") },
    );
    expect(exitCode).not.toBe(0);
    expect(stderr).toMatch(/not available|unavailable|Touch ID/);
  });

  it("does NOT prompt when only ungated keys are referenced", () => {
    setupVault(vaultDir, { plain: "plain-value-123456" });
    const filePath = join(workDir, "out.yaml");
    const { exitCode } = run(
      ["write", filePath, "--content", "k: <agent-vault:plain>"],
      { vaultDir, env: presenceEnv("0") },
    );
    expect(exitCode).toBe(0);
    expect(readLog()).toEqual([]);
  });
});

describe("agent-vault read — gated key in vault", () => {
  it("prompts once for redaction map covering multiple gated keys", async () => {
    await seedGatedSecret(vaultDir, "g1", "value-g1-12345678");
    await seedGatedSecret(vaultDir, "g2", "value-g2-12345678");
    await seedPlainSecret(vaultDir, "plain", "plain-value-12345");

    const filePath = join(workDir, "config.yaml");
    writeFileSync(
      filePath,
      "a: value-g1-12345678\nb: value-g2-12345678\nc: plain-value-12345\n",
    );

    const { stdout, exitCode } = run(["read", filePath], {
      vaultDir,
      env: presenceEnv("0"),
    });
    expect(exitCode).toBe(0);
    expect(stdout).toContain("<agent-vault:g1>");
    expect(stdout).toContain("<agent-vault:g2>");
    expect(stdout).not.toContain("value-g1-12345678");
    // Single prompt despite two gated keys.
    expect(readLog()).toHaveLength(1);
    expect(readLog()[0]).toMatch(/2 protected secrets/);
  });

  it("refuses to redact when presence denied (fail-closed)", async () => {
    await seedGatedSecret(vaultDir, "denied", "value-denied-12345");

    const filePath = join(workDir, "x.yaml");
    writeFileSync(filePath, "secret: value-denied-12345\n");

    const { exitCode, stderr, stdout } = run(["read", filePath], {
      vaultDir,
      env: presenceEnv("1"),
    });
    expect(exitCode).not.toBe(0);
    expect(stderr).toMatch(/denied|Touch ID/);
    // Critical fail-closed property: redacted output MUST NOT contain plaintext.
    expect(stdout).not.toContain("value-denied-12345");
  });
});

describe("agent-vault list — shows [presence] marker", () => {
  it("text output marks gated keys with [presence]", async () => {
    await seedPlainSecret(vaultDir, "plain", "value-plain-1234");
    await seedGatedSecret(vaultDir, "gated", "value-gated-1234");

    const { stdout } = run(["list"], { vaultDir, env: presenceEnv("0") });
    expect(stdout).toContain("plain");
    expect(stdout).toContain("gated  [presence]");
    expect(stdout).not.toContain("plain  [presence]");
    // list must NOT trigger presence at all (metadata only).
    expect(readLog()).toEqual([]);
  });

  it("JSON output exposes requirePresence: true only on gated entries", async () => {
    await seedPlainSecret(vaultDir, "plain", "value-plain-1234");
    await seedGatedSecret(vaultDir, "gated", "value-gated-1234");

    const { stdout } = run(["list", "--json"], { vaultDir, env: presenceEnv("0") });
    const result = JSON.parse(stdout);
    const plain = result.keys.find((k: { key: string }) => k.key === "plain");
    const gated = result.keys.find((k: { key: string }) => k.key === "gated");
    expect(plain).toBeDefined();
    expect(plain.requirePresence).toBeUndefined();
    expect(gated.requirePresence).toBe(true);
  });
});

describe("agent-vault has — never prompts", () => {
  it("returns true for gated key without triggering presence", async () => {
    await seedGatedSecret(vaultDir, "gated", "value-gated-1234");

    const { stdout, exitCode } = run(["has", "gated"], {
      vaultDir,
      env: presenceEnv("0"),
    });
    expect(stdout.trim()).toBe("true");
    expect(exitCode).toBe(0);
    expect(readLog()).toEqual([]);
  });
});
