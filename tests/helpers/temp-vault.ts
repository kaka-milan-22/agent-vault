import { mkdtempSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { initVault, setSecret } from "../../src/vault.js";

export function createTempVaultDir(): string {
  return mkdtempSync(join(tmpdir(), "agent-vault-test-"));
}

export function removeTempVaultDir(dir: string): void {
  rmSync(dir, { recursive: true, force: true });
}

/**
 * Pre-populate a vault directory with secrets, bypassing the CLI's TTY-gated
 * `set` command. Use this in e2e tests that need a vault to exist as the
 * fixture for testing `read` / `write` / `has` / `list` (the safe commands).
 *
 * Sensitive commands (set, get --reveal, rm, etc.) require an interactive TTY
 * and cannot be exercised end-to-end without a PTY; testing the underlying
 * vault library directly is the correct approach for those.
 */
export function setupVault(dir: string, secrets: Record<string, string>): void {
  const prev = process.env.AGENT_VAULT_DIR;
  process.env.AGENT_VAULT_DIR = dir;
  try {
    initVault();
    for (const [key, value] of Object.entries(secrets)) {
      setSecret(key, value);
    }
  } finally {
    if (prev === undefined) delete process.env.AGENT_VAULT_DIR;
    else process.env.AGENT_VAULT_DIR = prev;
  }
}

const CLI_PATH = resolve(import.meta.dirname, "../../dist/cli.js");

export function run(
  args: string[],
  opts?: {
    env?: Record<string, string>;
    input?: string;
    vaultDir: string;
  },
): { stdout: string; stderr: string; exitCode: number } {
  const result = spawnSync("node", [CLI_PATH, ...args], {
    env: {
      ...process.env,
      AGENT_VAULT_DIR: opts?.vaultDir,
      ...opts?.env,
    },
    input: opts?.input,
    encoding: "utf-8",
    timeout: 5000,
  });

  return {
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    exitCode: result.status ?? 1,
  };
}
