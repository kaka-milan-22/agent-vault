import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createTempVaultDir, removeTempVaultDir, run, setupVault } from "../helpers/temp-vault.js";

let vaultDir: string;
let workDir: string;

beforeEach(() => {
  vaultDir = createTempVaultDir();
  workDir = createTempVaultDir();
});

afterEach(() => {
  removeTempVaultDir(vaultDir);
  removeTempVaultDir(workDir);
});

// --- init ---

describe("agent-vault init", () => {
  it("requires TTY", () => {
    // E2E tests run without TTY (piped), so init should fail
    const { exitCode, stderr } = run(["init"], { vaultDir });
    expect(exitCode).toBe(1);
    expect(stderr).toContain("TTY");
  });
});

// --- set ---
//
// All three set modes must refuse to run without a TTY — this is the
// structural guarantee that prevents an agent (with prompt injection or a
// misconfigured skill) from silently rewriting a vault secret to an
// attacker-known value. The e2e harness pipes stdin and stdout, so every
// call below correctly simulates the agent's Bash tool environment.

describe("agent-vault set — TTY enforcement", () => {
  it("interactive set requires TTY (stdin)", () => {
    const { exitCode, stderr } = run(["set", "k"], { vaultDir });
    expect(exitCode).toBe(1);
    expect(stderr).toContain("TTY");
  });

  it("--from-env requires TTY (stdin)", () => {
    const { exitCode, stderr } = run(["set", "my-key", "--from-env", "TEST_SECRET"], {
      vaultDir,
      env: { TEST_SECRET: "secret-value-12345678" },
    });
    expect(exitCode).toBe(1);
    expect(stderr).toContain("TTY");
  });

  it("--stdin requires TTY (stdout)", () => {
    const { exitCode, stderr } = run(["set", "my-key", "--stdin"], {
      vaultDir,
      input: "piped-secret-value-1234",
    });
    expect(exitCode).toBe(1);
    expect(stderr).toContain("TTY");
  });

  it("--stdin --force still requires TTY (--force does not bypass the TTY gate)", () => {
    setupVault(vaultDir, { "my-key": "existing-value-1234" });
    const { exitCode, stderr } = run(["set", "my-key", "--stdin", "--force"], {
      vaultDir,
      input: "new-value-1234567890",
    });
    expect(exitCode).toBe(1);
    expect(stderr).toContain("TTY");
  });

  it("TTY gate fires before any other validation (key format)", () => {
    // Without a TTY, the command must refuse before validating the key —
    // any earlier exit would leak information about vault state to the agent.
    const { exitCode, stderr } = run(["set", "INVALID_KEY", "--from-env", "X"], {
      vaultDir,
      env: { X: "anything" },
    });
    expect(exitCode).toBe(1);
    expect(stderr).toContain("TTY");
  });
});

// --- get ---

describe("agent-vault get", () => {
  it("requires TTY", () => {
    setupVault(vaultDir, { k: "val-12345678901234" });
    const { exitCode, stderr } = run(["get", "k"], { vaultDir });
    expect(exitCode).toBe(1);
    expect(stderr).toContain("TTY");
  });

  it("exits 1 for missing vault", () => {
    const emptyVault = createTempVaultDir();
    const { exitCode } = run(["get", "k"], { vaultDir: emptyVault });
    expect(exitCode).toBe(1);
    removeTempVaultDir(emptyVault);
  });
});

// --- rm ---

describe("agent-vault rm", () => {
  it("requires TTY", () => {
    setupVault(vaultDir, { k: "val-12345678901234" });
    const { exitCode, stderr } = run(["rm", "k"], { vaultDir });
    expect(exitCode).toBe(1);
    expect(stderr).toContain("TTY");
  });
});

// --- import ---

describe("agent-vault import", () => {
  it("requires TTY", () => {
    const envFile = join(workDir, ".env");
    writeFileSync(envFile, "KEY=value-12345678901234\n");
    const { exitCode, stderr } = run(["import", envFile], { vaultDir });
    expect(exitCode).toBe(1);
    expect(stderr).toContain("TTY");
  });

  it("exits 1 for missing file", () => {
    const { exitCode, stderr } = run(["import", "/nonexistent/.env"], { vaultDir });
    expect(exitCode).toBe(1);
    // Either TTY error or file not found — TTY check comes first
    expect(stderr).toContain("TTY");
  });
});

// --- scan ---

describe("agent-vault scan", () => {
  it("requires TTY", () => {
    const filePath = join(workDir, "config.yaml");
    writeFileSync(filePath, "port: 3000\n");
    const { exitCode, stderr } = run(["scan", filePath], { vaultDir });
    expect(exitCode).toBe(1);
    expect(stderr).toContain("TTY");
  });
});

// --- Integration: write/read round-trip ---
//
// The CLI's `set` command is TTY-gated and cannot be exercised end-to-end
// without a PTY, so these tests pre-populate the vault via setupVault() and
// then exercise the SAFE commands (write, read) that don't require a TTY.

describe("e2e round-trip", () => {
  it("write → read preserves secrets correctly with redaction", () => {
    setupVault(vaultDir, { "api-key": "sk-proj-myrealsecretkey12345678" });

    const filePath = join(workDir, "config.yaml");
    run(
      [
        "write",
        filePath,
        "--content",
        "api_key: <agent-vault:api-key>\nport: 8080",
      ],
      { vaultDir },
    );

    const fileContent = readFileSync(filePath, "utf-8");
    expect(fileContent).toBe("api_key: sk-proj-myrealsecretkey12345678\nport: 8080");

    const { stdout } = run(["read", filePath], { vaultDir });
    expect(stdout).toContain("<agent-vault:api-key>");
    expect(stdout).not.toContain("sk-proj-myrealsecretkey12345678");
    expect(stdout).toContain("port: 8080");
  });

  it("multiple secrets in a single file round-trip", () => {
    setupVault(vaultDir, {
      "key-a": "secret-aaa-12345678901",
      "key-b": "secret-bbb-12345678901",
    });

    const filePath = join(workDir, "multi.env");
    run(
      [
        "write",
        filePath,
        "--content",
        "A=<agent-vault:key-a>\nB=<agent-vault:key-b>\nC=plain",
      ],
      { vaultDir },
    );

    const content = readFileSync(filePath, "utf-8");
    expect(content).toBe("A=secret-aaa-12345678901\nB=secret-bbb-12345678901\nC=plain");

    const { stdout } = run(["read", filePath], { vaultDir });
    expect(stdout).toContain("<agent-vault:key-a>");
    expect(stdout).toContain("<agent-vault:key-b>");
    expect(stdout).toContain("C=plain");
  });

  it("short vault values are redacted (regression test for Vuln 2)", () => {
    // Prior versions skipped values < 8 chars in Phase 1, leaking short
    // PINs and tokens verbatim. After the fix, any vaulted value — no
    // matter how short — must be substituted by `read`.
    setupVault(vaultDir, { "otp-pin": "482917" });

    const filePath = join(workDir, "iot.yaml");
    writeFileSync(filePath, "pin: 482917\nbroker: 10.0.0.5\n");

    const { stdout } = run(["read", filePath], { vaultDir });
    expect(stdout).toContain("<agent-vault:otp-pin>");
    expect(stdout).not.toContain("482917");
    expect(stdout).toContain("10.0.0.5");
  });
});
