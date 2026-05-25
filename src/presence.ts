// Physical-presence gate for per-key `--require-presence`.
//
// Spawns the platform helper binary (bin/agent-vault-presence on macOS, a
// Mach-O that drives the Touch ID API via LocalAuthentication.framework) and
// translates the exit code into a typed PresenceError. The helper is the
// ONLY code path that touches the Secure Enclave — this module is intentionally
// thin so the security-relevant surface stays in the signed/auditable helper.
//
// Why a child process and not a Node native module: agent-vault has zero
// native dependencies, and we want to keep `npm i -g @kaka-milan-22/agent-vault`
// a pure JavaScript install with no node-gyp / prebuilt-binary matrix in the
// hot path. The helper is a small, single-purpose Mach-O shipped in the
// tarball; this module pays one fork()/exec() per gated decrypt.
//
// Testing: set AGENT_VAULT_PRESENCE_BINARY to a script that exits with the
// desired status code. Tests must NEVER touch the real helper — that would
// pop a Touch ID dialog in CI / dev loops.

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { platform } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export type PresenceFailureReason =
  | "denied"               // user explicitly rejected or exceeded retry budget
  | "unavailable"          // sensor missing, SEP locked, policy unsupported
  | "platform-unsupported" // not running on macOS in v1
  | "helper-missing";      // bin/agent-vault-presence not packed/built

export class PresenceError extends Error {
  readonly reason: PresenceFailureReason;
  readonly helperStderr: string;

  constructor(reason: PresenceFailureReason, message: string, helperStderr = "") {
    super(message);
    this.name = "PresenceError";
    this.reason = reason;
    this.helperStderr = helperStderr;
  }
}

export interface PresenceOptions {
  /** Short, user-visible reason rendered in the Touch ID system prompt. */
  reason: string;
}

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Block until the user proves physical presence (Touch ID on macOS), or throw
 * PresenceError. macOS-only in v1; non-Darwin platforms fail-closed.
 *
 * Synchronous on purpose: the SEP prompt blocks the user anyway, and keeping
 * this sync avoids forcing every decrypt caller (read / write / scan / get)
 * to become async just for a feature most users will never enable.
 *
 * AGENT_VAULT_PRESENCE_BINARY env var override: when set, the platform check
 * is skipped (we trust the caller has provided a suitable helper, e.g. a test
 * mock or a future cross-platform helper like a polkit wrapper). This is NOT
 * a security regression — anyone able to set env vars in the user's shell can
 * already point the override at /bin/true to bypass the gate; the real
 * security boundary is the helper itself enforcing biometric verification.
 */
export function requirePresence(opts: PresenceOptions): void {
  const overrideBinary = process.env.AGENT_VAULT_PRESENCE_BINARY;

  if (!overrideBinary && platform() !== "darwin") {
    throw new PresenceError(
      "platform-unsupported",
      `Presence verification is currently macOS-only (current platform: ${platform()}). ` +
        `This vault contains secrets marked --require-presence; refusing to proceed.`,
    );
  }

  // dist/presence.js → ../bin/agent-vault-presence
  const helper =
    overrideBinary ?? join(__dirname, "..", "bin", "agent-vault-presence");

  if (!existsSync(helper)) {
    throw new PresenceError(
      "helper-missing",
      `Touch ID helper not found at ${helper}. ` +
        `Run: npm run build:native (requires macOS + Xcode Command Line Tools).`,
    );
  }

  const result = spawnSync(helper, [opts.reason], {
    stdio: ["ignore", "ignore", "pipe"],
    encoding: "utf-8",
    // No timeout: Touch ID UX expects the user to take seconds to respond and
    // a hard cap would mask "user is thinking" as a denial. The user can
    // cancel the system prompt to get a fast exit-1.
  });

  // spawnSync failure (e.g., ENOENT, EACCES) surfaces via result.error.
  if (result.error) {
    throw new PresenceError(
      "helper-missing",
      `Failed to spawn Touch ID helper: ${result.error.message}`,
    );
  }

  const status = result.status;
  const stderr = (result.stderr ?? "").trim();

  if (status === 0) return;

  if (status === 2) {
    throw new PresenceError(
      "unavailable",
      `Touch ID is not available on this device: ${stderr || "unknown reason"}`,
      stderr,
    );
  }

  // status === 1, null (signal), or any non-zero: treat as denial.
  throw new PresenceError(
    "denied",
    `Touch ID verification denied: ${stderr || "user canceled or authentication failed"}`,
    stderr,
  );
}
