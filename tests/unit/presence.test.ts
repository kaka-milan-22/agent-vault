import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { resolve } from "node:path";

const MOCK_HELPER = resolve(import.meta.dirname, "../helpers/mock-presence.sh");

// Dynamic import to pick up env vars + platform mocks each time
async function loadPresence() {
  return await import("../../src/presence.js");
}

describe("requirePresence", () => {
  let prevBinary: string | undefined;
  let prevResult: string | undefined;

  beforeEach(() => {
    prevBinary = process.env.AGENT_VAULT_PRESENCE_BINARY;
    prevResult = process.env.AGENT_VAULT_TEST_PRESENCE_RESULT;
  });

  afterEach(() => {
    if (prevBinary === undefined) delete process.env.AGENT_VAULT_PRESENCE_BINARY;
    else process.env.AGENT_VAULT_PRESENCE_BINARY = prevBinary;
    if (prevResult === undefined) delete process.env.AGENT_VAULT_TEST_PRESENCE_RESULT;
    else process.env.AGENT_VAULT_TEST_PRESENCE_RESULT = prevResult;
    vi.resetModules();
    vi.restoreAllMocks();
  });

  it("returns successfully when helper exits 0", async () => {
    process.env.AGENT_VAULT_PRESENCE_BINARY = MOCK_HELPER;
    process.env.AGENT_VAULT_TEST_PRESENCE_RESULT = "0";
    const { requirePresence } = await loadPresence();
    expect(() => requirePresence({ reason: "Test" })).not.toThrow();
  });

  it("throws PresenceError with reason='denied' when helper exits 1", async () => {
    process.env.AGENT_VAULT_PRESENCE_BINARY = MOCK_HELPER;
    process.env.AGENT_VAULT_TEST_PRESENCE_RESULT = "1";
    const { requirePresence, PresenceError } = await loadPresence();
    try {
      requirePresence({ reason: "Test denial" });
      expect.fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(PresenceError);
      expect((e as InstanceType<typeof PresenceError>).reason).toBe("denied");
    }
  });

  it("throws PresenceError with reason='unavailable' when helper exits 2", async () => {
    process.env.AGENT_VAULT_PRESENCE_BINARY = MOCK_HELPER;
    process.env.AGENT_VAULT_TEST_PRESENCE_RESULT = "2";
    const { requirePresence, PresenceError } = await loadPresence();
    try {
      requirePresence({ reason: "Test unavailable" });
      expect.fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(PresenceError);
      expect((e as InstanceType<typeof PresenceError>).reason).toBe("unavailable");
    }
  });

  it("throws PresenceError with reason='helper-missing' when binary path does not exist", async () => {
    process.env.AGENT_VAULT_PRESENCE_BINARY = "/tmp/this-binary-does-not-exist-agent-vault";
    const { requirePresence, PresenceError } = await loadPresence();
    try {
      requirePresence({ reason: "Test" });
      expect.fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(PresenceError);
      expect((e as InstanceType<typeof PresenceError>).reason).toBe("helper-missing");
    }
  });

  it("throws PresenceError with reason='platform-unsupported' on non-darwin (no override)", async () => {
    // Platform check is skipped when AGENT_VAULT_PRESENCE_BINARY is set, so
    // we must explicitly unset it to exercise the unsupported-platform path.
    delete process.env.AGENT_VAULT_PRESENCE_BINARY;
    vi.resetModules();
    vi.doMock("node:os", async () => {
      const actual = await vi.importActual<typeof import("node:os")>("node:os");
      return { ...actual, platform: () => "linux" };
    });
    const { requirePresence, PresenceError } = await loadPresence();
    try {
      requirePresence({ reason: "Test" });
      expect.fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(PresenceError);
      expect((e as InstanceType<typeof PresenceError>).reason).toBe("platform-unsupported");
    }
    vi.doUnmock("node:os");
  });

  it("passes the reason string to the helper as argv[1]", async () => {
    process.env.AGENT_VAULT_PRESENCE_BINARY = MOCK_HELPER;
    process.env.AGENT_VAULT_TEST_PRESENCE_RESULT = "1";
    const { requirePresence, PresenceError } = await loadPresence();
    try {
      requirePresence({ reason: "Sign Ethereum transaction" });
      expect.fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(PresenceError);
      // Mock script echoes the reason on stderr; the helperStderr field captures it.
      expect((e as InstanceType<typeof PresenceError>).helperStderr).toContain(
        "Sign Ethereum transaction",
      );
    }
  });
});
