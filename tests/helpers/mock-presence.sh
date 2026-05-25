#!/bin/sh
# Mock for bin/agent-vault-presence. Used by tests via AGENT_VAULT_PRESENCE_BINARY
# so e2e suites don't pop a real Touch ID dialog.
#
# Env vars:
#   AGENT_VAULT_TEST_PRESENCE_RESULT  exit code (default 0)
#   AGENT_VAULT_TEST_PRESENCE_LOG     if set, append the reason arg to this file
#                                     (one line per invocation, for call counting)
#
# $1 (the reason string) is also written to stderr so tests can assert on it
# directly via spawnSync's stderr capture.

if [ -n "${AGENT_VAULT_TEST_PRESENCE_LOG:-}" ]; then
    printf '%s\n' "$1" >> "$AGENT_VAULT_TEST_PRESENCE_LOG"
fi
echo "mock-presence reason: $1" >&2
exit "${AGENT_VAULT_TEST_PRESENCE_RESULT:-0}"
