// agent-vault-presence — macOS Touch ID gate helper.
//
// Used by `agent-vault` to enforce per-key `--require-presence` policy:
// before any decrypt of a gated secret, this binary is spawned and blocks
// until the user authenticates via the Secure Enclave (Touch ID, or login
// password fallback). The result is communicated via exit code only — no
// plaintext crosses this process boundary.
//
// Exit codes:
//   0  user authenticated successfully
//   1  user denied / canceled / authentication failed
//   2  presence verification unavailable on this device
//
// Usage:
//   agent-vault-presence "<reason shown in the system prompt>"
//
// The reason string is rendered by macOS inside the native Touch ID dialog
// (e.g. "agent-vault wants to <reason>"). Keep it short and specific so the
// user can recognize what's being authorized.

import Foundation
import LocalAuthentication

let reasonArg = CommandLine.arguments.dropFirst().joined(separator: " ")
let reason = reasonArg.isEmpty ? "Access a protected secret" : reasonArg

let ctx = LAContext()
var capabilityError: NSError?

// `.deviceOwnerAuthentication` allows password fallback after biometric
// retries are exhausted (Apple-enforced UX). A future `--strict-biometric`
// option can switch to `.deviceOwnerAuthenticationWithBiometrics` for a
// password-fallback-free gate.
guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &capabilityError) else {
    let message = capabilityError?.localizedDescription ?? "policy unavailable"
    FileHandle.standardError.write("presence-unavailable: \(message)\n".data(using: .utf8)!)
    exit(2)
}

let sema = DispatchSemaphore(value: 0)
var ok = false
ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, evalError in
    ok = success
    if !success, let err = evalError {
        FileHandle.standardError.write("presence-denied: \(err.localizedDescription)\n".data(using: .utf8)!)
    }
    sema.signal()
}
sema.wait()

exit(ok ? 0 : 1)
