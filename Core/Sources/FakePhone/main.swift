import CryptoKit
import AppCore
import Foundation

// A stand-in for the iPhone app, with a software key instead of the Secure Enclave and no Face ID.
// State lives in $FAKE_PHONE_STATE (default ~/.<Brand.id>-fake-phone.json). $FAKE_PHONE_RELAY overrides the
// relay from the pairing code, e.g. when the computer reaches the same local relay under another address.

struct State: Codable {
    var relay: URL
    var machineId: String
    var machineName: String
    var deviceId: String
    var privateKey: Data
    /// Raw software key-agreement key, for a computer that seals its password (`PasswordSeal`).
    var passwordKey: Data?

    var client: RelayClient {
        let relay = ProcessInfo.processInfo.environment["FAKE_PHONE_RELAY"].flatMap(URL.init(string:)) ?? relay
        return RelayClient(relay: relay, machineId: machineId)
    }
}

let statePath = ProcessInfo.processInfo.environment["FAKE_PHONE_STATE"]
    ?? (NSHomeDirectory() as NSString).appendingPathComponent(".\(Brand.id)-fake-phone.json")

func fail(_ message: String, code: Int32 = 1) -> Never {
    FileHandle.standardError.write(Data("error: \(message)\n".utf8))
    exit(code)
}

func loadState() -> State {
    guard let data = FileManager.default.contents(atPath: statePath),
          let state = try? JSONDecoder().decode(State.self, from: data)
    else { fail("not paired; run `fake-phone pair <code>` first") }
    return state
}

func save(_ state: State) throws {
    try JSONEncoder().encode(state).write(to: URL(fileURLWithPath: statePath), options: .atomic)
}

func describe(_ error: Error) -> String {
    (error as? LocalizedError)?.errorDescription ?? "\(error)"
}

/// Signs and sends `action` as the iPhone app does, including the password key and the wrapped key for a computer
/// that seals its password.
func send(_ action: Action, state: State, signingKey: P256.Signing.PrivateKey, reuseNonce: String? = nil) async throws -> (CommandResponse, String) {
    var state = state
    let hello = try await state.client.hello(deviceId: state.deviceId)
    let nonce = reuseNonce ?? hello.nonce
    var passwordKey: String?
    if hello.wantsPasswordKey == true {
        if state.passwordKey == nil {
            state.passwordKey = P256.KeyAgreement.PrivateKey().rawRepresentation
            try save(state)
        }
        passwordKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: state.passwordKey!).publicKey.x963Representation.base64EncodedString()
    }
    var wrappedKey: WrappedKey?
    if action == .unlock, let sealed = hello.sealedPassword, let sealKey = Data(base64Encoded: sealed.sealKey), let raw = state.passwordKey {
        let secret = try P256.KeyAgreement.PrivateKey(rawRepresentation: raw)
            .sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: sealKey))
        let key = PasswordSeal.passwordKey(sharedSecret: secret, sealKey: sealKey, machineId: state.machineId, deviceId: state.deviceId)
        wrappedKey = try PasswordSeal.wrap(key, sessionKey: sealed.sessionKey, machineId: state.machineId, deviceId: state.deviceId, nonce: nonce)
    }
    let message = SignedMessage.bytes(machineId: state.machineId, deviceId: state.deviceId, action: action, nonce: nonce,
                                      sessionKey: hello.sealedPassword?.sessionKey, passwordKey: passwordKey, wrappedKey: wrappedKey)
    let signature = try signingKey.signature(for: message).rawRepresentation
    let response = try await state.client.command(action, nonce: nonce, signature: signature, deviceId: state.deviceId,
                                                  passwordKey: passwordKey, wrappedKey: wrappedKey)
    return (response, nonce)
}

func printJSON(_ object: [String: Any]) {
    let data = try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    print(String(decoding: data, as: UTF8.self))
}

/// Asks hello until an approval is waiting (or `seconds` pass), like the app does when it opens.
func waitForApproval(state: State, seconds: Double) async throws -> Approval? {
    let deadline = Date().addingTimeInterval(seconds)
    repeat {
        if let approval = try await state.client.hello(deviceId: state.deviceId).approvals?.first { return approval }
        try await Task.sleep(nanoseconds: 250_000_000)
    } while Date() < deadline
    return nil
}

/// The value after `--name` in the arguments, if any.
func option(_ name: String) -> String? {
    guard let index = arguments.firstIndex(of: name), index + 1 < arguments.count else { return nil }
    return arguments[index + 1]
}

let arguments = Array(CommandLine.arguments.dropFirst())
let usage = """
usage: fake-phone pair <pairing-url-or-code> [--old-app]    # --old-app: without a password key
       fake-phone unlock | lock | status
       fake-phone hello [--push-token <hex>|--push-token ""]  # lock state and waiting approvals, no signature
       fake-phone approve [--wait <seconds>]                  # approves the first waiting request
       fake-phone approve-tampered [--wait <seconds>]         # signs a different command; must be rejected
       fake-phone deny [--wait <seconds>]
       fake-phone test-replay          # reuses a nonce; the computer must reject the second use
       fake-phone test-bad-signature   # signs with a different key; the computer must reject it
"""

switch arguments.first {
case "hello":
    let state = loadState()
    do {
        let hello = try await state.client.hello(deviceId: state.deviceId, pushToken: option("--push-token"))
        let approvals = (hello.approvals ?? []).map {
            ["id": $0.id, "title": $0.title, "detail": $0.detail, "expiresIn": $0.expiresIn] as [String: Any]
        }
        printJSON(["machineName": hello.machineName, "locked": hello.locked.map { $0 as Any } ?? NSNull(), "approvals": approvals])
    } catch {
        fail(describe(error))
    }

case "approve", "approve-tampered", "deny":
    let state = loadState()
    do {
        guard let approval = try await waitForApproval(state: state, seconds: Double(option("--wait") ?? "0") ?? 0) else {
            fail("nothing is waiting for approval")
        }
        let response: CommandResponse
        if arguments[0] == "deny" {
            response = try await state.client.deny(approval, deviceId: state.deviceId)
        } else {
            var signed = approval
            if arguments[0] == "approve-tampered" { signed.title = "sudo rm -rf /" }
            let key = try P256.Signing.PrivateKey(rawRepresentation: state.privateKey)
            let message = ApprovalMessage.bytes(machineId: state.machineId, deviceId: state.deviceId, approval: signed)
            response = try await state.client.approve(approval, signature: key.signature(for: message).rawRepresentation, deviceId: state.deviceId)
        }
        printJSON(["ok": response.ok, "title": approval.title, "message": response.message])
        exit(response.ok ? 0 : 1)
    } catch {
        fail(describe(error))
    }

case "pair":
    guard arguments.count >= 2, let invite = PairingInvite(string: arguments[1]) else { fail("invalid pairing code\n\(usage)", code: 64) }
    let key = P256.Signing.PrivateKey()
    // --old-app pairs like an app from before sealed passwords, without a password key.
    let passwordKey = invite.wantsPasswordKey == true && !arguments.contains("--old-app") ? P256.KeyAgreement.PrivateKey() : nil
    let deviceId = UUID().uuidString
    do {
        let client = ProcessInfo.processInfo.environment["FAKE_PHONE_RELAY"].flatMap(URL.init(string:))
            .map { RelayClient(relay: $0, machineId: invite.machineId) } ?? RelayClient(invite: invite)
        let response = try await client.pair(invite: invite, deviceId: deviceId, deviceName: "fake-phone",
                                             publicKey: key.publicKey.x963Representation,
                                             passwordKey: passwordKey?.publicKey.x963Representation)
        let state = State(relay: invite.relay, machineId: response.machineId, machineName: response.machineName,
                          deviceId: deviceId, privateKey: key.rawRepresentation, passwordKey: passwordKey?.rawRepresentation)
        try save(state)
        printJSON(["paired": true, "machineName": response.machineName, "platform": invite.platform, "relay": invite.relay.absoluteString])
    } catch {
        fail(describe(error))
    }

case "unlock", "lock", "status":
    let state = loadState()
    let action = Action(rawValue: arguments[0])!
    do {
        let key = try P256.Signing.PrivateKey(rawRepresentation: state.privateKey)
        let (response, _) = try await send(action, state: state, signingKey: key)
        printJSON(["ok": response.ok, "locked": response.locked, "message": response.message])
        exit(response.ok ? 0 : 1)
    } catch {
        fail(describe(error))
    }

case "test-replay":
    let state = loadState()
    do {
        let key = try P256.Signing.PrivateKey(rawRepresentation: state.privateKey)
        let (_, nonce) = try await send(.status, state: state, signingKey: key)
        do {
            _ = try await send(.status, state: state, signingKey: key, reuseNonce: nonce)
            fail("replayed nonce was accepted")
        } catch ClientError.server(let status, let message) {
            printJSON(["rejected": true, "status": status, "message": message])
        }
    } catch {
        fail(describe(error))
    }

case "test-bad-signature":
    let state = loadState()
    do {
        _ = try await send(.status, state: state, signingKey: P256.Signing.PrivateKey())
        fail("signature from an unpaired key was accepted")
    } catch ClientError.server(let status, let message) {
        printJSON(["rejected": true, "status": status, "message": message])
    } catch {
        fail(describe(error))
    }

default:
    fail(usage, code: 64)
}
