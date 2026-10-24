import CryptoKit
import FaceUnlockCore
import Foundation

// A stand-in for the iPhone app, with a software key instead of the Secure Enclave and no Face ID.
// State lives in $FAKE_PHONE_STATE (default ~/.faceunlock-fake-phone.json).

struct State: Codable {
    var relay: URL
    var machineId: String
    var machineName: String
    var deviceId: String
    var privateKey: Data

    var client: RelayClient { RelayClient(relay: relay, machineId: machineId) }
}

let statePath = ProcessInfo.processInfo.environment["FAKE_PHONE_STATE"]
    ?? (NSHomeDirectory() as NSString).appendingPathComponent(".faceunlock-fake-phone.json")

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

func describe(_ error: Error) -> String {
    (error as? LocalizedError)?.errorDescription ?? "\(error)"
}

func send(_ action: Action, state: State, signingKey: P256.Signing.PrivateKey, reuseNonce: String? = nil) async throws -> (CommandResponse, String) {
    let hello = try await state.client.hello(deviceId: state.deviceId)
    let nonce = reuseNonce ?? hello.nonce
    let message = SignedMessage.bytes(machineId: state.machineId, deviceId: state.deviceId, action: action, nonce: nonce)
    let signature = try signingKey.signature(for: message).rawRepresentation
    let response = try await state.client.command(action, nonce: nonce, signature: signature, deviceId: state.deviceId)
    return (response, nonce)
}

func printJSON(_ object: [String: Any]) {
    let data = try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    print(String(decoding: data, as: UTF8.self))
}

let arguments = Array(CommandLine.arguments.dropFirst())
let usage = """
usage: fake-phone pair <pairing-url-or-code>
       fake-phone unlock | lock | status
       fake-phone test-replay          # reuses a nonce; the computer must reject the second use
       fake-phone test-bad-signature   # signs with a different key; the computer must reject it
"""

switch arguments.first {
case "pair":
    guard arguments.count == 2, let invite = PairingInvite(string: arguments[1]) else { fail("invalid pairing code\n\(usage)", code: 64) }
    let key = P256.Signing.PrivateKey()
    let deviceId = UUID().uuidString
    do {
        let response = try await RelayClient(invite: invite).pair(invite: invite, deviceId: deviceId, deviceName: "fake-phone",
                                                                  publicKey: key.publicKey.x963Representation)
        let state = State(relay: invite.relay, machineId: response.machineId, machineName: response.machineName,
                          deviceId: deviceId, privateKey: key.rawRepresentation)
        try JSONEncoder().encode(state).write(to: URL(fileURLWithPath: statePath), options: .atomic)
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
