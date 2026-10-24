import CryptoKit
import Foundation
import Security

// Wire protocol shared by the iPhone app, the Mac app, `fake-phone` and the Linux agent (linux/protocol.go).
// The iPhone POSTs JSON to <relay>/v1/m/<machineId>/{pair,hello,command}; the relay forwards it over the
// computer's outgoing WebSocket as a `RelayRequest` and returns the computer's `RelayResponse`.

public enum FaceUnlockProtocol {
    public static let version = 2
    public static let defaultRelay = URL(string: "https://faceunlock.dinkelworks.nl")!
    public static let urlScheme = "faceunlock"
    /// How long a challenge from `hello` can be used.
    public static let nonceLifetime: TimeInterval = 60
    /// How long the pairing QR code stays valid.
    public static let pairingLifetime: TimeInterval = 300
}

public enum Action: String, Codable, Sendable, CaseIterable {
    case unlock, lock, status
}

/// What the pairing QR code contains.
public struct PairingInvite: Codable, Equatable, Sendable {
    public var v: Int
    public var machineId: String
    public var machineName: String
    /// "macOS" or "linux".
    public var platform: String
    public var relay: URL
    public var token: String

    public init(machineId: String, machineName: String, platform: String, relay: URL, token: String) {
        self.v = FaceUnlockProtocol.version
        self.machineId = machineId
        self.machineName = machineName
        self.platform = platform
        self.relay = relay
        self.token = token
    }

    /// `faceunlock://pair?d=<base64url JSON>`, which the iPhone Camera app opens straight in FaceUnlock.
    public var url: URL {
        var components = URLComponents()
        components.scheme = FaceUnlockProtocol.urlScheme
        components.host = "pair"
        let json = (try? JSONEncoder().encode(self)) ?? Data()
        components.queryItems = [URLQueryItem(name: "d", value: json.base64URLEncodedString())]
        return components.url!
    }

    /// Accepts the pairing URL or just the code that follows `d=`.
    public init?(string: String) {
        var code = string.trimmingCharacters(in: .whitespacesAndNewlines)
        if let components = URLComponents(string: code), components.scheme == FaceUnlockProtocol.urlScheme {
            guard let value = components.queryItems?.first(where: { $0.name == "d" })?.value else { return nil }
            code = value
        }
        guard let data = Data(base64URLEncoded: code),
              let invite = try? JSONDecoder().decode(PairingInvite.self, from: data),
              invite.v == FaceUnlockProtocol.version
        else { return nil }
        self = invite
    }
}

public struct PairRequest: Codable, Sendable {
    public var deviceId: String
    public var deviceName: String
    /// Base64 X9.63 P-256 public key of the iPhone's signing key.
    public var publicKey: String
    /// See `PairingProof`.
    public var proof: String

    public init(deviceId: String, deviceName: String, publicKey: String, proof: String) {
        self.deviceId = deviceId
        self.deviceName = deviceName
        self.publicKey = publicKey
        self.proof = proof
    }

    /// Builds a request that proves knowledge of the QR code's token without sending it.
    public init(invite: PairingInvite, deviceId: String, deviceName: String, publicKey: Data) {
        let publicKey = publicKey.base64EncodedString()
        self.init(deviceId: deviceId, deviceName: deviceName, publicKey: publicKey,
                  proof: PairingProof.make(token: invite.token, machineId: invite.machineId, deviceId: deviceId,
                                           deviceName: deviceName, publicKey: publicKey))
    }
}

/// The pairing token only travels optically, in the QR code. Over the network the iPhone sends an HMAC of its
/// key keyed with the token, so neither the relay nor anyone else can learn the token or swap in their own key.
public enum PairingProof {
    public static func make(token: String, machineId: String, deviceId: String, deviceName: String, publicKey: String) -> String {
        let code = HMAC<SHA256>.authenticationCode(for: message(machineId, deviceId, deviceName, publicKey),
                                                   using: SymmetricKey(data: Data(token.utf8)))
        return Data(code).base64EncodedString()
    }

    public static func isValid(_ proof: String, token: String, machineId: String, deviceId: String, deviceName: String, publicKey: String) -> Bool {
        guard let code = Data(base64Encoded: proof) else { return false }
        return HMAC<SHA256>.isValidAuthenticationCode(code, authenticating: message(machineId, deviceId, deviceName, publicKey),
                                                      using: SymmetricKey(data: Data(token.utf8)))
    }

    private static func message(_ machineId: String, _ deviceId: String, _ deviceName: String, _ publicKey: String) -> Data {
        Data("faceunlock-pair/v1\n\(machineId)\n\(deviceId)\n\(deviceName)\n\(publicKey)".utf8)
    }
}

public struct PairResponse: Codable, Sendable {
    public var machineId: String
    public var machineName: String

    public init(machineId: String, machineName: String) {
        self.machineId = machineId
        self.machineName = machineName
    }
}

public struct HelloRequest: Codable, Sendable {
    public var deviceId: String

    public init(deviceId: String) {
        self.deviceId = deviceId
    }
}

public struct HelloResponse: Codable, Sendable {
    public var machineId: String
    public var machineName: String
    /// Single-use challenge the iPhone signs for its next command.
    public var nonce: String

    public init(machineId: String, machineName: String, nonce: String) {
        self.machineId = machineId
        self.machineName = machineName
        self.nonce = nonce
    }
}

public struct CommandRequest: Codable, Sendable {
    public var deviceId: String
    public var action: Action
    public var nonce: String
    /// Base64 raw (r‖s) ECDSA P-256 signature over `SignedMessage.bytes`.
    public var signature: String

    public init(deviceId: String, action: Action, nonce: String, signature: String) {
        self.deviceId = deviceId
        self.action = action
        self.nonce = nonce
        self.signature = signature
    }
}

public struct CommandResponse: Codable, Sendable, Equatable {
    public var ok: Bool
    public var locked: Bool
    public var message: String

    public init(ok: Bool, locked: Bool, message: String) {
        self.ok = ok
        self.locked = locked
        self.message = message
    }
}

public struct ErrorResponse: Codable, Sendable {
    public var error: String

    public init(error: String) {
        self.error = error
    }
}

/// A phone request as the relay hands it to the computer over its WebSocket. `body` is the JSON text.
public struct RelayRequest: Codable, Sendable {
    public var id: String
    public var path: String
    public var body: String
}

public struct RelayResponse: Codable, Sendable {
    public var id: String
    public var status: Int
    public var body: String

    public init(id: String, status: Int, body: String) {
        self.id = id
        self.status = status
        self.body = body
    }
}

public enum SignedMessage {
    /// The exact bytes the iPhone signs. Binding the computer, device and action means a signature can't be reused elsewhere.
    public static func bytes(machineId: String, deviceId: String, action: Action, nonce: String) -> Data {
        Data("faceunlock/v1\n\(machineId)\n\(deviceId)\n\(action.rawValue)\n\(nonce)".utf8)
    }
}

public func randomToken(byteCount: Int = 32) -> String {
    var bytes = [UInt8](repeating: 0, count: byteCount)
    let status = SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes)
    precondition(status == errSecSuccess, "SecRandomCopyBytes failed")
    return Data(bytes).base64URLEncodedString()
}

extension Data {
    public init?(base64URLEncoded string: String) {
        var base64 = string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        self.init(base64Encoded: base64)
    }

    public func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
