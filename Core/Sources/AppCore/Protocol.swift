import CryptoKit
import Foundation
import Security

// Wire protocol shared by the iPhone app, the Mac app, `fake-phone` and the Linux agent (linux/protocol.go).
// The iPhone POSTs JSON to <relay>/v1/m/<machineId>/{pair,hello,command}; the relay forwards it over the
// computer's outgoing WebSocket as a `RelayRequest` and returns the computer's `RelayResponse`.
//
// The "faceunlock…/v1" prefixes of signed messages and the pairing proof come from the app's first name. They're
// fixed protocol constants, not the app's name (that's `Brand`): changing them would break every pairing and the
// test vectors shared with linux/protocol_test.go.

public enum WireProtocol {
    public static let version = 2
    /// How long a challenge from `hello` can be used.
    public static let nonceLifetime: TimeInterval = 60
    /// How long the pairing QR code stays valid.
    public static let pairingLifetime: TimeInterval = 300
}

public enum Action: String, Codable, Sendable, CaseIterable {
    case unlock, lock, status
    /// Answers an `Approval`. Approving is signed with `ApprovalMessage`; denying isn't signed, since it only
    /// makes the computer ask for its password instead.
    case approve, deny
    /// Sets how long approvals wait for the iPhone (`ApprovalWait`, `CommandRequest.wait`), signed with `WaitMessage`.
    case setWait
}

/// How long sudo, polkit and the Mac's password dialogs wait for the iPhone before they ask for the password. Each
/// computer keeps its own (it's the source of truth) and hands it to its checker with every request; you set it there
/// or from the iPhone. It never decides an approval: the checker still verifies the iPhone's signature itself.
public enum ApprovalWait {
    /// In practice, until you approve, deny or give up at the computer (Enter or Ctrl-C).
    public static let untilAnswered = 24 * 60 * 60
    /// The waits you can choose, in seconds. The first is the default.
    public static let choices = [30, 60, 300, 900, untilAnswered]

    /// A request that waits longer than this shows no countdown: it's one that waits until you answer.
    public static func showsCountdown(until deadline: Date) -> Bool {
        deadline.timeIntervalSinceNow < 3600
    }

    public static func name(_ seconds: Int) -> String {
        switch seconds {
        case untilAnswered: "Until answered"
        case ..<60: "\(seconds) seconds"
        case 60: "1 minute"
        default: "\(seconds / 60) minutes"
        }
    }
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
    /// The computer keeps its password sealed to the iPhone (`PasswordSeal`), so pairing sends a password key too.
    public var wantsPasswordKey: Bool?

    public init(machineId: String, machineName: String, platform: String, relay: URL, token: String, wantsPasswordKey: Bool? = nil) {
        self.v = WireProtocol.version
        self.machineId = machineId
        self.machineName = machineName
        self.platform = platform
        self.relay = relay
        self.token = token
        self.wantsPasswordKey = wantsPasswordKey
    }

    /// `<Brand.urlScheme>://pair?d=<base64url JSON>`, which the iPhone Camera app opens straight in the app.
    public var url: URL {
        var components = URLComponents()
        components.scheme = Brand.urlScheme
        components.host = "pair"
        let json = (try? JSONEncoder().encode(self)) ?? Data()
        components.queryItems = [URLQueryItem(name: "d", value: json.base64URLEncodedString())]
        return components.url!
    }

    /// Accepts the pairing URL or just the code that follows `d=`.
    public init?(string: String) {
        var code = string.trimmingCharacters(in: .whitespacesAndNewlines)
        if let components = URLComponents(string: code), components.scheme == Brand.urlScheme {
            guard let value = components.queryItems?.first(where: { $0.name == "d" })?.value else { return nil }
            code = value
        }
        guard let data = Data(base64URLEncoded: code),
              let invite = try? JSONDecoder().decode(PairingInvite.self, from: data),
              invite.v == WireProtocol.version
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
    /// Base64 X9.63 P-256 public key of the iPhone's password key (`PasswordSeal`), when the invite asks for one.
    public var passwordKey: String?

    public init(deviceId: String, deviceName: String, publicKey: String, proof: String, passwordKey: String? = nil) {
        self.deviceId = deviceId
        self.deviceName = deviceName
        self.publicKey = publicKey
        self.proof = proof
        self.passwordKey = passwordKey
    }

    /// Builds a request that proves knowledge of the QR code's token without sending it.
    public init(invite: PairingInvite, deviceId: String, deviceName: String, publicKey: Data, passwordKey: Data? = nil) {
        let publicKey = publicKey.base64EncodedString()
        let passwordKey = passwordKey?.base64EncodedString()
        self.init(deviceId: deviceId, deviceName: deviceName, publicKey: publicKey,
                  proof: PairingProof.make(token: invite.token, machineId: invite.machineId, deviceId: deviceId,
                                           deviceName: deviceName, publicKey: publicKey, passwordKey: passwordKey),
                  passwordKey: passwordKey)
    }
}

/// The pairing token only travels optically, in the QR code. Over the network the iPhone sends an HMAC of its
/// key keyed with the token, so neither the relay nor anyone else can learn the token or swap in their own key.
/// With a password key, the proof covers it too (v2), so nobody can swap in their own.
public enum PairingProof {
    public static func make(token: String, machineId: String, deviceId: String, deviceName: String, publicKey: String,
                            passwordKey: String? = nil) -> String {
        let code = HMAC<SHA256>.authenticationCode(for: message(machineId, deviceId, deviceName, publicKey, passwordKey),
                                                   using: SymmetricKey(data: Data(token.utf8)))
        return Data(code).base64EncodedString()
    }

    public static func isValid(_ proof: String, token: String, machineId: String, deviceId: String, deviceName: String,
                               publicKey: String, passwordKey: String? = nil) -> Bool {
        guard let code = Data(base64Encoded: proof) else { return false }
        return HMAC<SHA256>.isValidAuthenticationCode(code, authenticating: message(machineId, deviceId, deviceName, publicKey, passwordKey),
                                                      using: SymmetricKey(data: Data(token.utf8)))
    }

    private static func message(_ machineId: String, _ deviceId: String, _ deviceName: String, _ publicKey: String,
                                _ passwordKey: String?) -> Data {
        guard let passwordKey, !passwordKey.isEmpty else {
            return Data("faceunlock-pair/v1\n\(machineId)\n\(deviceId)\n\(deviceName)\n\(publicKey)".utf8)
        }
        return Data("faceunlock-pair/v2\n\(machineId)\n\(deviceId)\n\(deviceName)\n\(publicKey)\n\(passwordKey)".utf8)
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
    /// The iPhone's push token (see `PushToken`), so the computer can notify it when it's waiting for an approval.
    /// nil leaves the saved token as it is; "" removes it.
    public var pushToken: String?
    /// The iPhone's lock screen card on the relay (see `RelayCard`), which the computer keeps up to date.
    /// nil leaves the saved one as it is; "" removes it.
    public var cardId: String?

    public init(deviceId: String, pushToken: String? = nil, cardId: String? = nil) {
        self.deviceId = deviceId
        self.pushToken = pushToken
        self.cardId = cardId
    }
}

public struct HelloResponse: Codable, Sendable {
    public var machineId: String
    public var machineName: String
    /// Single-use challenge the iPhone signs for its next command.
    public var nonce: String
    /// Whether the screen is locked; nil if the computer couldn't tell (or runs an older version).
    public var locked: Bool?
    /// What the computer is waiting for you to approve, such as a `sudo` command.
    public var approvals: [Approval]?
    /// The computer has no password key for this iPhone yet: send one with the next signed command.
    public var wantsPasswordKey: Bool?
    /// The computer keeps its password sealed to this iPhone; unlocking sends the key that opens it.
    public var sealedPassword: SealedPasswordChallenge?
    /// How long its approvals wait for the iPhone (`ApprovalWait`); nil from a computer that can't change it.
    public var approvalWait: Int?

    public init(machineId: String, machineName: String, nonce: String, locked: Bool? = nil, approvals: [Approval]? = nil,
                wantsPasswordKey: Bool? = nil, sealedPassword: SealedPasswordChallenge? = nil, approvalWait: Int? = nil) {
        self.machineId = machineId
        self.machineName = machineName
        self.nonce = nonce
        self.locked = locked
        self.approvals = approvals
        self.wantsPasswordKey = wantsPasswordKey
        self.sealedPassword = sealedPassword
        self.approvalWait = approvalWait
    }
}

/// What the iPhone needs to open a sealed password (`PasswordSeal`) for this challenge.
public struct SealedPasswordChallenge: Codable, Equatable, Sendable {
    /// Base64 X9.63 public half of the one-time key the password was sealed with.
    public var sealKey: String
    /// Base64 X9.63 public half of a one-time key the computer made for this challenge; the iPhone encrypts the
    /// sealed password's key to it.
    public var sessionKey: String

    public init(sealKey: String, sessionKey: String) {
        self.sealKey = sealKey
        self.sessionKey = sessionKey
    }
}

/// The key that opens a sealed password, encrypted to the challenge's `sessionKey`.
public struct WrappedKey: Codable, Equatable, Sendable {
    /// Base64 X9.63 public half of the iPhone's one-time key.
    public var key: String
    /// Base64 AES-GCM nonce ‖ ciphertext ‖ tag.
    public var box: String

    public init(key: String, box: String) {
        self.key = key
        self.box = box
    }
}

/// A password prompt on the computer (`sudo`, a polkit dialog) that waits for you to approve it on the iPhone.
/// The computer's root-owned checker creates it and checks the signature itself, so neither the relay nor
/// the Mac app or Linux agent in between can approve anything on its own.
public struct Approval: Codable, Equatable, Identifiable, Sendable {
    public var id: String
    /// What it's for, e.g. "sudo pacman -Syu".
    public var title: String
    /// Who's asking and where, e.g. "ruben on ttys003".
    public var detail: String
    /// Single-use challenge from the checker.
    public var nonce: String
    /// Seconds left before the computer stops waiting and asks for the password.
    public var expiresIn: Int

    public init(id: String, title: String, detail: String, nonce: String, expiresIn: Int) {
        self.id = id
        self.title = title
        self.detail = detail
        self.nonce = nonce
        self.expiresIn = expiresIn
    }
}

public struct CommandRequest: Codable, Sendable {
    public var deviceId: String
    public var action: Action
    public var nonce: String
    /// Base64 raw (r‖s) ECDSA P-256 signature over `SignedMessage.bytes`, or `ApprovalMessage.bytes` to approve.
    public var signature: String
    /// The `Approval` that `approve` and `deny` answer.
    public var approvalId: String?
    /// Registers the iPhone's password key when hello asked for it (`wantsPasswordKey`). Base64 X9.63.
    public var passwordKey: String?
    /// Opens the sealed password when hello sent a `sealedPassword` challenge.
    public var wrappedKey: WrappedKey?
    /// The approval wait that `setWait` sets, in seconds (`ApprovalWait`).
    public var wait: Int?

    public init(deviceId: String, action: Action, nonce: String, signature: String, approvalId: String? = nil,
                passwordKey: String? = nil, wrappedKey: WrappedKey? = nil, wait: Int? = nil) {
        self.deviceId = deviceId
        self.action = action
        self.nonce = nonce
        self.signature = signature
        self.approvalId = approvalId
        self.passwordKey = passwordKey
        self.wrappedKey = wrappedKey
        self.wait = wait
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

/// What the computer sends the relay over its WebSocket when it's waiting for an approval. The relay turns it
/// into "<machineName> is waiting for you" and pushes that to the iPhones through Apple's push service.
public struct RelayNotification: Codable, Sendable {
    public struct Notify: Codable, Sendable {
        public var machineName: String
        public var pushTokens: [String]
        /// Seconds until the request stops waiting, so Apple can still deliver to an iPhone that was offline.
        public var expiresIn: Int?
    }

    public var notify: Notify

    public init(machineName: String, pushTokens: [String], expiresIn: Int? = nil) {
        notify = Notify(machineName: machineName, pushTokens: pushTokens, expiresIn: expiresIn)
    }
}

/// What the computer sends the relay over its WebSocket for the iPhones' lock screen cards, whenever it changes:
/// whether it's locked and what's waiting for approval. The relay keeps the latest one for each card, combines the
/// computers on it and pushes the card to the iPhone through Apple's push service (a Live Activity).
public struct RelayCard: Codable, Equatable, Sendable {
    /// An `Approval` without its challenge, which the iPhone gets from the computer itself when it answers.
    public struct Waiting: Codable, Equatable, Sendable {
        public var id: String
        public var title: String
        public var detail: String
        public var expiresIn: Int

        public init(id: String, title: String, detail: String, expiresIn: Int) {
            self.id = id
            self.title = title
            self.detail = detail
            self.expiresIn = expiresIn
        }

        public init(_ approval: Approval) {
            self.init(id: approval.id, title: approval.title, detail: approval.detail, expiresIn: approval.expiresIn)
        }
    }

    public struct Card: Codable, Equatable, Sendable {
        /// The cards of the paired iPhones that have one (`CardId`).
        public var cards: [String]
        /// nil if the computer couldn't tell.
        public var locked: Bool?
        public var approvals: [Waiting]
    }

    public var card: Card

    public init(cards: [String], locked: Bool?, approvals: [Waiting]) {
        card = Card(cards: cards, locked: locked, approvals: approvals)
    }

    /// The same card apart from the seconds left on each request, which change all the time.
    public func isSame(as other: RelayCard) -> Bool {
        func stable(_ card: Card) -> Card {
            var card = card
            card.approvals = card.approvals.map { var waiting = $0; waiting.expiresIn = 0; return waiting }
            return card
        }
        return stable(card) == stable(other.card)
    }
}

/// A lock screen card's id on the relay: the SHA-256 (hex) of a secret only the iPhone knows, which it needs to
/// tell the relay where to push the card. The computers only get the id.
public enum CardId {
    public static func isValid(_ id: String) -> Bool {
        id.count == 64 && id.allSatisfy { $0.isASCII && $0.isHexDigit && !$0.isUppercase }
    }

    public static func of(secret: String) -> String {
        SHA256.hash(data: Data(secret.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}

public enum SignedMessage {
    /// The exact bytes the iPhone signs. Binding the computer, device and action means a signature can't be reused elsewhere.
    public static func bytes(machineId: String, deviceId: String, action: Action, nonce: String) -> Data {
        Data("faceunlock/v1\n\(machineId)\n\(deviceId)\n\(action.rawValue)\n\(nonce)".utf8)
    }

    /// Signed instead when the command carries a password key or a wrapped key (v2); without either it's the v1 bytes,
    /// which computers that don't seal their password expect. v2 also covers the challenge's session key, so the
    /// computer can tell the iPhone encrypted to its own key and not to one swapped in on the way. None of the fields
    /// can contain a line break (base64), so they can't shift.
    public static func bytes(machineId: String, deviceId: String, action: Action, nonce: String, sessionKey: String?,
                             passwordKey: String?, wrappedKey: WrappedKey?) -> Data {
        // An empty password key counts as none, as in linux/protocol.go.
        guard passwordKey?.isEmpty == false || wrappedKey != nil else {
            return bytes(machineId: machineId, deviceId: deviceId, action: action, nonce: nonce)
        }
        return Data(["faceunlock/v2", machineId, deviceId, action.rawValue, nonce, sessionKey ?? "", passwordKey ?? "",
                     wrappedKey?.key ?? "", wrappedKey?.box ?? ""].joined(separator: "\n").utf8)
    }
}

public enum WaitMessage {
    /// The exact bytes the iPhone signs to set the approval wait, so nothing in between can change the value.
    public static func bytes(machineId: String, deviceId: String, nonce: String, wait: Int) -> Data {
        Data("faceunlock-wait/v1\n\(machineId)\n\(deviceId)\n\(nonce)\n\(wait)".utf8)
    }
}

public enum ApprovalMessage {
    /// The exact bytes the iPhone signs to approve. They include what the iPhone showed, so if anything in between
    /// swapped the title or detail, the checker (which has its own copy) rejects the signature. The checker never
    /// puts line breaks in the title or detail, so the fields can't be shifted.
    public static func bytes(machineId: String, deviceId: String, approval: Approval) -> Data {
        Data("faceunlock-approve/v1\n\(machineId)\n\(deviceId)\n\(approval.id)\n\(approval.nonce)\n\(approval.title)\n\(approval.detail)".utf8)
    }
}

/// Notifications go through Apple's push service (APNs): the iPhone app gets a push token from Apple and gives it
/// to its computers in `hello`, and the relay sends the notification for them. It only says which computer is
/// waiting; the details travel over the relay when the app asks.
public enum PushToken {
    /// APNs tokens are hex (32 bytes today; Apple says they may grow), so a token can't smuggle anything else in.
    public static func isValid(_ token: String) -> Bool {
        (64...200).contains(token.count) && token.allSatisfy { $0.isASCII && $0.isHexDigit }
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
