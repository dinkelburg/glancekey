import CryptoKit
import Foundation

public struct PairedDevice: Codable, Identifiable, Equatable, Sendable {
    public var id: String
    public var name: String
    /// X9.63 P-256 public key.
    public var publicKey: Data
    public var pairedAt: Date
    public var lastUsedAt: Date?
    /// ntfy topic to notify when an approval is waiting (see `Notifications`).
    public var notifyTopic: String?

    public init(id: String, name: String, publicKey: Data, pairedAt: Date, lastUsedAt: Date? = nil, notifyTopic: String? = nil) {
        self.id = id
        self.name = name
        self.publicKey = publicKey
        self.pairedAt = pairedAt
        self.lastUsedAt = lastUsedAt
        self.notifyTopic = notifyTopic
    }

    /// Checks the iPhone's signature over `message` with its paired key.
    public func isValidSignature(_ signature: String, for message: Data) -> Bool {
        guard let key = try? P256.Signing.PublicKey(x963Representation: publicKey),
              let data = Data(base64Encoded: signature),
              let signature = try? P256.Signing.ECDSASignature(rawRepresentation: data)
        else { return false }
        return key.isValidSignature(signature, for: message)
    }
}

public enum AuthError: Error, Equatable, CustomStringConvertible {
    case noPairingInProgress
    case pairingExpired
    case badPairingToken
    case badDeviceInfo
    case badPublicKey
    case unknownDevice
    case unknownNonce
    case expiredNonce
    case badSignature
    case approvalGone

    public var description: String {
        switch self {
        case .noPairingInProgress: "Pairing isn't active. Start pairing on your computer first."
        case .pairingExpired: "That pairing code expired. Start pairing again on your computer."
        case .badPairingToken: "That pairing code isn't valid. Scan the code your computer is showing now."
        case .badDeviceInfo: "The iPhone sent invalid device details."
        case .badPublicKey: "The iPhone sent an invalid key."
        case .unknownDevice: "This iPhone isn't paired with that computer anymore. Pair it again."
        case .unknownNonce: "The request was out of date. Try again."
        case .expiredNonce: "The request took too long. Try again."
        case .badSignature: "The computer rejected this iPhone's signature."
        case .approvalGone: "That request isn't waiting anymore."
        }
    }
}

/// The computer's security checks: pairing codes, single-use challenges and signature verification.
/// Not thread-safe; the Mac app only uses it from the main actor (the Linux agent has its own Go version).
public final class Authenticator {
    public let machineId: String
    private let now: () -> Date
    private var pairing: (token: String, expires: Date)?
    private var nonces: [String: (deviceId: String, expires: Date)] = [:]

    static let maxOutstandingNonces = 64

    public init(machineId: String, now: @escaping () -> Date = Date.init) {
        self.machineId = machineId
        self.now = now
    }

    public var pairingExpiresAt: Date? { pairing?.expires }

    /// Starts a pairing window and returns the one-time token to put in the QR code.
    public func startPairing() -> String {
        let token = randomToken(byteCount: 16)
        pairing = (token, now().addingTimeInterval(FaceUnlockProtocol.pairingLifetime))
        return token
    }

    public func cancelPairing() {
        pairing = nil
    }

    public func completePairing(_ request: PairRequest) throws -> PairedDevice {
        guard let pairing else { throw AuthError.noPairingInProgress }
        guard pairing.expires > now() else {
            self.pairing = nil
            throw AuthError.pairingExpired
        }
        guard PairingProof.isValid(request.proof, token: pairing.token, machineId: machineId, deviceId: request.deviceId,
                                   deviceName: request.deviceName, publicKey: request.publicKey)
        else { throw AuthError.badPairingToken }
        guard (1...100).contains(request.deviceId.count), (1...100).contains(request.deviceName.count) else {
            throw AuthError.badDeviceInfo
        }
        guard let keyData = Data(base64Encoded: request.publicKey),
              (try? P256.Signing.PublicKey(x963Representation: keyData)) != nil
        else { throw AuthError.badPublicKey }
        self.pairing = nil
        return PairedDevice(id: request.deviceId, name: request.deviceName, publicKey: keyData, pairedAt: now())
    }

    public func issueNonce(for deviceId: String) -> String {
        let now = now()
        nonces = nonces.filter { $0.value.expires > now }
        if nonces.count >= Self.maxOutstandingNonces,
           let oldest = nonces.min(by: { $0.value.expires < $1.value.expires })?.key {
            nonces.removeValue(forKey: oldest)
        }
        let nonce = randomToken()
        nonces[nonce] = (deviceId, now.addingTimeInterval(FaceUnlockProtocol.nonceLifetime))
        return nonce
    }

    /// Checks a signed command and returns the device that sent it. Each nonce works once.
    public func verify(_ request: CommandRequest, devices: [PairedDevice]) throws -> PairedDevice {
        guard let device = devices.first(where: { $0.id == request.deviceId }) else { throw AuthError.unknownDevice }
        guard let challenge = nonces.removeValue(forKey: request.nonce), challenge.deviceId == device.id else {
            throw AuthError.unknownNonce
        }
        guard challenge.expires > now() else { throw AuthError.expiredNonce }
        let message = SignedMessage.bytes(machineId: machineId, deviceId: device.id, action: request.action, nonce: request.nonce)
        guard device.isValidSignature(request.signature, for: message) else { throw AuthError.badSignature }
        return device
    }
}
