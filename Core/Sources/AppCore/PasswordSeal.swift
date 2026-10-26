import CryptoKit
import Foundation

/// Keeps a computer's saved login password useless without the iPhone.
///
/// Each iPhone has a password key per computer: a P-256 key-agreement key in the Secure Enclave that, like its
/// signing key, only works after Face ID. The computer encrypts ("seals") the password to that key's public half
/// with a one-time key, and keeps only the result. To unlock, hello sends the one-time key's public half and a
/// fresh session key; the iPhone works out the key that opens the password and sends it back encrypted to that
/// session key, signed with the command (`SignedMessage` v2). So the iPhone never sees the password, the relay sees
/// neither the password nor its key, and a copy of the computer's files can't be opened without the iPhone.
///
/// P-256 ECDH, HKDF-SHA256 and AES-256-GCM, all from CryptoKit. The Linux agent does the computer side in
/// linux/seal.go; the vectors in both test suites keep the two in step.
public enum PasswordSeal {
    /// A sealed password as the computer keeps it.
    public struct Sealed: Codable, Equatable, Sendable {
        /// X9.63 public half of the one-time key it was sealed with.
        public var key: Data
        /// AES-GCM nonce ‖ ciphertext ‖ tag.
        public var box: Data
    }

    public enum SealError: Error {
        case badKey
    }

    // MARK: - iPhone

    /// The key that opens a password sealed with `sealKey`, from the password key's shared secret with `sealKey`.
    public static func passwordKey(sharedSecret: SharedSecret, sealKey: Data, machineId: String, deviceId: String) -> SymmetricKey {
        sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: sealKey,
                                             sharedInfo: sealInfo(machineId: machineId, deviceId: deviceId), outputByteCount: 32)
    }

    /// Encrypts `key` to the challenge's session key, for the command that answers `nonce`.
    public static func wrap(_ key: SymmetricKey, sessionKey: String, machineId: String, deviceId: String, nonce: String) throws -> WrappedKey {
        try wrap(key, sessionKey: sessionKey, machineId: machineId, deviceId: deviceId, nonce: nonce,
                 ephemeral: P256.KeyAgreement.PrivateKey(), aesNonce: AES.GCM.Nonce())
    }

    static func wrap(_ key: SymmetricKey, sessionKey: String, machineId: String, deviceId: String, nonce: String,
                     ephemeral: P256.KeyAgreement.PrivateKey, aesNonce: AES.GCM.Nonce) throws -> WrappedKey {
        guard let sessionData = Data(base64Encoded: sessionKey),
              let session = try? P256.KeyAgreement.PublicKey(x963Representation: sessionData)
        else { throw SealError.badKey }
        let ephemeralKey = ephemeral.publicKey.x963Representation
        let wrapping = try ephemeral.sharedSecretFromKeyAgreement(with: session)
            .hkdfDerivedSymmetricKey(using: SHA256.self, salt: ephemeralKey,
                                     sharedInfo: wrapInfo(machineId: machineId, deviceId: deviceId, nonce: nonce), outputByteCount: 32)
        let box = try AES.GCM.seal(key.withUnsafeBytes { Data($0) }, using: wrapping, nonce: aesNonce)
        return WrappedKey(key: ephemeralKey.base64EncodedString(), box: box.combined!.base64EncodedString())
    }

    // MARK: - Computer (the Linux agent has its own, in Go; these are for tests and `fake-phone`)

    public static func seal(_ password: String, to passwordKey: Data, machineId: String, deviceId: String) throws -> Sealed {
        try seal(password, to: passwordKey, machineId: machineId, deviceId: deviceId,
                 ephemeral: P256.KeyAgreement.PrivateKey(), aesNonce: AES.GCM.Nonce())
    }

    static func seal(_ password: String, to passwordKey: Data, machineId: String, deviceId: String,
                     ephemeral: P256.KeyAgreement.PrivateKey, aesNonce: AES.GCM.Nonce) throws -> Sealed {
        guard let phone = try? P256.KeyAgreement.PublicKey(x963Representation: passwordKey) else { throw SealError.badKey }
        let sealKey = ephemeral.publicKey.x963Representation
        let key = try Self.passwordKey(sharedSecret: ephemeral.sharedSecretFromKeyAgreement(with: phone), sealKey: sealKey,
                                       machineId: machineId, deviceId: deviceId)
        return Sealed(key: sealKey, box: try AES.GCM.seal(Data(password.utf8), using: key, nonce: aesNonce).combined!)
    }

    /// Opens `sealed` with the key the iPhone wrapped to `session`.
    public static func open(_ sealed: Sealed, wrapped: WrappedKey, session: P256.KeyAgreement.PrivateKey,
                            machineId: String, deviceId: String, nonce: String) throws -> String {
        guard let ephemeralKey = Data(base64Encoded: wrapped.key), let box = Data(base64Encoded: wrapped.box),
              let ephemeral = try? P256.KeyAgreement.PublicKey(x963Representation: ephemeralKey)
        else { throw SealError.badKey }
        let wrapping = try session.sharedSecretFromKeyAgreement(with: ephemeral)
            .hkdfDerivedSymmetricKey(using: SHA256.self, salt: ephemeralKey,
                                     sharedInfo: wrapInfo(machineId: machineId, deviceId: deviceId, nonce: nonce), outputByteCount: 32)
        let key = try AES.GCM.open(AES.GCM.SealedBox(combined: box), using: wrapping)
        let password = try AES.GCM.open(AES.GCM.SealedBox(combined: sealed.box), using: SymmetricKey(data: key))
        return String(decoding: password, as: UTF8.self)
    }

    // MARK: - Shared

    static func sealInfo(machineId: String, deviceId: String) -> Data {
        Data("faceunlock-seal/v1\n\(machineId)\n\(deviceId)".utf8)
    }

    static func wrapInfo(machineId: String, deviceId: String, nonce: String) -> Data {
        Data("faceunlock-wrap/v1\n\(machineId)\n\(deviceId)\n\(nonce)".utf8)
    }
}
