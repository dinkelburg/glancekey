import AppCore
import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// One signing key per paired computer. On a real iPhone it lives in the Secure Enclave and only signs after Face ID.
/// A computer that seals its saved password to the iPhone (`PasswordSeal`) also gets a password key: a key-agreement
/// key with the same protection, stored next to the signing key.
enum DeviceKey {
    enum KeyError: LocalizedError {
        case accessControl
        case keychain(OSStatus)
        case missing

        var errorDescription: String? {
            switch self {
            case .accessControl: "Couldn't protect the key with \(Biometry.name)."
            case .keychain(let status): "Keychain error \(status)."
            case .missing: "This iPhone's key for that computer is gone. Pair again."
            }
        }
    }

    private static let service = Brand.keychainService("device-key")

    private static var usesSecureEnclave: Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        return SecureEnclave.isAvailable
        #endif
    }

    /// .biometryCurrentSet: Face ID only (no passcode fallback), and enrolling a new face invalidates the key.
    private static func accessControl() throws -> SecAccessControl {
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                           [.privateKeyUsage, .biometryCurrentSet], nil)
        else { throw KeyError.accessControl }
        return access
    }

    /// Creates the key and returns its X9.63 public key.
    static func create(tag: String) throws -> Data {
        if usesSecureEnclave {
            let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl())
            try store(key.dataRepresentation, tag: tag)
            return key.publicKey.x963Representation
        } else {
            // Simulator: no Secure Enclave, so a software key guarded only by the Face ID check before signing.
            let key = P256.Signing.PrivateKey()
            try store(key.rawRepresentation, tag: tag)
            return key.publicKey.x963Representation
        }
    }

    /// The signing key's X9.63 public key. Needs no Face ID: only signing does.
    static func publicKey(tag: String) throws -> Data {
        let stored = try load(tag: tag)
        if usesSecureEnclave {
            return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: stored).publicKey.x963Representation
        }
        return try P256.Signing.PrivateKey(rawRepresentation: stored).publicKey.x963Representation
    }

    /// `context` must already have passed Face ID. The Secure Enclave enforces that on its own too.
    static func sign(_ message: Data, tag: String, context: LAContext) throws -> Data {
        let stored = try load(tag: tag)
        if usesSecureEnclave {
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: stored, authenticationContext: context)
            return try key.signature(for: message).rawRepresentation
        }
        return try P256.Signing.PrivateKey(rawRepresentation: stored).signature(for: message).rawRepresentation
    }

    /// The X9.63 public key of the password key for this pairing, made the first time it's needed.
    static func passwordKey(tag: String) throws -> Data {
        let keyTag = passwordTag(tag)
        do {
            let stored = try load(tag: keyTag)
            if usesSecureEnclave {
                return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: stored).publicKey.x963Representation
            }
            return try P256.KeyAgreement.PrivateKey(rawRepresentation: stored).publicKey.x963Representation
        } catch KeyError.missing {
            // None yet: made below. Any other error must not replace a key the computer already sealed to.
        }
        if usesSecureEnclave {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: accessControl())
            try store(key.dataRepresentation, tag: keyTag)
            return key.publicKey.x963Representation
        }
        let key = P256.KeyAgreement.PrivateKey()
        try store(key.rawRepresentation, tag: keyTag)
        return key.publicKey.x963Representation
    }

    /// The password key's shared secret with `publicKey` (X9.63). `context` must already have passed Face ID.
    static func passwordSecret(with publicKey: Data, tag: String, context: LAContext) throws -> SharedSecret {
        let stored = try load(tag: passwordTag(tag))
        let other = try P256.KeyAgreement.PublicKey(x963Representation: publicKey)
        if usesSecureEnclave {
            return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: stored, authenticationContext: context)
                .sharedSecretFromKeyAgreement(with: other)
        }
        return try P256.KeyAgreement.PrivateKey(rawRepresentation: stored).sharedSecretFromKeyAgreement(with: other)
    }

    /// Deletes the pairing's signing key and password key.
    static func delete(tag: String) {
        SecItemDelete(query(tag: tag) as CFDictionary)
        SecItemDelete(query(tag: passwordTag(tag)) as CFDictionary)
    }

    private static func passwordTag(_ tag: String) -> String { tag + ".password" }

    private static func query(tag: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: tag,
        ]
    }

    private static func store(_ data: Data, tag: String) throws {
        SecItemDelete(query(tag: tag) as CFDictionary)
        var item = query(tag: tag)
        item[kSecValueData as String] = data
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeyError.keychain(status) }
    }

    private static func load(tag: String) throws -> Data {
        var request = query(tag: tag)
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        guard status != errSecItemNotFound else { throw KeyError.missing }
        guard status == errSecSuccess, let data = result as? Data else { throw KeyError.keychain(status) }
        return data
    }
}
