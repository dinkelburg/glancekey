import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// One signing key per paired Mac. On a real iPhone it lives in the Secure Enclave and only signs after Face ID.
enum DeviceKey {
    enum KeyError: LocalizedError {
        case accessControl
        case keychain(OSStatus)
        case missing

        var errorDescription: String? {
            switch self {
            case .accessControl: "Couldn't set up Face ID protection for the key."
            case .keychain(let status): "Keychain error \(status)."
            case .missing: "This iPhone's key for that Mac is gone. Pair again."
            }
        }
    }

    private static let service = "nl.dinkelworks.faceunlock.device-key"

    private static var usesSecureEnclave: Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        return SecureEnclave.isAvailable
        #endif
    }

    /// Creates the key and returns its X9.63 public key.
    static func create(tag: String) throws -> Data {
        if usesSecureEnclave {
            // .biometryCurrentSet: Face ID only (no passcode fallback), and enrolling a new face invalidates the key.
            guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                               [.privateKeyUsage, .biometryCurrentSet], nil)
            else { throw KeyError.accessControl }
            let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
            try store(key.dataRepresentation, tag: tag)
            return key.publicKey.x963Representation
        } else {
            // Simulator: no Secure Enclave, so a software key guarded only by the Face ID check before signing.
            let key = P256.Signing.PrivateKey()
            try store(key.rawRepresentation, tag: tag)
            return key.publicKey.x963Representation
        }
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

    static func delete(tag: String) {
        SecItemDelete(query(tag: tag) as CFDictionary)
    }

    private static func query(tag: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: tag,
        ]
    }

    private static func store(_ data: Data, tag: String) throws {
        delete(tag: tag)
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
