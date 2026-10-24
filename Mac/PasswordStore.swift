import Foundation
import OpenDirectory
import Security

/// Generic passwords in the login keychain. Nothing stored here leaves this Mac.
enum Keychain {
    private static func query(_ service: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: NSUserName(),
        ]
    }

    static func exists(_ service: String) -> Bool {
        var request = query(service)
        request[kSecReturnAttributes as String] = true
        return SecItemCopyMatching(request as CFDictionary, nil) == errSecSuccess
    }

    static func load(_ service: String) -> String? {
        var request = query(service)
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(request as CFDictionary, &result) == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func save(_ value: String, service: String, label: String) throws {
        delete(service)
        var item = query(service)
        item[kSecValueData as String] = Data(value.utf8)
        item[kSecAttrLabel as String] = label
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
    }

    static func delete(_ service: String) {
        SecItemDelete(query(service) as CFDictionary)
    }
}

/// The Mac login password FaceUnlock types on the lock screen.
enum PasswordStore {
    enum Check {
        case correct, wrong, unknown
    }

    private static let service = "nl.dinkelworks.faceunlock.login-password"

    static var exists: Bool { Keychain.exists(service) }
    static func load() -> String? { Keychain.load(service) }
    static func save(_ password: String) throws { try Keychain.save(password, service: service, label: "FaceUnlock: Mac login password") }
    static func delete() { Keychain.delete(service) }

    /// Checks the password against the local account, so FaceUnlock never types a wrong one into the lock screen.
    static func check(_ password: String) async -> Check {
        await Task.detached(priority: .userInitiated) {
            let record: ODRecord
            do {
                let node = try ODNode(session: ODSession.default(), type: ODNodeType(kODNodeTypeLocalNodes))
                record = try node.record(withRecordType: kODRecordTypeUsers, name: NSUserName(), attributes: nil)
            } catch {
                return Check.unknown
            }
            do {
                try record.verifyPassword(password)
                return .correct
            } catch {
                return .wrong
            }
        }.value
    }
}
