import AppCore
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
        loadData(service).flatMap { String(data: $0, encoding: .utf8) }
    }

    static func loadData(_ service: String) -> Data? {
        var request = query(service)
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(request as CFDictionary, &result) == errSecSuccess else { return nil }
        return result as? Data
    }

    static func save(_ value: String, service: String, label: String) throws {
        try save(data: Data(value.utf8), service: service, label: label)
    }

    static func save(data: Data, service: String, label: String) throws {
        delete(service)
        var item = query(service)
        item[kSecValueData as String] = data
        item[kSecAttrLabel as String] = label
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
    }

    static func delete(_ service: String) {
        SecItemDelete(query(service) as CFDictionary)
    }
}

/// The Mac login password the app types on the lock screen, and the iPhones allowed to make it do that.
///
/// Both live in one keychain item. Other programs running as you can't read the app's keychain items, but they can
/// overwrite them, and they can change its UserDefaults (where the paired iPhones are listed too). They don't know
/// your password, though: once the password in this item passes `check`, the list next to it is the one this app
/// saved. So only those iPhones may unlock, fill in password dialogs or approve sudo.
enum PasswordStore {
    enum Check {
        case correct, wrong, unknown
    }

    struct Saved {
        var password: String
        /// nil in an item saved by a version that only kept the password.
        var trusted: [TrustedDevice]?
    }

    struct TrustedDevice: Codable, Equatable {
        var id: String
        var publicKey: Data

        init(_ device: PairedDevice) {
            id = device.id
            publicKey = device.publicKey
        }

        func matches(_ device: PairedDevice) -> Bool { device.id == id && device.publicKey == publicKey }
    }

    private struct Contents: Codable {
        var password: String
        var trusted: [TrustedDevice]
    }

    private static let service = Brand.keychainService("login-password")
    /// Starts the item when it holds `Contents`; before, it held just the password, which can't contain this byte.
    private static let marker: UInt8 = 0

    static var exists: Bool { Keychain.exists(service) }

    static func load() -> Saved? {
        guard let data = Keychain.loadData(service) else { return nil }
        if data.first == marker {
            guard let contents = try? JSONDecoder().decode(Contents.self, from: data.dropFirst()) else { return nil }
            return Saved(password: contents.password, trusted: contents.trusted)
        }
        return String(data: data, encoding: .utf8).map { Saved(password: $0, trusted: nil) }
    }

    static func save(_ password: String, trusting trusted: [TrustedDevice]) throws {
        let contents = try JSONEncoder().encode(Contents(password: password, trusted: trusted))
        try Keychain.save(data: Data([marker]) + contents, service: service, label: "\(Brand.name): Mac login password")
    }

    static func delete() { Keychain.delete(service) }

    /// Checks the password against the local account, so the app never types a wrong one into the lock screen.
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
