import Darwin
import AppCore
import CryptoKit
import Foundation

/// The Unix socket the root-owned checker (the Go agent's `pam` command, which sudo runs) and `enable-sudo` talk to,
/// with the same newline-separated JSON as the Linux agent's control socket. Only this user and root can open it.
final class ControlSocket {
    static var path: String {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/\(Brand.id)/agent.sock").path
    }

    private let path: String
    private let handler: @MainActor (Connection) async -> Void
    private var listener: Int32 = -1
    private var source: DispatchSourceRead?

    init(path: String = ControlSocket.path, handler: @escaping @MainActor (Connection) async -> Void) {
        self.path = path
        self.handler = handler
    }

    func start() throws {
        let directory = (path as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        unlink(path)

        listener = socket(AF_UNIX, SOCK_STREAM, 0)
        guard listener >= 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let capacity = MemoryLayout.size(ofValue: address.sun_path)
        guard path.utf8.count < capacity else { throw POSIXError(.ENAMETOOLONG) }
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            buffer.copyBytes(from: path.utf8)
            buffer[path.utf8.count] = 0
        }
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard bound == 0, chmod(path, 0o600) == 0, listen(listener, 8) == 0 else {
            let error = POSIXError(.init(rawValue: errno) ?? .EIO)
            close(listener)
            throw error
        }

        let listener = listener
        let source = DispatchSource.makeReadSource(fileDescriptor: listener, queue: .global(qos: .userInitiated))
        source.setEventHandler { [handler] in
            let client = accept(listener, nil, nil)
            guard client >= 0 else { return }
            var on: Int32 = 1
            setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
            let connection = Connection(descriptor: client)
            Task { @MainActor in
                await handler(connection)
                connection.close()
            }
        }
        source.resume()
        self.source = source
    }

    /// One client. Lines arrive in `lines` until the client hangs up.
    final class Connection: @unchecked Sendable {
        let lines: AsyncStream<String>
        private let descriptor: Int32

        init(descriptor: Int32) {
            self.descriptor = descriptor
            var continuation: AsyncStream<String>.Continuation!
            lines = AsyncStream { continuation = $0 }
            // A plain blocking reader thread: messages are tiny and there's at most one sudo waiting at a time.
            Thread.detachNewThread { [continuation] in
                var pending = Data()
                var chunk = [UInt8](repeating: 0, count: 4096)
                while true {
                    let count = read(descriptor, &chunk, chunk.count)
                    guard count > 0 else { break }
                    pending.append(contentsOf: chunk[0..<count])
                    while let newline = pending.firstIndex(of: 10) {
                        continuation?.yield(String(decoding: pending[pending.startIndex..<newline], as: UTF8.self))
                        pending.removeSubrange(pending.startIndex...newline)
                    }
                    if pending.count > 64 * 1024 { break }
                }
                continuation?.finish()
                Darwin.close(descriptor)
            }
        }

        func send<Value: Encodable>(_ value: Value) {
            guard var data = try? JSONEncoder().encode(value) else { return }
            data.append(10)
            data.withUnsafeBytes { buffer in
                var offset = 0
                while offset < buffer.count {
                    let written = write(descriptor, buffer.baseAddress! + offset, buffer.count - offset)
                    if written <= 0 { return }
                    offset += written
                }
            }
        }

        /// Hangs up; the reader thread then closes the descriptor.
        func close() {
            shutdown(descriptor, SHUT_RDWR)
        }
    }
}

/// Messages on the control socket, matching linux/control.go and linux/approvals.go.
struct ControlRequest: Decodable {
    var command: String
    var approval: Approval?
}

struct ControlResponse: Encodable {
    var error: String?
    var approvers: Approvers?
}

/// Who may approve password prompts on this Mac; `enable-sudo` saves it, root-owned, at `path`.
struct Approvers: Codable {
    static let path = "/etc/\(Brand.id)/approvers.json"

    struct Device: Codable {
        /// The iPhone's device id, as this app hands it to enable-sudo. approvers.json only keeps its SHA-256
        /// (`idHash`): anyone on the Mac can read the file, and a device id is all a hello needs.
        var id: String?
        var idHash: String?
        var name: String
        var publicKey: Data
        /// RFC 3339, as linux/control.go's Approver has it. Shown with the key when setting up.
        var pairedAt: String?

        /// Whether this is the iPhone with `deviceId`, from either (files from before 1.0.3 have the id itself).
        func isDevice(_ deviceId: String) -> Bool {
            (idHash ?? id.map(Approvers.hash)) == Approvers.hash(deviceId)
        }
    }

    /// How approvers.json names a device id: hex SHA-256, as deviceIDHash in linux/control.go.
    static func hash(_ id: String) -> String {
        SHA256.hash(data: Data(id.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    var machineId: String
    var machineName: String
    var devices: [Device]
}

struct CheckerMessage: Codable {
    var waiting: Bool?
    var decision: String?
    var deviceId: String?
    var signature: String?
    var accepted: Bool?
    var error: String?
    /// With `waiting`: how long to wait for the iPhone, this Mac's approval wait (`ApprovalWait`).
    var expiresIn: Int?
}
