import Foundation

public enum ClientError: Error, LocalizedError, Equatable {
    case unreachable
    case server(status: Int, message: String)
    case wrongMachine
    case invalidResponse

    public var errorDescription: String? {
        switch self {
        case .unreachable: "Can't reach the \(Brand.name) relay. Check your internet connection."
        case .server(_, let message): message
        case .wrongMachine: "A different computer answered. Pair this iPhone again."
        case .invalidResponse: "Your computer sent an unexpected response."
        }
    }
}

/// The iPhone side of the protocol: talks to one computer through the relay. Used by the iPhone app and `fake-phone`.
public struct RelayClient: Sendable {
    public var relay: URL
    public var machineId: String
    public var session: URLSession
    public var helloTimeout: TimeInterval = 10
    /// Unlocking waits for the lock screen to go away, so give it longer.
    public var commandTimeout: TimeInterval = 30

    public init(relay: URL, machineId: String, session: URLSession = URLSession(configuration: .ephemeral)) {
        self.relay = relay
        self.machineId = machineId
        self.session = session
    }

    public init(invite: PairingInvite) {
        self.init(relay: invite.relay, machineId: invite.machineId)
    }

    /// `passwordKey` is the iPhone's password key (`PasswordSeal`), for invites that ask for one.
    public func pair(invite: PairingInvite, deviceId: String, deviceName: String, publicKey: Data,
                     passwordKey: Data? = nil) async throws -> PairResponse {
        let request = PairRequest(invite: invite, deviceId: deviceId, deviceName: deviceName, publicKey: publicKey,
                                  passwordKey: passwordKey)
        let response: PairResponse = try await post("pair", body: request, timeout: helloTimeout)
        guard response.machineId == machineId else { throw ClientError.wrongMachine }
        return response
    }

    public func hello(deviceId: String, pushToken: String? = nil, cardId: String? = nil) async throws -> HelloResponse {
        let request = HelloRequest(deviceId: deviceId, pushToken: pushToken, cardId: cardId)
        let response: HelloResponse = try await post("hello", body: request, timeout: helloTimeout)
        guard response.machineId == machineId else { throw ClientError.wrongMachine }
        return response
    }

    /// `signature` is over `SignedMessage.bytes`: the v2 bytes when there's a `passwordKey` or `wrappedKey`.
    public func command(_ action: Action, nonce: String, signature: Data, deviceId: String,
                        passwordKey: String? = nil, wrappedKey: WrappedKey? = nil) async throws -> CommandResponse {
        let request = CommandRequest(deviceId: deviceId, action: action, nonce: nonce, signature: signature.base64EncodedString(),
                                     passwordKey: passwordKey, wrappedKey: wrappedKey)
        return try await post("command", body: request, timeout: commandTimeout)
    }

    /// Sets the computer's approval wait. `signature` is over `WaitMessage.bytes`.
    public func setWait(_ wait: Int, nonce: String, signature: Data, deviceId: String) async throws -> CommandResponse {
        let request = CommandRequest(deviceId: deviceId, action: .setWait, nonce: nonce, signature: signature.base64EncodedString(), wait: wait)
        return try await post("command", body: request, timeout: helloTimeout)
    }

    /// `signature` is over `ApprovalMessage.bytes`.
    public func approve(_ approval: Approval, signature: Data, deviceId: String) async throws -> CommandResponse {
        let request = CommandRequest(deviceId: deviceId, action: .approve, nonce: approval.nonce,
                                     signature: signature.base64EncodedString(), approvalId: approval.id)
        return try await post("command", body: request, timeout: commandTimeout)
    }

    /// Makes the computer stop waiting and ask for its password instead. Needs no Face ID.
    public func deny(_ approval: Approval, deviceId: String) async throws -> CommandResponse {
        let request = CommandRequest(deviceId: deviceId, action: .deny, nonce: approval.nonce, signature: "", approvalId: approval.id)
        return try await post("command", body: request, timeout: commandTimeout)
    }

    private func post<Body: Encodable, Response: Decodable>(_ endpoint: String, body: Body, timeout: TimeInterval) async throws -> Response {
        let url = relay.appendingPathComponent("v1/m/\(machineId)/\(endpoint)")
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: timeout)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(body)

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw ClientError.unreachable
        }
        guard let http = response as? HTTPURLResponse else { throw ClientError.invalidResponse }
        guard (200..<300).contains(http.statusCode) else {
            let message = (try? JSONDecoder().decode(ErrorResponse.self, from: data))?.error ?? "The relay answered with HTTP \(http.statusCode)."
            throw ClientError.server(status: http.statusCode, message: message)
        }
        guard let decoded = try? JSONDecoder().decode(Response.self, from: data) else { throw ClientError.invalidResponse }
        return decoded
    }
}
