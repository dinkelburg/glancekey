import Foundation

public enum ClientError: Error, LocalizedError, Equatable {
    case unreachable
    case server(status: Int, message: String)
    case wrongMachine
    case invalidResponse

    public var errorDescription: String? {
        switch self {
        case .unreachable: "Can't reach the FaceUnlock relay. Check your internet connection."
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

    public func pair(invite: PairingInvite, deviceId: String, deviceName: String, publicKey: Data) async throws -> PairResponse {
        let request = PairRequest(invite: invite, deviceId: deviceId, deviceName: deviceName, publicKey: publicKey)
        let response: PairResponse = try await post("pair", body: request, timeout: helloTimeout)
        guard response.machineId == machineId else { throw ClientError.wrongMachine }
        return response
    }

    public func hello(deviceId: String) async throws -> HelloResponse {
        let response: HelloResponse = try await post("hello", body: HelloRequest(deviceId: deviceId), timeout: helloTimeout)
        guard response.machineId == machineId else { throw ClientError.wrongMachine }
        return response
    }

    public func command(_ action: Action, nonce: String, signature: Data, deviceId: String) async throws -> CommandResponse {
        let request = CommandRequest(deviceId: deviceId, action: action, nonce: nonce, signature: signature.base64EncodedString())
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
