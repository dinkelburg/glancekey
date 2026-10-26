import AppCore
import Foundation

/// Keeps the outgoing WebSocket to the relay open and answers the iPhone's requests that arrive on it.
/// Going out rather than listening means it works on any network, behind any router.
@MainActor
final class RelayConnection: NSObject, URLSessionWebSocketDelegate {
    enum State: Equatable {
        case connecting
        case connected
        case offline(String)
    }

    typealias Handler = (_ path: String, _ body: Data) async -> (status: Int, body: Data)

    private let relay: URL
    private let machineId: String
    private let secret: String
    private let handler: Handler
    var onStateChange: ((State) -> Void)?

    private lazy var session = URLSession(configuration: .default, delegate: self, delegateQueue: .main)
    private var task: URLSessionWebSocketTask?
    private var generation = 0
    private var failures = 0
    private var lastHeardAt = Date()
    private var heartbeat: Timer?
    private var retry: Task<Void, Never>?
    private(set) var state = State.offline("Not started") {
        didSet { if state != oldValue { onStateChange?(state) } }
    }

    private static let pingInterval: TimeInterval = 20
    /// The relay answers every ping, so this much silence means the connection is dead (e.g. after sleep).
    private static let silenceLimit: TimeInterval = 50

    init(relay: URL, machineId: String, secret: String, handler: @escaping Handler) {
        self.relay = relay
        self.machineId = machineId
        self.secret = secret
        self.handler = handler
    }

    /// (Re)connects now, e.g. at launch, after waking from sleep or when the network changes.
    func connect() {
        retry?.cancel()
        task?.cancel(with: .goingAway, reason: nil)
        generation += 1
        let generation = generation

        var components = URLComponents(url: relay.appendingPathComponent("v1/agent/\(machineId)"), resolvingAgainstBaseURL: false)!
        components.scheme = relay.scheme == "http" ? "ws" : "wss"
        var request = URLRequest(url: components.url!, timeoutInterval: 15)
        request.setValue("Bearer \(secret)", forHTTPHeaderField: "Authorization")

        let task = session.webSocketTask(with: request)
        self.task = task
        state = .connecting
        lastHeardAt = Date()
        task.resume()
        receive(on: task, generation: generation)

        heartbeat?.invalidate()
        heartbeat = Timer.scheduledTimer(withTimeInterval: Self.pingInterval, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.beat(task, generation: generation) }
        }
    }

    func reconnectIfNeeded() {
        if state != .connected { connect() }
    }

    private func beat(_ task: URLSessionWebSocketTask, generation: Int) {
        guard generation == self.generation, state == .connected else { return }
        if Date().timeIntervalSince(lastHeardAt) > Self.silenceLimit {
            fail("The relay stopped answering", generation: generation)
        } else {
            task.send(.string("ping")) { _ in }
        }
    }

    private func receive(on task: URLSessionWebSocketTask, generation: Int) {
        Task {
            do {
                while true {
                    let message = try await task.receive()
                    guard generation == self.generation else { return }
                    lastHeardAt = Date()
                    if case .string(let text) = message, text != "pong" {
                        answer(text, on: task)
                    }
                }
            } catch {
                guard generation == self.generation else { return }
                if let http = task.response as? HTTPURLResponse, http.statusCode != 101 {
                    fail("The relay refused the connection (HTTP \(http.statusCode))", generation: generation)
                } else {
                    fail(error.localizedDescription, generation: generation)
                }
            }
        }
    }

    private func answer(_ text: String, on task: URLSessionWebSocketTask) {
        guard let request = try? JSONDecoder().decode(RelayRequest.self, from: Data(text.utf8)) else { return }
        Task {
            let (status, body) = await handler(request.path, Data(request.body.utf8))
            let response = RelayResponse(id: request.id, status: status, body: String(decoding: body, as: UTF8.self))
            guard let encoded = try? JSONEncoder().encode(response) else { return }
            try? await task.send(.string(String(decoding: encoded, as: UTF8.self)))
        }
    }

    /// Asks the relay to push a notification to the iPhones. False if it didn't reach the relay.
    func notify(_ notification: RelayNotification) async -> Bool {
        guard state == .connected, let task, let encoded = try? JSONEncoder().encode(notification) else { return false }
        return (try? await task.send(.string(String(decoding: encoded, as: UTF8.self)))) != nil
    }

    private func fail(_ reason: String, generation: Int) {
        guard generation == self.generation else { return }
        heartbeat?.invalidate()
        task?.cancel(with: .goingAway, reason: nil)
        state = .offline(reason)
        let delays: [UInt64] = [1, 2, 5, 10, 30]
        let delay = delays[min(failures, delays.count - 1)]
        failures += 1
        retry = Task { [weak self] in
            try? await Task.sleep(nanoseconds: delay * 1_000_000_000)
            guard !Task.isCancelled else { return }
            self?.connect()
        }
    }

    nonisolated func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didOpenWithProtocol protocol: String?) {
        MainActor.assumeIsolated {
            guard webSocketTask === task else { return }
            failures = 0
            state = .connected
        }
    }
}
