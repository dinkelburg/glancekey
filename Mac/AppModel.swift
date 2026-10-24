import AppKit
import FaceUnlockCore
import IOKit.ps
import IOKit.pwr_mgt
import Network
import ServiceManagement
import SystemConfiguration

@MainActor
final class AppModel: ObservableObject {
    static let shared = AppModel()

    struct LogEntry: Identifiable {
        let id = UUID()
        let date = Date()
        let text: String
        let isError: Bool
    }

    struct RequestError: Error {
        let status: Int
        let message: String
    }

    private enum Defaults {
        static let machineId = "machineId"
        static let devices = "pairedDevices"
        static let keepAwake = "keepAwakeOnPower"
        static let didSetUpLoginItem = "didSetUpLoginItem"
        /// Override with `defaults write nl.dinkelworks.faceunlock.mac relayURL http://localhost:8787` for testing.
        static let relayURL = "relayURL"
    }

    private static let agentSecretService = "nl.dinkelworks.faceunlock.agent-secret"

    let machineId: String
    let machineName = (SCDynamicStoreCopyComputerName(nil, nil) as String?) ?? Host.current().localizedName ?? "Mac"
    let relay: URL

    @Published private(set) var devices: [PairedDevice]
    @Published private(set) var relayState = RelayConnection.State.offline("Starting…")
    @Published private(set) var hasPassword = PasswordStore.exists
    @Published private(set) var hasEventAccess = ScreenController.hasEventAccess
    @Published private(set) var launchAtLogin = SMAppService.mainApp.status == .enabled
    @Published private(set) var invite: PairingInvite?
    @Published private(set) var pairingExpiresAt: Date?
    @Published private(set) var log: [LogEntry] = []
    @Published var keepAwakeOnPower: Bool {
        didSet {
            UserDefaults.standard.set(keepAwakeOnPower, forKey: Defaults.keepAwake)
            updateSleepAssertion()
        }
    }

    var needsAttention: Bool { !hasPassword || !hasEventAccess || devices.isEmpty || relayState != .connected }

    private let authenticator: Authenticator
    private let pathMonitor = NWPathMonitor()
    private var connection: RelayConnection?
    private var timer: Timer?
    private var sleepAssertion: IOPMAssertionID?
    private var isBusy = false

    private init() {
        let defaults = UserDefaults.standard
        if let id = defaults.string(forKey: Defaults.machineId) {
            machineId = id
        } else {
            machineId = UUID().uuidString
            defaults.set(machineId, forKey: Defaults.machineId)
        }
        relay = defaults.string(forKey: Defaults.relayURL).flatMap(URL.init(string:)) ?? FaceUnlockProtocol.defaultRelay
        devices = defaults.data(forKey: Defaults.devices).flatMap { try? JSONDecoder().decode([PairedDevice].self, from: $0) } ?? []
        keepAwakeOnPower = defaults.object(forKey: Defaults.keepAwake) as? Bool ?? true
        authenticator = Authenticator(machineId: machineId)
    }

    func start() {
        guard connection == nil else { return }
        let connection = RelayConnection(relay: relay, machineId: machineId, secret: agentSecret()) { [weak self] path, body in
            guard let self else { return (503, Data()) }
            return await self.handle(path: path, body: body)
        }
        connection.onStateChange = { [weak self] state in self?.relayState = state }
        self.connection = connection
        connection.connect()

        // A sleeping Mac drops the connection; reconnect as soon as it wakes or the network comes back.
        NSWorkspace.shared.notificationCenter.addObserver(forName: NSWorkspace.didWakeNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.connection?.connect() }
        }
        pathMonitor.pathUpdateHandler = { [weak self] path in
            guard path.status == .satisfied else { return }
            Task { @MainActor in self?.connection?.reconnectIfNeeded() }
        }
        pathMonitor.start(queue: .main)

        setUpLoginItemOnFirstLaunch()
        refreshStatus()
        timer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refreshStatus() }
        }
    }

    /// Claims this Mac's id on the relay, so nobody else can connect in its place.
    private func agentSecret() -> String {
        if let secret = Keychain.load(Self.agentSecretService) { return secret }
        let secret = randomToken()
        try? Keychain.save(secret, service: Self.agentSecretService, label: "FaceUnlock: relay secret")
        return secret
    }

    // MARK: - Setup

    func refreshStatus() {
        let eventAccess = ScreenController.hasEventAccess
        if eventAccess != hasEventAccess { hasEventAccess = eventAccess }
        let loginItem = SMAppService.mainApp.status == .enabled
        if loginItem != launchAtLogin { launchAtLogin = loginItem }
        if let expires = pairingExpiresAt, expires < Date() { cancelPairing() }
        updateSleepAssertion()
    }

    /// Returns an error message, or nil once the password is saved.
    func savePassword(_ password: String) async -> String? {
        guard !password.isEmpty else { return "Enter your password." }
        if await PasswordStore.check(password) == .wrong {
            return "That isn't the login password for \(NSUserName())."
        }
        do {
            try PasswordStore.save(password)
        } catch {
            return "Couldn't save it to the keychain (\(error.localizedDescription))."
        }
        hasPassword = true
        note("Saved your Mac password")
        return nil
    }

    func forgetPassword() {
        PasswordStore.delete()
        hasPassword = false
        note("Removed the saved Mac password")
    }

    func setLaunchAtLogin(_ enabled: Bool) {
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
        } catch {
            note("Couldn't change the login item: \(error.localizedDescription)", isError: true)
        }
        launchAtLogin = SMAppService.mainApp.status == .enabled
    }

    private func setUpLoginItemOnFirstLaunch() {
        guard !UserDefaults.standard.bool(forKey: Defaults.didSetUpLoginItem) else { return }
        UserDefaults.standard.set(true, forKey: Defaults.didSetUpLoginItem)
        setLaunchAtLogin(true)
    }

    // MARK: - Pairing

    func startPairing() {
        let token = authenticator.startPairing()
        invite = PairingInvite(machineId: machineId, machineName: machineName, platform: "macOS", relay: relay, token: token)
        pairingExpiresAt = authenticator.pairingExpiresAt
    }

    func cancelPairing() {
        authenticator.cancelPairing()
        invite = nil
        pairingExpiresAt = nil
    }

    func remove(_ device: PairedDevice) {
        devices.removeAll { $0.id == device.id }
        saveDevices()
        note("Removed \(device.name)")
    }

    private func saveDevices() {
        UserDefaults.standard.set(try? JSONEncoder().encode(devices), forKey: Defaults.devices)
    }

    // MARK: - Requests from the iPhone

    func handle(path: String, body: Data) async -> (status: Int, body: Data) {
        do {
            switch path {
            case "/v1/pair": return try pair(decode(body))
            case "/v1/hello": return try hello(decode(body))
            case "/v1/command": return try await command(decode(body))
            default: return failure(404, "Not found.")
            }
        } catch let error as AuthError {
            note("Rejected a request: \(error.description)", isError: true)
            return failure(403, error.description)
        } catch let error as RequestError {
            note(error.message, isError: true)
            return failure(error.status, error.message)
        } catch {
            return failure(400, "Bad request.")
        }
    }

    private func pair(_ request: PairRequest) throws -> (status: Int, body: Data) {
        let device = try authenticator.completePairing(request)
        devices.removeAll { $0.id == device.id }
        devices.append(device)
        saveDevices()
        invite = nil
        pairingExpiresAt = nil
        note("Paired \(device.name)")
        return respond(PairResponse(machineId: machineId, machineName: machineName))
    }

    private func hello(_ request: HelloRequest) throws -> (status: Int, body: Data) {
        guard devices.contains(where: { $0.id == request.deviceId }) else { throw AuthError.unknownDevice }
        let nonce = authenticator.issueNonce(for: request.deviceId)
        return respond(HelloResponse(machineId: machineId, machineName: machineName, nonce: nonce))
    }

    private func command(_ request: CommandRequest) async throws -> (status: Int, body: Data) {
        var device = try authenticator.verify(request, devices: devices)
        guard !isBusy else { throw RequestError(status: 409, message: "Your Mac is still busy with the previous request.") }
        isBusy = true
        defer { isBusy = false }

        let response: CommandResponse
        switch request.action {
        case .status:
            let locked = ScreenController.isLocked
            response = CommandResponse(ok: true, locked: locked, message: locked ? "Locked" : "Unlocked")
        case .lock:
            if ScreenController.isLocked {
                response = CommandResponse(ok: true, locked: true, message: "Already locked")
            } else {
                let locked = await ScreenController.lock()
                response = CommandResponse(ok: locked, locked: locked, message: locked ? "Locked" : "Couldn't lock the Mac")
            }
        case .unlock:
            response = try await unlock()
        }

        device.lastUsedAt = Date()
        if let index = devices.firstIndex(where: { $0.id == device.id }) {
            devices[index] = device
            saveDevices()
        }
        if request.action != .status {
            note("\(device.name): \(response.message)", isError: !response.ok)
        }
        return respond(response)
    }

    private func unlock() async throws -> CommandResponse {
        guard ScreenController.isLocked else {
            ScreenController.wakeDisplay()
            return CommandResponse(ok: true, locked: false, message: "Already unlocked")
        }
        guard ScreenController.hasEventAccess else {
            throw RequestError(status: 409, message: "FaceUnlock on your Mac needs Accessibility permission.")
        }
        guard let password = PasswordStore.load() else {
            throw RequestError(status: 409, message: "Save your Mac password in FaceUnlock on the Mac first.")
        }
        if await PasswordStore.check(password) == .wrong {
            throw RequestError(status: 409, message: "The password saved in FaceUnlock is out of date. Update it on your Mac.")
        }
        let unlocked = await ScreenController.unlock(password: password)
        return CommandResponse(ok: unlocked, locked: !unlocked, message: unlocked ? "Unlocked" : "Typed the password, but the Mac is still locked")
    }

    // MARK: - Helpers

    func note(_ text: String, isError: Bool = false) {
        log.insert(LogEntry(text: text, isError: isError), at: 0)
        if log.count > 30 { log.removeLast(log.count - 30) }
    }

    private func decode<T: Decodable>(_ data: Data) throws -> T {
        try JSONDecoder().decode(T.self, from: data)
    }

    private func respond<T: Encodable>(_ value: T) -> (status: Int, body: Data) {
        (200, (try? JSONEncoder().encode(value)) ?? Data())
    }

    private func failure(_ status: Int, _ message: String) -> (status: Int, body: Data) {
        (status, (try? JSONEncoder().encode(ErrorResponse(error: message))) ?? Data())
    }

    /// On the power adapter, stay awake so the iPhone can reach the Mac while it's locked.
    private func updateSleepAssertion() {
        let wanted = keepAwakeOnPower && Self.isOnPowerAdapter
        if wanted, sleepAssertion == nil {
            var assertion: IOPMAssertionID = 0
            let reason = "FaceUnlock keeps this Mac reachable so your iPhone can unlock it" as CFString
            if IOPMAssertionCreateWithName(kIOPMAssertionTypePreventUserIdleSystemSleep as CFString,
                                           IOPMAssertionLevel(kIOPMAssertionLevelOn), reason, &assertion) == kIOReturnSuccess {
                sleepAssertion = assertion
            }
        } else if !wanted, let assertion = sleepAssertion {
            IOPMAssertionRelease(assertion)
            sleepAssertion = nil
        }
    }

    private static var isOnPowerAdapter: Bool {
        let snapshot = IOPSCopyPowerSourcesInfo().takeRetainedValue()
        return (IOPSGetProvidingPowerSourceType(snapshot).takeUnretainedValue() as String) == kIOPMACPowerKey
    }
}
