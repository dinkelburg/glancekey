import AppKit
import AppCore
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

    /// Whether sudo waits for the iPhone (scripts/enable-mac-sudo.sh), from `Approvers.path`.
    enum SudoApprovals: Equatable {
        case off
        case on
        /// A paired iPhone isn't in approvers.json yet.
        case outdated(String)
    }

    private enum Defaults {
        static let machineId = "machineId"
        static let devices = "pairedDevices"
        static let keepAwake = "keepAwakeOnPower"
        static let didSetUpLoginItem = "didSetUpLoginItem"
        /// Override with `defaults write nl.dinkelworks.<Brand.id>.mac relayURL http://localhost:8787` for testing.
        static let relayURL = "relayURL"
        /// Where to post ntfy notifications; https://ntfy.sh unless overridden for testing.
        static let ntfyURL = "ntfyURL"
        static let fillsPasswordDialogs = "fillsPasswordDialogs"
    }

    private static let agentSecretService = Brand.keychainService("agent-secret")

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
    @Published private(set) var sudoApprovals = SudoApprovals.off
    @Published var keepAwakeOnPower: Bool {
        didSet {
            UserDefaults.standard.set(keepAwakeOnPower, forKey: Defaults.keepAwake)
            updateSleepAssertion()
        }
    }
    /// Ask the iPhone when a system password dialog appears, and fill in the password once it approves.
    @Published var fillsPasswordDialogs: Bool {
        didSet { UserDefaults.standard.set(fillsPasswordDialogs, forKey: Defaults.fillsPasswordDialogs) }
    }

    var needsAttention: Bool { !hasPassword || !hasEventAccess || devices.isEmpty || relayState != .connected }

    private let authenticator: Authenticator
    private let pathMonitor = NWPathMonitor()
    private var connection: RelayConnection?
    private var controlSocket: ControlSocket?
    private var approvals: [String: PendingApproval] = [:]
    private var dialogRequest: DialogRequest?
    /// The dialog already asked about, so one you denied or let expire doesn't ask again.
    private var askedDialog: AXUIElement?
    private var timer: Timer?
    private var dialogTimer: Timer?
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
        relay = defaults.string(forKey: Defaults.relayURL).flatMap(URL.init(string:)) ?? Brand.relay
        devices = defaults.data(forKey: Defaults.devices).flatMap { try? JSONDecoder().decode([PairedDevice].self, from: $0) } ?? []
        keepAwakeOnPower = defaults.object(forKey: Defaults.keepAwake) as? Bool ?? true
        fillsPasswordDialogs = defaults.object(forKey: Defaults.fillsPasswordDialogs) as? Bool ?? true
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

        let controlSocket = ControlSocket { [weak self] connection in await self?.serveControl(connection) }
        do {
            try controlSocket.start()
            self.controlSocket = controlSocket
        } catch {
            note("Couldn't open the socket for sudo approvals: \(error.localizedDescription)", isError: true)
        }

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
        dialogTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.checkPasswordDialog() }
        }
    }

    /// Claims this Mac's id on the relay, so nobody else can connect in its place.
    private func agentSecret() -> String {
        if let secret = Keychain.load(Self.agentSecretService) { return secret }
        let secret = randomToken()
        try? Keychain.save(secret, service: Self.agentSecretService, label: "\(Brand.name): relay secret")
        return secret
    }

    // MARK: - Setup

    func refreshStatus() {
        let eventAccess = ScreenController.hasEventAccess
        if eventAccess != hasEventAccess { hasEventAccess = eventAccess }
        let loginItem = SMAppService.mainApp.status == .enabled
        if loginItem != launchAtLogin { launchAtLogin = loginItem }
        if let expires = pairingExpiresAt, expires < Date() { cancelPairing() }
        let sudo = Self.readSudoApprovals(devices: devices)
        if sudo != sudoApprovals { sudoApprovals = sudo }
        updateSleepAssertion()
    }

    private static func readSudoApprovals(devices: [PairedDevice]) -> SudoApprovals {
        guard let data = FileManager.default.contents(atPath: Approvers.path),
              let approvers = try? JSONDecoder().decode(Approvers.self, from: data)
        else { return .off }
        if let missing = devices.first(where: { device in !approvers.devices.contains { $0.id == device.id } }) {
            return .outdated(missing.name)
        }
        return .on
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
        guard let index = devices.firstIndex(where: { $0.id == request.deviceId }) else { throw AuthError.unknownDevice }
        if let topic = request.notifyTopic, topic != (devices[index].notifyTopic ?? ""),
           topic.isEmpty || Notifications.isValidTopic(topic) {
            devices[index].notifyTopic = topic.isEmpty ? nil : topic
            saveDevices()
        }
        let nonce = authenticator.issueNonce(for: request.deviceId)
        var waiting = approvals.values.filter { !$0.answered }.map { ($0.approval, $0.deadline) }
        if let dialog = dialogRequest, !dialog.answered { waiting.append((dialog.approval, dialog.deadline)) }
        let unanswered = waiting.compactMap { approval, deadline -> Approval? in
            guard deadline > Date() else { return nil }
            var approval = approval
            approval.expiresIn = Int(deadline.timeIntervalSinceNow.rounded(.up))
            return approval
        }
        return respond(HelloResponse(machineId: machineId, machineName: machineName, nonce: nonce,
                                     locked: ScreenController.isLocked, approvals: unanswered))
    }

    private func command(_ request: CommandRequest) async throws -> (status: Int, body: Data) {
        if request.action == .approve || request.action == .deny { return try await answerApproval(request) }
        let device = try authenticator.verify(request, devices: devices)
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
        case .approve, .deny:
            throw RequestError(status: 400, message: "Bad request.")
        }

        markUsed(device.id)
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
            throw RequestError(status: 409, message: "\(Brand.name) on your Mac needs Accessibility permission.")
        }
        guard let password = PasswordStore.load() else {
            throw RequestError(status: 409, message: "Save your Mac password in \(Brand.name) on the Mac first.")
        }
        if await PasswordStore.check(password) == .wrong {
            throw RequestError(status: 409, message: "The password saved in \(Brand.name) is out of date. Update it on your Mac.")
        }
        let unlocked = await ScreenController.unlock(password: password)
        return CommandResponse(ok: unlocked, locked: !unlocked, message: unlocked ? "Unlocked" : "Typed the password, but the Mac is still locked")
    }

    // MARK: - Approvals for sudo

    /// sudo runs the root-owned checker (linux/checker.go) through the PAM module (Mac/PAM). The checker asks
    /// here over the control socket; the request shows up in the iPhone's hello and the iPhone's answer goes back
    /// to the checker, which verifies the signature itself against approvers.json. This app only
    /// passes messages along, so it can't approve anything on its own.
    private final class PendingApproval {
        enum Event {
            case answer(Action, PairedDevice, signature: String)
            /// A line from the checker, or nil when it hung up.
            case checker(CheckerMessage?)
            case timeout
        }

        let approval: Approval
        let deadline: Date
        let events: AsyncStream<Event>
        let post: AsyncStream<Event>.Continuation
        var answered = false
        private var verdict: CheckedContinuation<CheckerMessage?, Never>?

        init(_ approval: Approval) {
            self.approval = approval
            deadline = Date().addingTimeInterval(TimeInterval(approval.expiresIn))
            var post: AsyncStream<Event>.Continuation!
            events = AsyncStream { post = $0 }
            self.post = post
        }

        /// Sends the iPhone's approval to the checker and waits for its verdict.
        func approve(by device: PairedDevice, signature: String) async -> CheckerMessage? {
            await withCheckedContinuation { continuation in
                verdict = continuation
                post.yield(.answer(.approve, device, signature: signature))
            }
        }

        func resolve(_ message: CheckerMessage?) {
            verdict?.resume(returning: message)
            verdict = nil
        }
    }

    func serveControl(_ connection: ControlSocket.Connection) async {
        var lines = connection.lines.makeAsyncIterator()
        guard let line = await lines.next(),
              let request = try? JSONDecoder().decode(ControlRequest.self, from: Data(line.utf8))
        else { return }
        switch request.command {
        case "approvers":
            let approvers = Approvers(machineId: machineId, machineName: machineName,
                                      devices: devices.map { .init(id: $0.id, name: $0.name, publicKey: $0.publicKey) })
            connection.send(ControlResponse(approvers: approvers))
        case "approval":
            await serveApproval(request.approval, connection: connection, lines: lines)
        default:
            connection.send(ControlResponse(error: "unknown command \(request.command)"))
        }
    }

    private func serveApproval(_ approval: Approval?, connection: ControlSocket.Connection, lines: AsyncStream<String>.Iterator) async {
        guard let approval, !approval.id.isEmpty, !approval.nonce.isEmpty, !approval.title.isEmpty,
              approval.title.count <= 300, approval.detail.count <= 300, (1...120).contains(approval.expiresIn),
              !(approval.title + approval.detail).contains(where: \.isNewline)
        else {
            connection.send(CheckerMessage(error: "invalid approval request"))
            return
        }
        guard !devices.isEmpty, relayState == .connected else {
            connection.send(CheckerMessage(error: devices.isEmpty ? "no iPhone is paired" : "not connected to the relay"))
            return
        }

        let pending = PendingApproval(approval)
        approvals[approval.id] = pending
        connection.send(CheckerMessage(waiting: true))
        note("Waiting for your iPhone: \(approval.title)")
        notifyPhones()

        // The checker only writes again after the iPhone answered, so anything earlier means it hung up.
        let reader = Task {
            var lines = lines
            while let line = await lines.next() {
                pending.post.yield(.checker(try? JSONDecoder().decode(CheckerMessage.self, from: Data(line.utf8))))
            }
            pending.post.yield(.checker(nil))
        }
        let timer = Task {
            try? await Task.sleep(nanoseconds: UInt64(approval.expiresIn) * 1_000_000_000)
            pending.post.yield(.timeout)
        }
        defer {
            reader.cancel()
            timer.cancel()
            approvals[approval.id] = nil
            pending.resolve(nil)
        }

        for await event in pending.events {
            switch event {
            case let .answer(decision, device, signature):
                connection.send(CheckerMessage(decision: decision.rawValue, deviceId: device.id, signature: signature))
                if decision == .deny { return }
            case .checker(let message):
                if pending.answered {
                    pending.resolve(message?.accepted == nil ? nil : message)
                } else {
                    note("Cancelled: \(approval.title)")
                }
                return
            case .timeout:
                // Once answered, the checker replies right away or hangs up by its own deadline.
                guard !pending.answered else { continue }
                connection.send(CheckerMessage(error: "No answer from your iPhone."))
                note("No answer from your iPhone: \(approval.title)", isError: true)
                return
            }
        }
    }

    private func answerApproval(_ request: CommandRequest) async throws -> (status: Int, body: Data) {
        guard let device = devices.first(where: { $0.id == request.deviceId }) else { throw AuthError.unknownDevice }
        if let dialog = dialogRequest, dialog.approval.id == request.approvalId {
            return try await answerPasswordDialog(request, by: device)
        }
        guard let id = request.approvalId, let pending = approvals[id], !pending.answered, pending.deadline > Date() else {
            throw AuthError.approvalGone
        }
        // Checked here too, so a bad signature gets a clear error without using up the request.
        if request.action == .approve,
           !device.isValidSignature(request.signature, for: ApprovalMessage.bytes(machineId: machineId, deviceId: device.id, approval: pending.approval)) {
            throw AuthError.badSignature
        }
        pending.answered = true
        if request.action == .deny {
            pending.post.yield(.answer(.deny, device, signature: ""))
            note("\(device.name) denied: \(pending.approval.title)")
            return respond(CommandResponse(ok: true, locked: false, message: "Denied. It asks for the password instead."))
        }
        let verdict = await pending.approve(by: device, signature: request.signature)
        guard let verdict, verdict.accepted == true else {
            throw RequestError(status: 403, message: verdict?.error ?? "Your Mac didn't confirm the approval.")
        }
        markUsed(device.id)
        note("\(device.name) approved: \(pending.approval.title)")
        return respond(CommandResponse(ok: true, locked: false, message: "Approved"))
    }

    // MARK: - Password dialogs

    /// A system password dialog waiting for the iPhone (see PasswordDialog). Unlike sudo, this app decides itself:
    /// it checks the iPhone's signature as for an unlock, then types the password as it does on the lock screen.
    private struct DialogRequest {
        let dialog: PasswordDialog.Found
        let approval: Approval
        let deadline: Date
        var answered = false
    }

    private func checkPasswordDialog() {
        let found = fillsPasswordDialogs && hasPassword && hasEventAccess && !devices.isEmpty ? PasswordDialog.find() : nil
        if let request = dialogRequest, !request.answered,
           request.deadline < Date() || !(found.map { $0.isSame(as: request.dialog) } ?? false) {
            // Expired, or handled on the Mac (Touch ID, typed, cancelled): the iPhone stops showing it.
            dialogRequest = nil
        }
        guard let found else {
            askedDialog = nil
            return
        }
        guard dialogRequest == nil, askedDialog.map({ !CFEqual($0, found.window) }) ?? true, relayState == .connected else { return }
        askedDialog = found.window
        let approval = Approval(id: randomToken(byteCount: 16), title: found.title, detail: found.detail, nonce: randomToken(), expiresIn: 120)
        dialogRequest = DialogRequest(dialog: found, approval: approval, deadline: Date().addingTimeInterval(120))
        note("Waiting for your iPhone: \(found.title)")
        notifyPhones()
    }

    private func answerPasswordDialog(_ request: CommandRequest, by device: PairedDevice) async throws -> (status: Int, body: Data) {
        guard let dialog = dialogRequest, !dialog.answered, dialog.deadline > Date() else { throw AuthError.approvalGone }
        if request.action == .deny {
            dialogRequest = nil
            PasswordDialog.cancel(dialog.dialog)
            note("\(device.name) denied: \(dialog.approval.title)")
            return respond(CommandResponse(ok: true, locked: false, message: "Denied. Closed the dialog."))
        }
        guard device.isValidSignature(request.signature, for: ApprovalMessage.bytes(machineId: machineId, deviceId: device.id, approval: dialog.approval)) else {
            throw AuthError.badSignature
        }
        guard !isBusy else { throw RequestError(status: 409, message: "Your Mac is still busy with the previous request.") }
        isBusy = true
        dialogRequest?.answered = true
        defer {
            isBusy = false
            dialogRequest = nil
            // A dialog that's still open (wrong password, say) doesn't ask again.
            askedDialog = PasswordDialog.find()?.window
        }
        guard let password = PasswordStore.load() else {
            throw RequestError(status: 409, message: "Save your Mac password in \(Brand.name) on the Mac first.")
        }
        if await PasswordStore.check(password) == .wrong {
            throw RequestError(status: 409, message: "The password saved in \(Brand.name) is out of date. Update it on your Mac.")
        }
        markUsed(device.id)
        switch await PasswordDialog.fill(dialog.dialog, password: password) {
        case .filled:
            note("\(device.name) approved: \(dialog.approval.title)")
            return respond(CommandResponse(ok: true, locked: false, message: "Approved. Filled in your password."))
        case .closed:
            throw RequestError(status: 409, message: "The dialog closed before \(Brand.name) could fill it in.")
        case .failed(let reason):
            throw RequestError(status: 409, message: reason)
        }
    }

    /// Posts to the paired iPhones' ntfy topics; tapping the notification opens the app.
    private func notifyPhones() {
        let server = UserDefaults.standard.string(forKey: Defaults.ntfyURL).flatMap(URL.init(string:)) ?? Notifications.server
        for topic in Set(devices.compactMap(\.notifyTopic).filter(Notifications.isValidTopic)) {
            var request = URLRequest(url: server, timeoutInterval: 10)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try? JSONSerialization.data(withJSONObject: [
                "topic": topic,
                "title": "\(machineName) is waiting for you",
                "message": "Tap to approve or deny with \(Brand.name).",
                "click": Notifications.openURL.absoluteString,
                "priority": 4,
                "tags": ["closed_lock_with_key"],
            ] as [String: Any])
            URLSession.shared.dataTask(with: request) { _, response, error in
                guard error != nil || ((response as? HTTPURLResponse)?.statusCode ?? 0) >= 300 else { return }
                Task { @MainActor in AppModel.shared.note("Couldn't send the notification to your iPhone", isError: true) }
            }.resume()
        }
    }

    private func markUsed(_ deviceId: String) {
        guard let index = devices.firstIndex(where: { $0.id == deviceId }) else { return }
        devices[index].lastUsedAt = Date()
        saveDevices()
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
            let reason = "\(Brand.name) keeps this Mac reachable so your iPhone can unlock it" as CFString
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
