import AppCore
import Foundation
import LocalAuthentication
import SwiftUI
import UIKit
import UserNotifications

struct PairedMachine: Codable, Identifiable, Equatable {
    var id: String { machineId }
    var machineId: String
    var machineName: String
    /// "macOS" or "linux".
    var platform: String
    var relay: URL
    var deviceId: String

    var client: RelayClient { RelayClient(relay: relay, machineId: machineId) }
    var symbolName: String { platform == "macOS" ? "laptopcomputer" : "desktopcomputer" }
}

struct OperationResult: Equatable {
    var success: Bool
    var message: String
    var date = Date()
}

enum OperationState: Equatable {
    case idle
    case working(String)
    case finished(OperationResult)
}

/// What a computer answered when the app last asked, which needs no Face ID.
struct MachineStatus: Equatable {
    /// nil if the computer couldn't tell or runs an older version of the app.
    var locked: Bool?
    var approvals: [Approval] = []
    /// Why the computer couldn't be reached.
    var error: String?
    var checkedAt = Date()
}

/// A password prompt on one of the computers, waiting for you (see `Approval`).
struct WaitingApproval: Identifiable, Equatable {
    var id: String { approval.id }
    let machine: PairedMachine
    let approval: Approval
    let expiresAt: Date
}

@MainActor
final class PhoneModel: ObservableObject {
    static let shared = PhoneModel()

    private enum Defaults {
        static let machines = "pairedMachines"
        static let autoUnlock = "autoUnlockOnOpen"
        static let notifications = "notificationsEnabled"
        static let pushToken = "pushToken"
    }

    @Published private(set) var machines: [PairedMachine]
    @Published private(set) var states: [String: OperationState] = [:]
    @Published private(set) var statuses: [String: MachineStatus] = [:]
    @Published private(set) var approvalStates: [String: OperationState] = [:]
    @Published private(set) var isPairing = false
    @Published var pairingResult: OperationResult?
    /// A pairing code waiting for you to confirm it: one from a link (which could come from anywhere), or one that
    /// would replace a pairing. ContentView asks.
    @Published var pendingInvite: PairingInvite?
    /// On open, unlock the one locked computer. Approvals always wait for a tap.
    @Published var autoUnlockOnOpen: Bool {
        didSet { UserDefaults.standard.set(autoUnlockOnOpen, forKey: Defaults.autoUnlock) }
    }
    /// Computers notify this iPhone when they wait for an approval: the relay sends Apple a notification for
    /// `pushToken`. Turning it on asks for permission first.
    @Published var notificationsEnabled: Bool {
        didSet {
            UserDefaults.standard.set(notificationsEnabled, forKey: Defaults.notifications)
            if notificationsEnabled, !oldValue {
                Task { await enableNotifications() }
            } else if !notificationsEnabled {
                notificationProblem = nil
                Task { await refresh() }
            }
        }
    }
    /// Why notifications don't work, if they don't.
    @Published var notificationProblem: String?
    /// The lock screen card (`LiveCardController`).
    @Published var liveCardEnabled = LiveCardController.shared.isEnabled {
        didSet {
            guard liveCardEnabled != oldValue else { return }
            Task {
                await LiveCardController.shared.setEnabled(liveCardEnabled)
                await refresh()
            }
        }
    }
    /// A request or computer the list should scroll to: the one a lock screen card button was about.
    @Published var scrollTarget: String?
    /// Where Apple delivers this iPhone's notifications; nil until Apple hands it over.
    private var pushToken: String?
    /// The push token, while notifications are on.
    var notificationAddress: String? { notificationsEnabled ? pushToken : nil }

    private struct InFlight {
        let id = UUID()
        let action: Action
        let machineId: String
        let task: Task<OperationResult, Never>
    }

    private var inFlight: InFlight?
    private var autoUnlockTask: Task<Void, Never>?
    private var smartTask: Task<OperationResult?, Never>?
    private var liveRefresh: Task<Void, Never>?
    private var cameFromBackground = true

    private init() {
        let defaults = UserDefaults.standard
        machines = defaults.data(forKey: Defaults.machines).flatMap { try? JSONDecoder().decode([PairedMachine].self, from: $0) } ?? []
        autoUnlockOnOpen = defaults.object(forKey: Defaults.autoUnlock) as? Bool ?? true
        notificationsEnabled = defaults.bool(forKey: Defaults.notifications)
        pushToken = defaults.string(forKey: Defaults.pushToken)
    }

    func state(for machine: PairedMachine) -> OperationState {
        states[machine.machineId] ?? .idle
    }

    func approvalState(for waiting: WaitingApproval) -> OperationState {
        approvalStates[waiting.id] ?? .idle
    }

    var waitingApprovals: [WaitingApproval] {
        let now = Date()
        return machines.flatMap { machine -> [WaitingApproval] in
            guard let status = statuses[machine.machineId] else { return [] }
            return status.approvals.map {
                // Computers wait two minutes at most; the bound also keeps a bad value from the relay harmless.
                WaitingApproval(machine: machine, approval: $0,
                                expiresAt: status.checkedAt.addingTimeInterval(TimeInterval(min(max($0.expiresIn, 0), 300))))
            }
        }
        .filter { $0.expiresAt > now }
    }

    var lockedMachines: [PairedMachine] {
        machines.filter { statuses[$0.machineId]?.locked == true }
    }

    // MARK: - Asking the computers (no Face ID)

    /// Asks every paired computer whether it's locked and what it's waiting for, all at once.
    func refresh() async {
        // Sending "" when notifications or the card are off makes the computers forget them.
        let token = notificationsEnabled ? pushToken : ""
        let card = LiveCardController.shared.cardIdForComputers
        let results = await withTaskGroup(of: (PairedMachine, Result<HelloResponse, Error>).self) { group in
            for machine in machines {
                group.addTask {
                    do {
                        return (machine, .success(try await machine.client.hello(deviceId: machine.deviceId, pushToken: token, cardId: card)))
                    } catch {
                        return (machine, .failure(error))
                    }
                }
            }
            return await group.reduce(into: []) { $0.append($1) }
        }
        // Cancelled because you tapped something meanwhile: the failed requests say nothing about the computers.
        guard !Task.isCancelled else { return }
        for (machine, result) in results {
            switch result {
            case .success(let hello):
                statuses[machine.machineId] = MachineStatus(locked: hello.locked, approvals: hello.approvals ?? [])
                if hello.machineName != machine.machineName {
                    update(machine.machineId) { $0.machineName = hello.machineName }
                }
            case .failure(let error):
                statuses[machine.machineId] = MachineStatus(error: Self.describe(error))
            }
        }
        await LiveCardController.shared.show(liveCardContent)
    }

    /// What the lock screen card shows, as far as the app knows.
    var liveCardContent: LiveCardAttributes.ContentState {
        let computers = machines.map { machine -> LiveCardAttributes.ContentState.Computer in
            let status = statuses[machine.machineId]
            let state: LiveCardAttributes.ContentState.Computer.State = switch (status?.error, status?.locked) {
            case (.some, _): .offline
            case (nil, true?): .locked
            case (nil, false?): .unlocked
            default: .unknown
            }
            return .init(id: machine.machineId, name: machine.machineName, state: state)
        }
        let requests = waitingApprovals.prefix(3).map {
            LiveCardAttributes.ContentState.Request(computer: $0.machine.machineId, id: $0.approval.id, title: $0.approval.title,
                                                    detail: $0.approval.detail, until: Int($0.expiresAt.timeIntervalSince1970))
        }
        return .init(computers: computers, requests: Array(requests), key: LiveCardController.shared.key)
    }

    /// Opening the app (or tapping the notification, Siri or the Action button) unlocks the one locked computer.
    /// Requests waiting for you only show up: approving one always takes a tap on Approve, so you see what it is.
    @discardableResult
    func smartOpen() async -> OperationResult? {
        if let smartTask { return await smartTask.value }
        let task = Task { await runSmartOpen() }
        smartTask = task
        let result = await task.value
        smartTask = nil
        return result
    }

    private func runSmartOpen() async -> OperationResult? {
        await refresh()
        let waiting = waitingApprovals
        let locked = lockedMachines
        switch (waiting.count, locked.count) {
        case (0, 1):
            return await perform(.unlock, on: locked[0], isAutomatic: true)
        case (0, 0):
            // An older computer doesn't say whether it's locked: unlock it if it's the only one, as before.
            if machines.count == 1, let machine = machines.first, let status = statuses[machine.machineId],
               status.error == nil, status.locked == nil {
                return await perform(.unlock, on: machine, isAutomatic: true)
            }
            return nil
        default:
            return nil
        }
    }

    // MARK: - Unlock and lock

    /// Runs `action` with Face ID. A second identical request while one is running waits for that one instead.
    @discardableResult
    func perform(_ action: Action, on machine: PairedMachine, isAutomatic: Bool = false) async -> OperationResult {
        if !isAutomatic { autoUnlockTask?.cancel() }
        while let current = inFlight {
            if current.action == action && current.machineId == machine.machineId { return await current.task.value }
            _ = await current.task.value
        }
        let operation = InFlight(action: action, machineId: machine.machineId, task: Task { [weak self] in
            await self?.run(action, on: machine) ?? OperationResult(success: false, message: "Cancelled")
        })
        inFlight = operation
        let result = await operation.task.value
        if inFlight?.id == operation.id { inFlight = nil }
        return result
    }

    /// For Siri, Shortcuts and the Action button. Without a computer, unlocking does what's waiting (see
    /// `smartOpen`) and locking uses the first one paired.
    func perform(_ action: Action, onMachineWithId machineId: String?) async -> OperationResult {
        if machineId == nil, action == .unlock, !machines.isEmpty {
            autoUnlockTask?.cancel()
            return await smartOpen() ?? OperationResult(success: true, message: waitingSummary)
        }
        guard let machine = machines.first(where: { $0.machineId == machineId }) ?? machines.first else {
            return OperationResult(success: false, message: "Pair \(Brand.name) with a computer first.")
        }
        return await perform(action, on: machine)
    }

    /// What's left after a smart open that didn't act, for Siri.
    private var waitingSummary: String {
        let waiting = waitingApprovals.count, locked = lockedMachines.count
        if waiting > 0 { return "Open \(Brand.name) to approve: \(waiting) request(s) waiting." }
        if locked == 0 { return "Nothing is locked or waiting." }
        return "Open \(Brand.name) to choose: \(locked) computers are locked."
    }

    private func run(_ action: Action, on machine: PairedMachine) async -> OperationResult {
        states[machine.machineId] = .working(action == .unlock ? "Unlocking…" : "Locking…")
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        let reason = action == .unlock ? "Unlock \(machine.machineName)" : "Lock \(machine.machineName)"

        // Ask for Face ID while fetching the challenge, so the two waits overlap.
        async let approval = context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
        let result: OperationResult
        do {
            let hello: HelloResponse
            do {
                hello = try await machine.client.hello(deviceId: machine.deviceId)
            } catch {
                context.invalidate() // dismisses the Face ID sheet
                _ = try? await approval
                throw error
            }
            _ = try await approval

            let request = try signedCommand(action, on: machine, hello: hello, context: context)
            let response = try await machine.client.command(action, nonce: hello.nonce, signature: request.signature, deviceId: machine.deviceId,
                                                            passwordKey: request.passwordKey, wrappedKey: request.wrappedKey)
            if hello.machineName != machine.machineName {
                update(machine.machineId) { $0.machineName = hello.machineName }
            }
            result = OperationResult(success: response.ok, message: response.message)
        } catch {
            result = OperationResult(success: false, message: Self.describe(error))
        }
        states[machine.machineId] = .finished(result)
        if result.success, action != .status {
            statuses[machine.machineId]?.locked = action == .lock
            await LiveCardController.shared.set(machine.machineId, to: action == .lock ? .locked : .unlocked)
        }
        haptic(for: result)
        return result
    }

    private struct SignedCommand {
        var signature: Data
        var passwordKey: String?
        var wrappedKey: WrappedKey?
    }

    /// Signs `action` for `hello`'s challenge. For a computer that seals its password (`PasswordSeal`) it also sends
    /// the password key it asked for, and for an unlock the key that opens the password, wrapped to the challenge's
    /// session key. `context` must already have passed Face ID.
    private func signedCommand(_ action: Action, on machine: PairedMachine, hello: HelloResponse, context: LAContext) throws -> SignedCommand {
        let passwordKey = hello.wantsPasswordKey == true ? try DeviceKey.passwordKey(tag: machine.deviceId).base64EncodedString() : nil
        var wrappedKey: WrappedKey?
        if action == .unlock, let sealed = hello.sealedPassword, let sealKey = Data(base64Encoded: sealed.sealKey) {
            let secret = try DeviceKey.passwordSecret(with: sealKey, tag: machine.deviceId, context: context)
            let key = PasswordSeal.passwordKey(sharedSecret: secret, sealKey: sealKey, machineId: machine.machineId, deviceId: machine.deviceId)
            wrappedKey = try PasswordSeal.wrap(key, sessionKey: sealed.sessionKey, machineId: machine.machineId,
                                               deviceId: machine.deviceId, nonce: hello.nonce)
        }
        let message = SignedMessage.bytes(machineId: machine.machineId, deviceId: machine.deviceId, action: action, nonce: hello.nonce,
                                          sessionKey: hello.sealedPassword?.sessionKey, passwordKey: passwordKey, wrappedKey: wrappedKey)
        return SignedCommand(signature: try DeviceKey.sign(message, tag: machine.deviceId, context: context),
                             passwordKey: passwordKey, wrappedKey: wrappedKey)
    }

    private func haptic(for result: OperationResult) {
        if result.success {
            UINotificationFeedbackGenerator().notificationOccurred(.success)
        } else if result.message != "Cancelled" {
            UINotificationFeedbackGenerator().notificationOccurred(.error)
        }
    }

    /// Unlocks every locked computer with one Face ID.
    @discardableResult
    func unlockAll() async -> OperationResult {
        autoUnlockTask?.cancel()
        let targets = lockedMachines
        guard !targets.isEmpty, inFlight == nil, !targets.contains(where: { if case .working = state(for: $0) { true } else { false } }) else {
            return OperationResult(success: false, message: "Nothing to unlock right now.")
        }
        for machine in targets { states[machine.machineId] = .working("Unlocking…") }
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        let names = ListFormatter.localizedString(byJoining: targets.map(\.machineName))

        // As with one computer: fetch the challenges while Face ID runs.
        async let approval = context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Unlock \(names)")
        let hellos = await withTaskGroup(of: (String, Result<HelloResponse, Error>).self) { group in
            for machine in targets {
                group.addTask {
                    do { return (machine.machineId, .success(try await machine.client.hello(deviceId: machine.deviceId))) }
                    catch { return (machine.machineId, .failure(error)) }
                }
            }
            return await group.reduce(into: [String: Result<HelloResponse, Error>]()) { $0[$1.0] = $1.1 }
        }
        do {
            _ = try await approval
        } catch {
            let result = OperationResult(success: false, message: Self.describe(error))
            for machine in targets { states[machine.machineId] = .finished(result) }
            haptic(for: result)
            return result
        }

        var requests: [(PairedMachine, String, SignedCommand)] = []
        for machine in targets {
            do {
                let hello = try hellos[machine.machineId]!.get()
                requests.append((machine, hello.nonce, try signedCommand(.unlock, on: machine, hello: hello, context: context)))
            } catch {
                states[machine.machineId] = .finished(OperationResult(success: false, message: Self.describe(error)))
            }
        }
        let results = await withTaskGroup(of: (String, OperationResult).self) { group in
            for (machine, nonce, request) in requests {
                group.addTask {
                    do {
                        let response = try await machine.client.command(.unlock, nonce: nonce, signature: request.signature,
                                                                        deviceId: machine.deviceId, passwordKey: request.passwordKey,
                                                                        wrappedKey: request.wrappedKey)
                        return (machine.machineId, OperationResult(success: response.ok, message: response.message))
                    } catch {
                        return (machine.machineId, OperationResult(success: false, message: Self.describe(error)))
                    }
                }
            }
            return await group.reduce(into: [String: OperationResult]()) { $0[$1.0] = $1.1 }
        }
        for (machineId, result) in results {
            states[machineId] = .finished(result)
            if result.success {
                statuses[machineId]?.locked = false
                await LiveCardController.shared.set(machineId, to: .unlocked)
            }
        }
        let failed = targets.count - results.values.filter(\.success).count
        let result = failed == 0
            ? OperationResult(success: true, message: "Unlocked \(names)")
            : OperationResult(success: false, message: "\(failed) of \(targets.count) didn't unlock")
        haptic(for: result)
        return result
    }

    // MARK: - Approvals

    /// Approves a waiting password prompt with Face ID. The computer verifies the signature.
    @discardableResult
    func approve(_ waiting: WaitingApproval) async -> OperationResult {
        autoUnlockTask?.cancel()
        if case .working = approvalState(for: waiting) { return OperationResult(success: false, message: "Already approving") }
        approvalStates[waiting.id] = .working("Approving…")
        let machine = waiting.machine, approval = waiting.approval
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        let title = approval.title.count > 60 ? String(approval.title.prefix(59)) + "…" : approval.title
        let result: OperationResult
        var sent = false
        do {
            try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Approve “\(title)” on \(machine.machineName)")
            let message = ApprovalMessage.bytes(machineId: machine.machineId, deviceId: machine.deviceId, approval: approval)
            let signature = try DeviceKey.sign(message, tag: machine.deviceId, context: context)
            sent = true
            let response = try await machine.client.approve(approval, signature: signature, deviceId: machine.deviceId)
            result = OperationResult(success: response.ok, message: response.ok ? "Approved on \(machine.machineName)" : response.message)
        } catch {
            result = OperationResult(success: false, message: Self.describe(error))
        }
        finish(waiting, with: result, answered: sent)
        return result
    }

    /// Makes the computer stop waiting and ask for its password. No Face ID needed.
    func deny(_ waiting: WaitingApproval) async {
        autoUnlockTask?.cancel()
        approvalStates[waiting.id] = .working("Denying…")
        let result: OperationResult
        do {
            let response = try await waiting.machine.client.deny(waiting.approval, deviceId: waiting.machine.deviceId)
            result = OperationResult(success: response.ok, message: response.message)
        } catch {
            result = OperationResult(success: false, message: Self.describe(error))
        }
        finish(waiting, with: result, answered: true)
    }

    /// `answered`: the answer went to the computer. If Face ID stopped it before that, the request is still waiting.
    private func finish(_ waiting: WaitingApproval, with result: OperationResult, answered: Bool) {
        approvalStates[waiting.id] = .finished(result)
        if answered {
            statuses[waiting.machine.machineId]?.approvals.removeAll { $0.id == waiting.id }
            states[waiting.machine.machineId] = .finished(result)
            Task { await LiveCardController.shared.remove(request: waiting.id) }
        }
        haptic(for: result)
    }

    nonisolated static func describe(_ error: Error) -> String {
        if let error = error as? LAError {
            switch error.code {
            case .userCancel, .appCancel, .systemCancel: return "Cancelled"
            case .biometryNotEnrolled: return "Set up \(Biometry.name) in Settings first."
            case .biometryNotAvailable: return "\(Biometry.name) isn't available. Allow it for \(Brand.name) in Settings."
            case .biometryLockout: return "\(Biometry.name) is locked. Unlock your iPhone with its passcode, then try again."
            case .authenticationFailed: return "\(Biometry.name) didn't recognise you."
            default: return error.localizedDescription
            }
        }
        if let error = error as? LocalizedError, let description = error.errorDescription { return description }
        return "Couldn't sign the request. If you changed \(Biometry.name) since pairing, pair this iPhone again."
    }

    // MARK: - Pairing

    func handle(url: URL) {
        autoUnlockTask?.cancel()
        guard url.scheme == Brand.urlScheme else { return }
        switch url.host {
        case "card":
            if let link = LiveCardLink(url: url, key: LiveCardController.shared.key) { Task { await open(link) } }
        default:
            if let invite = invite(from: url.absoluteString) { pendingInvite = invite }
        }
    }

    /// A button on the lock screen card that needs Face ID, which opened the app.
    private func open(_ link: LiveCardLink) async {
        switch link {
        case .open(let request):
            await refresh()
            scrollTarget = request
        case .unlock(let computer), .lock(let computer):
            guard let machine = machines.first(where: { $0.machineId == computer }) else { return }
            scrollTarget = computer
            let unlocking = link == .unlock(computer: computer)
            // The card shows it working too, for when you go back to the Lock Screen.
            await LiveCardController.shared.setBusy(computer, unlocking ? .unlock : .lock)
            await perform(unlocking ? .unlock : .lock, on: machine)
            await LiveCardController.shared.setBusy(computer, nil)
        case .approve(let computer, let request):
            // The request as the computer has it now, with its challenge; Face ID names it before anything is signed.
            await refresh()
            if let waiting = waitingApprovals.first(where: { $0.machine.machineId == computer && $0.approval.id == request }) {
                scrollTarget = request
                await LiveCardController.shared.setBusy(request, .approve)
                await approve(waiting)
                await LiveCardController.shared.setBusy(request, nil)
            } else if machines.contains(where: { $0.machineId == computer }) {
                states[computer] = .finished(OperationResult(success: false, message: "That request isn't waiting anymore."))
                scrollTarget = computer
            }
        }
    }

    /// Pairs with a code you pasted, after asking if it replaces a pairing.
    func pair(code: String) async {
        autoUnlockTask?.cancel()
        guard let invite = invite(from: code) else { return }
        if pairedMachine(replacedBy: invite) != nil {
            pendingInvite = invite
        } else {
            await pair(invite)
        }
    }

    /// The paired computer that pairing with `invite` would replace.
    func pairedMachine(replacedBy invite: PairingInvite) -> PairedMachine? {
        machines.first { $0.machineId == invite.machineId }
    }

    /// The invite in a pairing code; says so in `pairingResult` if it isn't one.
    private func invite(from code: String) -> PairingInvite? {
        guard let invite = PairingInvite(string: code) else {
            pairingResult = OperationResult(success: false, message: "That isn't a \(Brand.name) pairing code. Update both apps if it should be.")
            return nil
        }
        return invite
    }

    func pair(_ invite: PairingInvite) async {
        pendingInvite = nil
        guard !isPairing else { return }
        isPairing = true
        defer { isPairing = false }

        let deviceId = UUID().uuidString
        do {
            let publicKey = try DeviceKey.create(tag: deviceId)
            do {
                let passwordKey = invite.wantsPasswordKey == true ? try DeviceKey.passwordKey(tag: deviceId) : nil
                let response = try await RelayClient(invite: invite).pair(invite: invite, deviceId: deviceId, deviceName: UIDevice.current.name,
                                                                          publicKey: publicKey, passwordKey: passwordKey)
                if let previous = machines.first(where: { $0.machineId == response.machineId }) {
                    DeviceKey.delete(tag: previous.deviceId)
                }
                machines.removeAll { $0.machineId == response.machineId }
                machines.append(PairedMachine(machineId: response.machineId, machineName: response.machineName,
                                              platform: invite.platform, relay: invite.relay, deviceId: deviceId))
                states[response.machineId] = nil
                save()
                pairingResult = OperationResult(success: true, message: "Paired with \(response.machineName)")
                Task { await refresh() }
            } catch {
                DeviceKey.delete(tag: deviceId)
                throw error
            }
        } catch {
            pairingResult = OperationResult(success: false, message: Self.describe(error))
        }
    }

    func remove(_ machine: PairedMachine) {
        DeviceKey.delete(tag: machine.deviceId)
        machines.removeAll { $0.machineId == machine.machineId }
        states[machine.machineId] = nil
        statuses[machine.machineId] = nil
        save()
    }

    // MARK: - Notifications

    func enableNotifications() async {
        let granted = (try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])) ?? false
        guard granted else {
            notificationsEnabled = false
            notificationProblem = "Allow notifications for \(Brand.name) in Settings, then turn this on again."
            return
        }
        notificationProblem = nil
        UIApplication.shared.registerForRemoteNotifications()
    }

    func registered(pushToken token: String) {
        notificationProblem = nil
        guard token != pushToken, PushToken.isValid(token) else { return }
        pushToken = token
        UserDefaults.standard.set(token, forKey: Defaults.pushToken)
        Task { await refresh() }
    }

    /// Tapping the notification of a waiting approval: do what's waiting, whatever the open setting.
    func openedFromNotification() async {
        autoUnlockTask?.cancel()
        await smartOpen()
    }

    // MARK: - When the app opens

    func scenePhaseChanged(to phase: ScenePhase) {
        if phase == .active { startLiveRefresh() } else { liveRefresh?.cancel() }
        switch phase {
        case .background:
            cameFromBackground = true
            autoUnlockTask?.cancel()
            // "Paired with …" is news for this visit only.
            pairingResult = nil
        case .active:
            // Face ID's own sheet makes the app inactive and active again; only react to real launches.
            guard cameFromBackground else { return }
            cameFromBackground = false
            // The app shows what's waiting now, so its notifications are done.
            UNUserNotificationCenter.current().removeAllDeliveredNotifications()
            guard !machines.isEmpty, inFlight == nil else { return }
            // Brief delay so a pairing link, notification or Shortcut that opened the app can cancel this first.
            autoUnlockTask = Task { [weak self] in
                try? await Task.sleep(nanoseconds: 400_000_000)
                guard !Task.isCancelled, let self, self.inFlight == nil else { return }
                if self.autoUnlockOnOpen {
                    await self.smartOpen()
                } else {
                    await self.refresh()
                }
            }
        default:
            break
        }
    }

    /// While the app is on screen, new requests (say, a sudo you just typed) show up within a couple of seconds.
    private func startLiveRefresh() {
        liveRefresh?.cancel()
        liveRefresh = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                guard !Task.isCancelled, let self else { return }
                if self.inFlight == nil, self.smartTask == nil, !self.machines.isEmpty { await self.refresh() }
            }
        }
    }

    // MARK: - Storage

    private func update(_ machineId: String, _ change: (inout PairedMachine) -> Void) {
        guard let index = machines.firstIndex(where: { $0.machineId == machineId }) else { return }
        change(&machines[index])
        save()
    }

    private func save() {
        UserDefaults.standard.set(try? JSONEncoder().encode(machines), forKey: Defaults.machines)
    }
}
