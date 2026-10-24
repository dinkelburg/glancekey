import FaceUnlockCore
import Foundation
import LocalAuthentication
import SwiftUI
import UIKit

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

@MainActor
final class PhoneModel: ObservableObject {
    static let shared = PhoneModel()

    private enum Defaults {
        static let machines = "pairedMachines"
        static let autoUnlock = "autoUnlockOnOpen"
    }

    @Published private(set) var machines: [PairedMachine]
    @Published private(set) var states: [String: OperationState] = [:]
    @Published private(set) var isPairing = false
    @Published var pairingResult: OperationResult?
    @Published var autoUnlockOnOpen: Bool {
        didSet { UserDefaults.standard.set(autoUnlockOnOpen, forKey: Defaults.autoUnlock) }
    }

    private struct InFlight {
        let id = UUID()
        let action: Action
        let machineId: String
        let task: Task<OperationResult, Never>
    }

    private var inFlight: InFlight?
    private var autoUnlockTask: Task<Void, Never>?
    private var cameFromBackground = true

    private init() {
        let defaults = UserDefaults.standard
        machines = defaults.data(forKey: Defaults.machines).flatMap { try? JSONDecoder().decode([PairedMachine].self, from: $0) } ?? []
        autoUnlockOnOpen = defaults.object(forKey: Defaults.autoUnlock) as? Bool ?? true
    }

    func state(for machine: PairedMachine) -> OperationState {
        states[machine.machineId] ?? .idle
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

    /// For Siri, Shortcuts and the Action button. Without a computer, uses the first one paired.
    func perform(_ action: Action, onMachineWithId machineId: String?) async -> OperationResult {
        guard let machine = machines.first(where: { $0.machineId == machineId }) ?? machines.first else {
            return OperationResult(success: false, message: "Pair FaceUnlock with a computer first.")
        }
        return await perform(action, on: machine)
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

            let message = SignedMessage.bytes(machineId: machine.machineId, deviceId: machine.deviceId, action: action, nonce: hello.nonce)
            let signature = try DeviceKey.sign(message, tag: machine.deviceId, context: context)
            let response = try await machine.client.command(action, nonce: hello.nonce, signature: signature, deviceId: machine.deviceId)
            if hello.machineName != machine.machineName {
                update(machine.machineId) { $0.machineName = hello.machineName }
            }
            result = OperationResult(success: response.ok, message: response.message)
        } catch {
            result = OperationResult(success: false, message: describe(error))
        }
        states[machine.machineId] = .finished(result)
        if result.success {
            UINotificationFeedbackGenerator().notificationOccurred(.success)
        } else if result.message != "Cancelled" {
            UINotificationFeedbackGenerator().notificationOccurred(.error)
        }
        return result
    }

    private func describe(_ error: Error) -> String {
        if let error = error as? LAError {
            switch error.code {
            case .userCancel, .appCancel, .systemCancel: return "Cancelled"
            case .biometryNotEnrolled: return "Set up Face ID in Settings first."
            case .biometryNotAvailable: return "Face ID isn't available. Allow it for FaceUnlock in Settings."
            case .biometryLockout: return "Face ID is locked. Unlock your iPhone with its passcode, then try again."
            case .authenticationFailed: return "Face ID didn't recognise you."
            default: return error.localizedDescription
            }
        }
        if let error = error as? LocalizedError, let description = error.errorDescription { return description }
        return "Couldn't sign the request. If you changed Face ID since pairing, pair this iPhone again."
    }

    // MARK: - Pairing

    func handle(url: URL) {
        autoUnlockTask?.cancel()
        guard url.scheme == FaceUnlockProtocol.urlScheme else { return }
        Task { await pair(code: url.absoluteString) }
    }

    func pair(code: String) async {
        autoUnlockTask?.cancel()
        guard let invite = PairingInvite(string: code) else {
            pairingResult = OperationResult(success: false, message: "That isn't a FaceUnlock pairing code. Update both apps if it should be.")
            return
        }
        guard !isPairing else { return }
        isPairing = true
        defer { isPairing = false }

        let deviceId = UUID().uuidString
        do {
            let publicKey = try DeviceKey.create(tag: deviceId)
            do {
                let response = try await RelayClient(invite: invite).pair(invite: invite, deviceId: deviceId,
                                                                          deviceName: UIDevice.current.name, publicKey: publicKey)
                if let previous = machines.first(where: { $0.machineId == response.machineId }) {
                    DeviceKey.delete(tag: previous.deviceId)
                }
                machines.removeAll { $0.machineId == response.machineId }
                machines.append(PairedMachine(machineId: response.machineId, machineName: response.machineName,
                                              platform: invite.platform, relay: invite.relay, deviceId: deviceId))
                states[response.machineId] = nil
                save()
                pairingResult = OperationResult(success: true, message: "Paired with \(response.machineName)")
            } catch {
                DeviceKey.delete(tag: deviceId)
                throw error
            }
        } catch {
            pairingResult = OperationResult(success: false, message: describe(error))
        }
    }

    func remove(_ machine: PairedMachine) {
        DeviceKey.delete(tag: machine.deviceId)
        machines.removeAll { $0.machineId == machine.machineId }
        states[machine.machineId] = nil
        save()
    }

    // MARK: - Unlock when the app opens

    func scenePhaseChanged(to phase: ScenePhase) {
        switch phase {
        case .background:
            cameFromBackground = true
            autoUnlockTask?.cancel()
        case .active:
            // Face ID's own sheet makes the app inactive and active again; only react to real launches.
            guard cameFromBackground else { return }
            cameFromBackground = false
            guard autoUnlockOnOpen, let machine = machines.first, inFlight == nil else { return }
            // Brief delay so a pairing link or Shortcut that opened the app can cancel this first.
            autoUnlockTask = Task { [weak self] in
                try? await Task.sleep(nanoseconds: 400_000_000)
                guard !Task.isCancelled, let self, self.inFlight == nil else { return }
                await self.perform(.unlock, on: machine, isAutomatic: true)
            }
        default:
            break
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
