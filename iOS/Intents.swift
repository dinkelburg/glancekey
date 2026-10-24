import AppIntents
import FaceUnlockCore

// Shortcuts, Siri, Spotlight and the Action button. They open the app because Face ID needs it on screen.

struct ComputerEntity: AppEntity {
    static let typeDisplayRepresentation: TypeDisplayRepresentation = "Computer"
    static let defaultQuery = ComputerQuery()

    let id: String
    let name: String

    var displayRepresentation: DisplayRepresentation { DisplayRepresentation(title: "\(name)") }
}

struct ComputerQuery: EntityQuery {
    @MainActor
    func entities(for identifiers: [String]) async throws -> [ComputerEntity] {
        PhoneModel.shared.machines
            .filter { identifiers.contains($0.machineId) }
            .map { ComputerEntity(id: $0.machineId, name: $0.machineName) }
    }

    @MainActor
    func suggestedEntities() async throws -> [ComputerEntity] {
        PhoneModel.shared.machines.map { ComputerEntity(id: $0.machineId, name: $0.machineName) }
    }
}

struct UnlockComputerIntent: AppIntent {
    static let title: LocalizedStringResource = "Unlock Computer"
    static let description = IntentDescription("Unlocks a paired computer after Face ID. Leave Computer empty to use the first one.")
    static let openAppWhenRun = true

    @Parameter(title: "Computer")
    var computer: ComputerEntity?

    static var parameterSummary: some ParameterSummary {
        Summary("Unlock \(\.$computer)")
    }

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        let result = await PhoneModel.shared.perform(.unlock, onMachineWithId: computer?.id)
        return .result(dialog: "\(result.message)")
    }
}

struct LockComputerIntent: AppIntent {
    static let title: LocalizedStringResource = "Lock Computer"
    static let description = IntentDescription("Locks a paired computer after Face ID. Leave Computer empty to use the first one.")
    static let openAppWhenRun = true

    @Parameter(title: "Computer")
    var computer: ComputerEntity?

    static var parameterSummary: some ParameterSummary {
        Summary("Lock \(\.$computer)")
    }

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        let result = await PhoneModel.shared.perform(.lock, onMachineWithId: computer?.id)
        return .result(dialog: "\(result.message)")
    }
}

struct FaceUnlockShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(intent: UnlockComputerIntent(), phrases: ["Unlock my computer with \(.applicationName)"],
                    shortTitle: "Unlock Computer", systemImageName: "lock.open")
        AppShortcut(intent: LockComputerIntent(), phrases: ["Lock my computer with \(.applicationName)"],
                    shortTitle: "Lock Computer", systemImageName: "lock")
    }
}
