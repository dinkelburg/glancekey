import ActivityKit
import AppCore
import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var model: PhoneModel
    @State private var showingAddComputer = false
    @State private var showingSettings = false
    /// `model.offer` once it's on screen: the other sheets close first.
    @State private var shownOffer: UnlimitedOffer?
    /// The computer pages open on top of the list.
    @State private var path: [String] = []

    var body: some View {
        NavigationStack(path: $path) {
            Group {
                if model.machines.isEmpty {
                    ScrollView {
                        VStack(spacing: 32) {
                            PairingView()
                            AboutLinks()
                        }
                        .padding()
                    }
                    // Its own heading says what the app does; a title would only repeat the app's name. Settings is
                    // here too, so the subscription and help can be found before pairing.
                    .toolbar {
                        ToolbarItem(placement: .topBarTrailing) { settingsButton }
                    }
                } else {
                    machineList
                        .navigationTitle("Computers")
                        // On the same line as + and Settings, not on its own below them.
                        .toolbarTitleDisplayMode(.inlineLarge)
                        .toolbar {
                            ToolbarItemGroup(placement: .topBarTrailing) {
                                Button {
                                    model.pairingResult = nil
                                    showingAddComputer = true
                                } label: {
                                    Image(systemName: "plus")
                                }
                                .accessibilityLabel("Add a computer")
                                settingsButton
                            }
                        }
                        .navigationDestination(for: String.self) { MachineDetail(machineId: $0) }
                }
            }
            .sheet(isPresented: $showingAddComputer, onDismiss: showOffer) {
                NavigationStack {
                    ScrollView { PairingView().padding() }
                        .navigationTitle("Add a computer")
                        .navigationBarTitleDisplayMode(.inline)
                        .toolbar {
                            ToolbarItem(placement: .cancellationAction) { Button("Done") { showingAddComputer = false } }
                        }
                }
            }
            .sheet(isPresented: $showingSettings, onDismiss: showOffer) { SettingsView() }
            .sheet(item: $shownOffer, onDismiss: { model.offer = nil }) { UnlimitedView(offer: $0) }
            .onChange(of: model.offer?.id) {
                if model.offer == nil {
                    shownOffer = nil
                } else if showingAddComputer || showingSettings {
                    showingAddComputer = false
                    showingSettings = false
                } else {
                    showOffer()
                }
            }
            .onChange(of: model.pairingResult) { _, result in
                if result?.success == true { showingAddComputer = false }
            }
            .alert("Pair with \(model.pendingInvite?.machineName ?? "this computer")?", isPresented: isConfirmingPairing,
                   presenting: model.pendingInvite) { invite in
                Button("Pair") { Task { await model.pair(invite) } }
                Button("Cancel", role: .cancel) {}
            } message: { invite in
                if let paired = model.pairedMachine(replacedBy: invite) {
                    Text("This iPhone is already paired with \(paired.machineName). Pairing again replaces that pairing.")
                } else {
                    Text("Only pair if you just clicked Pair iPhone on that computer.")
                }
            }
        }
    }

    private var settingsButton: some View {
        Button {
            showingSettings = true
        } label: {
            Image(systemName: "gearshape")
        }
        .accessibilityLabel("Settings")
    }

    private func showOffer() {
        if let offer = model.offer { shownOffer = offer }
    }

    private var isConfirmingPairing: Binding<Bool> {
        Binding(get: { model.pendingInvite != nil }, set: { if !$0 { model.pendingInvite = nil } })
    }

    /// What's happening: requests waiting for you, then a row per computer. Everything else is in Settings.
    private var machineList: some View {
        ScrollViewReader { proxy in
            List {
                if let result = model.pairingResult {
                    Section {
                        Label(result.message, systemImage: result.success ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                            .foregroundStyle(result.success ? .green : .orange)
                    }
                }
                if !model.waitingApprovals.isEmpty {
                    Section {
                        ForEach(model.waitingApprovals) { waiting in
                            ApprovalCard(waiting: waiting)
                                .id(waiting.id)
                        }
                    }
                }
                Section {
                    ForEach(model.machines) { machine in
                        MachineRow(machine: machine)
                            .id(machine.machineId)
                    }
                    if model.lockedMachines.count > 1 {
                        Button {
                            Task { await model.unlockAll() }
                        } label: {
                            Label("Unlock all \(model.lockedMachines.count)", systemImage: Biometry.symbol)
                        }
                    }
                }
            }
            .refreshable { await model.refresh() }
            .onChange(of: model.scrollTarget) { _, target in
                guard let target else { return }
                // A card button opened the app: what it's about may be behind a computer's page or a sheet.
                path.removeAll()
                showingSettings = false
                showingAddComputer = false
                withAnimation { proxy.scrollTo(target, anchor: .top) }
                model.scrollTarget = nil
            }
        }
    }
}

private struct ApprovalCard: View {
    @EnvironmentObject private var model: PhoneModel
    let waiting: WaitingApproval

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: waiting.machine.symbolName)
                Text(waiting.machine.machineName).font(.subheadline.weight(.semibold))
                Spacer()
                if ApprovalWait.showsCountdown(until: waiting.expiresAt) {
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        let left = Int(waiting.expiresAt.timeIntervalSince(context.date).rounded(.up))
                        Text(left > 0 ? "\(left) s" : "Expired")
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                }
            }
            Text(waiting.approval.title)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
            Text(waiting.approval.detail)
                .font(.footnote)
                .foregroundStyle(.secondary)
            HStack {
                Button {
                    Task { await model.approve(waiting) }
                } label: {
                    Text("Approve")
                        .frame(maxWidth: .infinity, minHeight: 36)
                }
                .buttonStyle(.borderedProminent)
                Button(role: .destructive) {
                    Task { await model.deny(waiting) }
                } label: {
                    Text("Deny")
                        .frame(maxWidth: .infinity, minHeight: 36)
                }
                .buttonStyle(.bordered)
            }
            .disabled(isWorking)
            switch model.approvalState(for: waiting) {
            case .working(let text):
                HStack(spacing: 6) {
                    ProgressView()
                    Text(text)
                }
                .font(.footnote)
                .foregroundStyle(.secondary)
            case .finished(let result) where !result.success:
                Label(result.message, systemImage: "exclamationmark.triangle.fill")
                    .font(.footnote)
                    .foregroundStyle(.orange)
            default:
                EmptyView()
            }
        }
        .padding(.vertical, 6)
    }

    private var isWorking: Bool {
        if case .working = model.approvalState(for: waiting) { return true }
        return false
    }
}

/// A computer in the list: whether it's locked and the one button you'd want, Unlock or Lock. Tapping the row opens
/// everything else (`MachineDetail`).
private struct MachineRow: View {
    @EnvironmentObject private var model: PhoneModel
    let machine: PairedMachine

    var body: some View {
        NavigationLink(value: machine.machineId) {
            HStack(spacing: 10) {
                Circle()
                    .fill(color)
                    .frame(width: 8, height: 8)
                VStack(alignment: .leading, spacing: 2) {
                    Text(machine.machineName)
                        .font(.body.weight(.semibold))
                    MachineStatusText(machine: machine, brief: true)
                        .font(.footnote)
                }
                Spacer(minLength: 8)
                actionButton
            }
            .padding(.vertical, 2)
        }
    }

    private var isLocked: Bool? { model.statuses[machine.machineId]?.locked }

    /// Unlock unless it's known to be unlocked.
    private var actionButton: some View {
        let unlocks = isLocked != false
        return Button {
            Task { await model.perform(unlocks ? .unlock : .lock, on: machine) }
        } label: {
            Text(unlocks ? "Unlock" : "Lock")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(unlocks ? .white : .primary)
                .padding(.horizontal, 14)
                .padding(.vertical, 6)
                .background(Capsule().fill(unlocks ? Color.accentColor : Color(.tertiarySystemFill)))
        }
        // Its own tap target inside the row's link.
        .buttonStyle(.borderless)
        .disabled(model.isWorking(on: machine))
    }

    private var color: Color {
        switch (model.statuses[machine.machineId]?.error, isLocked) {
        case (.some, _): .gray
        case (nil, true?): .orange
        case (nil, false?): .green
        default: .gray
        }
    }
}

/// What a computer is doing or last did, or else whether it's locked. `brief` keeps it to a word for the list.
private struct MachineStatusText: View {
    @EnvironmentObject private var model: PhoneModel
    let machine: PairedMachine
    let brief: Bool

    var body: some View {
        switch model.state(for: machine) {
        case .working(let text):
            HStack(spacing: 6) {
                ProgressView()
                    .controlSize(.mini)
                Text(text)
            }
            .foregroundStyle(.secondary)
        case .finished(let result) where !result.success:
            Text(result.message)
                .foregroundStyle(.orange)
                .lineLimit(brief ? 1 : nil)
        default:
            if let error = model.statuses[machine.machineId]?.error {
                Text(brief ? "Can't be reached" : error)
                    .foregroundStyle(.orange)
            } else if let locked = model.statuses[machine.machineId]?.locked {
                Text(locked ? "Locked" : "Unlocked")
                    .foregroundStyle(.secondary)
            } else {
                Text(machine.kind)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

/// Everything for one computer: unlocking, locking and removing it.
private struct MachineDetail: View {
    @EnvironmentObject private var model: PhoneModel
    @Environment(\.dismiss) private var dismiss
    @State private var confirmingRemoval = false
    let machineId: String

    var body: some View {
        if let machine = model.machines.first(where: { $0.machineId == machineId }) {
            List {
                Section {
                    LabeledContent("Status") {
                        MachineStatusText(machine: machine, brief: false)
                            .multilineTextAlignment(.trailing)
                    }
                    LabeledContent("Kind", value: machine.kind)
                } footer: {
                    // The computer lists this iPhone with the same key, so one paired behind your back stands out there.
                    if let key = try? DeviceKey.publicKey(tag: machine.deviceId) {
                        Text("This iPhone's key: \(PairedDevice.keyFingerprint(key)). \(machine.machineName) shows the same next to this iPhone.")
                    }
                }
                // Unknown while the computer can't be reached.
                if let status = model.statuses[machine.machineId], status.error == nil {
                    approvalWaitSection(machine, wait: status.approvalWait)
                }
                Section {
                    Button {
                        Task { await model.perform(.unlock, on: machine) }
                    } label: {
                        Label("Unlock", systemImage: Biometry.symbol)
                    }
                    Button {
                        Task { await model.perform(.lock, on: machine) }
                    } label: {
                        Label("Lock", systemImage: "lock")
                    }
                }
                .disabled(model.isWorking(on: machine))
                Section {
                    Button("Remove \(machine.machineName)", role: .destructive) { confirmingRemoval = true }
                } footer: {
                    Text("This iPhone won't be able to unlock it until you pair again. Also remove this iPhone on the computer.")
                }
            }
            .navigationTitle(machine.machineName)
            .navigationBarTitleDisplayMode(.inline)
            .refreshable { await model.refresh() }
            .confirmationDialog("Remove \(machine.machineName)?", isPresented: $confirmingRemoval, titleVisibility: .visible) {
                Button("Remove", role: .destructive) {
                    dismiss()
                    model.remove(machine)
                }
            }
        }
    }

    /// How long its approvals wait, changeable here once the computer runs a version that says.
    private func approvalWaitSection(_ machine: PairedMachine, wait: Int?) -> some View {
        Section {
            if let wait {
                Picker("Wait for approval", selection: Binding(get: { wait }, set: { choice in
                    Task { await model.setApprovalWait(choice, on: machine) }
                })) {
                    ForEach(ApprovalWait.choices, id: \.self) { Text(ApprovalWait.name($0)).tag($0) }
                }
            } else {
                // An older version on the computer waits 30 seconds and can't be changed from here.
                LabeledContent("Wait for approval", value: ApprovalWait.name(ApprovalWait.choices[0]))
            }
        } footer: {
            if wait == nil {
                Text("To change this from your iPhone, update \(Brand.name) on \(machine.machineName).")
            } else {
                Text("How long sudo and password dialogs on \(machine.machineName) wait for your iPhone before they ask for the password. At the computer, press Enter to type it sooner. Changing it asks for \(Biometry.name).")
            }
        }
    }
}

/// The switches you set once, and the links about the app.
private struct SettingsView: View {
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                UnlimitedSection()
                LiveCardSection()
                NotificationsSection()
                Section {
                    AboutLinks()
                } footer: {
                    Text("Tip: add “Unlock Computer” to the Action button or Control Center in the Shortcuts app.")
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
        }
    }
}

/// The subscription: what's left of today's free use, or managing the subscription.
private struct UnlimitedSection: View {
    @ObservedObject private var store = Store.shared
    @State private var managing = false

    var body: some View {
        Section {
            if store.subscribed {
                LabeledContent("\(Brand.name) Unlimited", value: "On")
                Button("Manage Subscription") { managing = true }
            } else if store.isOwnBuild {
                LabeledContent("\(Brand.name) Unlimited", value: "Not needed")
            } else {
                if let perDay = store.limits.perDay {
                    LabeledContent("Used today", value: "\(min(store.usedToday, perDay)) of \(perDay)")
                }
                NavigationLink("Get \(Brand.name) Unlimited") { UnlimitedView(offer: UnlimitedOffer(reason: .asked)) }
            }
        } footer: {
            if store.subscribed {
                Text("Unlock and approve as often as you like, on as many computers as you like.")
            } else if store.isOwnBuild {
                Text("This copy of \(Brand.name) wasn't installed from the App Store, so it has no limits.")
            } else {
                Text("\(store.freeSummary) Computers on a relay you host yourself have no limits.")
            }
        }
        .manageSubscriptionsSheet(isPresented: $managing)
    }
}

private struct LiveCardSection: View {
    @EnvironmentObject private var model: PhoneModel
    @Environment(\.scenePhase) private var scenePhase
    @State private var isAllowed = ActivityAuthorizationInfo().areActivitiesEnabled

    var body: some View {
        Section {
            Toggle("Show on the Lock Screen", isOn: $model.liveCardEnabled)
            if model.liveCardEnabled && !isAllowed {
                Label("Allow Live Activities for \(Brand.name) in Settings.", systemImage: "exclamationmark.triangle.fill")
                    .font(.footnote)
                    .foregroundStyle(.orange)
                Link("Open Settings", destination: URL(string: UIApplication.openSettingsURLString)!)
            }
        } footer: {
            Text("Your computers and waiting requests on the Lock Screen, with Unlock, Lock and Approve. Requests show the command, which passes through Apple's push service.")
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active { isAllowed = ActivityAuthorizationInfo().areActivitiesEnabled }
        }
    }
}

private struct NotificationsSection: View {
    @EnvironmentObject private var model: PhoneModel

    var body: some View {
        Section {
            Toggle("Notify me", isOn: $model.notificationsEnabled)
            if let problem = model.notificationProblem {
                Label(problem, systemImage: "exclamationmark.triangle.fill")
                    .font(.footnote)
                    .foregroundStyle(.orange)
                Link("Open Settings", destination: URL(string: UIApplication.openSettingsURLString)!)
            }
        } footer: {
            Text("When a computer waits for your approval, for example for sudo. The Lock Screen card lights up with it; without the card, a notification names the computer.")
        }
    }
}

struct PairingView: View {
    @EnvironmentObject private var model: PhoneModel
    @State private var code = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Image(systemName: Biometry.symbol)
                .font(.system(size: 56))
                .foregroundStyle(.tint)
                .frame(maxWidth: .infinity)

            Text("Unlock your computers with \(Biometry.name)")
                .font(.title2.weight(.bold))
                .frame(maxWidth: .infinity)

            VStack(alignment: .leading, spacing: 12) {
                Step(number: 1, text: "Install \(Brand.name) on your Mac or Linux computer.") {
                    Link("Download for Mac or Linux", destination: Brand.download)
                }
                Step(number: 2, text: "On your Mac, click the \(Brand.name) menu bar icon, then **Pair iPhone…** On Linux, run **\(Brand.id)-agent pair**.")
                if QRScanButton.isSupported {
                    Step(number: 3, text: "Scan the QR code it shows. The iPhone **Camera** app works too: tap the \(Brand.name) link.")
                } else {
                    Step(number: 3, text: "Scan the QR code with the iPhone **Camera** app and tap the \(Brand.name) link.")
                }
            }

            if QRScanButton.isSupported {
                QRScanButton { code in Task { await model.pair(code: code) } }
                    .disabled(model.isPairing)
            }

            Divider()

            Text("Or paste the pairing code").font(.subheadline.weight(.semibold))
            TextField("\(Brand.urlScheme)://pair?d=…", text: $code, axis: .vertical)
                .textFieldStyle(.roundedBorder)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
                .lineLimit(1...4)
            HStack {
                PasteButton(payloadType: String.self) { strings in
                    guard let first = strings.first else { return }
                    Task { @MainActor in
                        code = first
                        await model.pair(code: first)
                    }
                }
                .labelStyle(.titleAndIcon)
                Spacer()
                Button("Pair") {
                    Task { await model.pair(code: code) }
                }
                .buttonStyle(.borderedProminent)
                .disabled(code.isEmpty || model.isPairing)
            }

            if model.isPairing {
                HStack {
                    ProgressView()
                    Text("Pairing…")
                }
                .foregroundStyle(.secondary)
            } else if let result = model.pairingResult {
                Label(result.message, systemImage: result.success ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                    .foregroundStyle(result.success ? .green : .orange)
            }
        }
    }
}

private struct Step<Extra: View>: View {
    let number: Int
    let text: LocalizedStringKey
    @ViewBuilder var extra: Extra

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text("\(number)")
                .font(.footnote.weight(.bold))
                .frame(width: 22, height: 22)
                .background(Circle().fill(.tint.opacity(0.15)))
            VStack(alignment: .leading, spacing: 4) {
                Text(text)
                extra
            }
        }
    }
}

extension Step where Extra == EmptyView {
    init(number: Int, text: LocalizedStringKey) {
        self.init(number: number, text: text) { EmptyView() }
    }
}

/// Help and the privacy policy, on the website.
private struct AboutLinks: View {
    var body: some View {
        HStack(spacing: 24) {
            Link("Help", destination: Brand.docs)
            Link("Privacy Policy", destination: Brand.privacyPolicy)
        }
        .font(.footnote)
        .frame(maxWidth: .infinity)
    }
}
