import FaceUnlockCore
import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var model: PhoneModel
    @State private var showingAddComputer = false

    var body: some View {
        NavigationStack {
            Group {
                if model.machines.isEmpty {
                    ScrollView { PairingView().padding() }
                } else {
                    machineList
                }
            }
            .navigationTitle("FaceUnlock")
            .sheet(isPresented: $showingAddComputer) {
                NavigationStack {
                    ScrollView { PairingView().padding() }
                        .navigationTitle("Add a computer")
                        .navigationBarTitleDisplayMode(.inline)
                        .toolbar {
                            ToolbarItem(placement: .cancellationAction) { Button("Done") { showingAddComputer = false } }
                        }
                }
            }
            .onChange(of: model.pairingResult) { _, result in
                if result?.success == true { showingAddComputer = false }
            }
        }
    }

    private var machineList: some View {
        List {
            if let result = model.pairingResult {
                Section {
                    Label(result.message, systemImage: result.success ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(result.success ? .green : .orange)
                }
            }
            ForEach(model.machines) { machine in
                Section {
                    MachineCard(machine: machine)
                }
            }
            Section {
                Toggle("Unlock when FaceUnlock opens", isOn: $model.autoUnlockOnOpen)
                Button("Add another computer") { showingAddComputer = true }
            } footer: {
                Text("Tip: add “Unlock Computer” to the Action button, Control Center or your Home Screen in Shortcuts, and pick which computer it unlocks.")
            }
        }
    }
}

private struct MachineCard: View {
    @EnvironmentObject private var model: PhoneModel
    @State private var confirmingRemoval = false
    let machine: PairedMachine

    var body: some View {
        VStack(spacing: 14) {
            HStack {
                Image(systemName: machine.symbolName)
                    .font(.title2)
                Text(machine.machineName).font(.headline)
                Spacer()
                Menu {
                    Button("Remove \(machine.machineName)", systemImage: "trash", role: .destructive) {
                        confirmingRemoval = true
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                        .font(.title3)
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("More for \(machine.machineName)")
            }
            .confirmationDialog("Remove \(machine.machineName)?", isPresented: $confirmingRemoval, titleVisibility: .visible) {
                Button("Remove", role: .destructive) { model.remove(machine) }
            } message: {
                Text("This iPhone won't be able to unlock it until you pair again. Also remove this iPhone on the computer.")
            }

            Button {
                Task { await model.perform(.unlock, on: machine) }
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "faceid")
                    Text("Unlock")
                }
                .font(.title3.weight(.semibold))
                .frame(maxWidth: .infinity, minHeight: 44)
            }
            .buttonStyle(.borderedProminent)
            .disabled(isWorking)

            Button {
                Task { await model.perform(.lock, on: machine) }
            } label: {
                Label("Lock", systemImage: "lock")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .disabled(isWorking)

            statusLine
        }
        .padding(.vertical, 6)
    }

    private var isWorking: Bool {
        if case .working = model.state(for: machine) { return true }
        return false
    }

    @ViewBuilder
    private var statusLine: some View {
        switch model.state(for: machine) {
        case .idle:
            Text(machine.platform == "macOS" ? "Mac" : "Linux")
                .font(.footnote)
                .foregroundStyle(.secondary)
        case .working(let text):
            HStack(spacing: 6) {
                ProgressView()
                Text(text)
            }
            .font(.footnote)
            .foregroundStyle(.secondary)
        case .finished(let result):
            Label(result.message, systemImage: result.success ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                .font(.footnote)
                .foregroundStyle(result.success ? .green : .orange)
                .multilineTextAlignment(.center)
        }
    }
}

struct PairingView: View {
    @EnvironmentObject private var model: PhoneModel
    @State private var code = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Image(systemName: "faceid")
                .font(.system(size: 56))
                .foregroundStyle(.tint)
                .frame(maxWidth: .infinity)

            Text("Unlock your computers with Face ID")
                .font(.title2.weight(.bold))
                .frame(maxWidth: .infinity)

            VStack(alignment: .leading, spacing: 12) {
                Step(number: 1, text: "On your Mac, click the FaceUnlock menu bar icon, then **Pair iPhone…** On Linux, run **faceunlock-agent pair**.")
                Step(number: 2, text: "Scan the QR code with the iPhone **Camera** app and tap the FaceUnlock link.")
            }

            Divider()

            Text("Or paste the pairing code").font(.subheadline.weight(.semibold))
            TextField("faceunlock://pair?d=…", text: $code, axis: .vertical)
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

private struct Step: View {
    let number: Int
    let text: LocalizedStringKey

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text("\(number)")
                .font(.footnote.weight(.bold))
                .frame(width: 22, height: 22)
                .background(Circle().fill(.tint.opacity(0.15)))
            Text(text)
        }
    }
}
