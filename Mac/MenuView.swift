import CoreImage.CIFilterBuiltins
import AppCore
import SwiftUI

struct MenuView: View {
    @ObservedObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 8) {
                Image(nsImage: NSApp.applicationIconImage)
                    .resizable()
                    .frame(width: 40, height: 40)
                VStack(alignment: .leading, spacing: 1) {
                    Text(Brand.name).font(.headline)
                    Text(statusText)
                        .font(.caption)
                        .foregroundStyle(model.relayState == .connected ? Color.secondary : Color.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            Divider()
            if let invite = model.invite {
                PairingSection(model: model, invite: invite)
            } else {
                SetupSection(model: model)
                DevicesSection(model: model)
            }

            Divider()
            OptionsSection(model: model)
            if !model.log.isEmpty {
                ActivitySection(log: model.log)
            }

            Divider()
            HStack {
                Spacer()
                Button("Quit \(Brand.name)") { NSApp.terminate(nil) }
            }
        }
        .padding(16)
        .frame(width: 360)
    }

    private var statusText: String {
        switch model.relayState {
        case .connected: "Ready. Your iPhone can reach this Mac from anywhere."
        case .connecting: "Connecting to \(model.relay.host ?? "the relay")…"
        case .offline(let reason): "Offline: \(reason). Retrying…"
        }
    }
}

/// A title with its explanation underneath on the left and a switch or button on the right, so the controls of
/// all rows line up.
private struct DetailRow<Control: View>: View {
    let title: String
    var detail: String?
    var detailColor: Color = .secondary
    @ViewBuilder var control: Control

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                if let detail {
                    Text(detail)
                        .font(.caption)
                        .foregroundStyle(detailColor)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 8)
            control
        }
    }
}

private struct StatusRow<Accessory: View>: View {
    let ok: Bool
    let title: String
    let detail: String
    @ViewBuilder var accessory: Accessory

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: ok ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                .foregroundStyle(ok ? .green : .orange)
            DetailRow(title: title, detail: detail) { accessory }
        }
    }
}

private struct SetupSection: View {
    @ObservedObject var model: AppModel
    @State private var password = ""
    @State private var error: String?
    @State private var isSaving = false
    @State private var isChanging = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            StatusRow(
                ok: model.hasEventAccess,
                title: "Accessibility access",
                detail: model.hasEventAccess ? "Lets \(Brand.name) type on the lock screen and into password dialogs." : "Needed to type your password on the lock screen and into password dialogs."
            ) {
                if !model.hasEventAccess {
                    Button("Grant…") { ScreenController.requestEventAccess() }
                }
            }

            StatusRow(
                ok: model.hasPassword,
                title: "Mac password",
                detail: model.hasPassword ? "Saved in your keychain. It never leaves this Mac." : "\(Brand.name) types it on the lock screen when your iPhone approves."
            ) {
                if model.hasPassword && !isChanging {
                    Button("Change…") { isChanging = true }
                }
            }

            if !model.hasPassword || isChanging {
                HStack {
                    SecureField("Login password for \(NSUserName())", text: $password)
                        .textFieldStyle(.roundedBorder)
                        .onSubmit(save)
                    Button("Save", action: save)
                        .disabled(password.isEmpty || isSaving)
                }
                if let error {
                    Text(error).font(.caption).foregroundStyle(.red)
                }
                if isChanging {
                    HStack {
                        Button("Cancel") {
                            isChanging = false
                            password = ""
                            error = nil
                        }
                        Spacer()
                        Button("Remove saved password", role: .destructive) {
                            model.forgetPassword()
                            isChanging = false
                        }
                    }
                    .buttonStyle(.link)
                    .font(.caption)
                }
            }
        }
    }

    private func save() {
        guard !password.isEmpty, !isSaving else { return }
        isSaving = true
        Task {
            error = await model.savePassword(password)
            isSaving = false
            if error == nil {
                password = ""
                isChanging = false
            }
        }
    }
}

private struct DevicesSection: View {
    @ObservedObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Paired iPhones").font(.subheadline.weight(.semibold))
                Spacer()
                Button("Pair iPhone…") { model.startPairing() }
            }
            if model.devices.isEmpty {
                Text("None yet. Pair your iPhone to get started.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            ForEach(model.devices) { device in
                HStack {
                    Image(systemName: "iphone")
                    VStack(alignment: .leading, spacing: 1) {
                        Text(device.name)
                        if let trusted = model.trustedDeviceIds, !trusted.contains(device.id) {
                            // Not paired through this app: something else added it. See PasswordStore.
                            Text("Not confirmed on this Mac, so it can't unlock or approve. Remove it, and pair again if it's yours.")
                                .font(.caption)
                                .foregroundStyle(.orange)
                                .fixedSize(horizontal: false, vertical: true)
                        } else {
                            Text(device.lastUsedAt.map { "Last used \($0.formatted(.relative(presentation: .named)))" }
                                ?? "Paired \(device.pairedAt.formatted(date: .abbreviated, time: .shortened))")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    Spacer()
                    Button {
                        model.remove(device)
                    } label: {
                        Image(systemName: "trash")
                    }
                    .buttonStyle(.borderless)
                    .help("Remove this iPhone")
                }
            }
        }
    }
}

private struct PairingSection: View {
    @ObservedObject var model: AppModel
    let invite: PairingInvite
    @State private var copied = false

    var body: some View {
        VStack(spacing: 10) {
            Text("Scan with your iPhone's Camera").font(.headline)
            if let image = QRCode.image(for: invite.url.absoluteString) {
                Image(nsImage: image)
                    .interpolation(.none)
                    .resizable()
                    .frame(width: 210, height: 210)
            }
            Text("Install \(Brand.name) on your iPhone first. Scanning the code opens it and pairs.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            if let expires = model.pairingExpiresAt {
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    let seconds = max(0, Int(expires.timeIntervalSince(context.date)))
                    Text("Code expires in \(seconds / 60):\(String(format: "%02d", seconds % 60))")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
            }
            HStack {
                Button(copied ? "Copied" : "Copy code") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(invite.url.absoluteString, forType: .string)
                    copied = true
                }
                Button("Cancel") { model.cancelPairing() }
            }
        }
        .frame(maxWidth: .infinity)
    }
}

private struct OptionsSection: View {
    @ObservedObject var model: AppModel
    @State private var isChangingSudo = false
    @State private var sudoError: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            toggle("Keep Mac awake on power adapter", isOn: $model.keepAwakeOnPower,
                   detail: "A sleeping Mac can't be reached. On battery it sleeps as usual.")
            toggle("Open at login", isOn: Binding(get: { model.launchAtLogin }, set: { model.setLaunchAtLogin($0) }))
            toggle("Fill in password dialogs from iPhone", isOn: $model.fillsPasswordDialogs,
                   detail: "When a dialog asks for your Mac password (1Password, System Settings), approve it on your iPhone and \(Brand.name) types the password.")
            DetailRow(title: "Approve sudo from iPhone", detail: sudoText, detailColor: sudoIsOutdated ? .orange : .secondary) {
                if model.canSetUpSudo {
                    // The size of the buttons above, not of the switches.
                    sudoButton.disabled(isChangingSudo).controlSize(.regular)
                }
            }
            if let sudoError {
                Text(sudoError)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .toggleStyle(.switch)
        .labelsHidden()
        .controlSize(.small)
    }

    private func toggle(_ title: String, isOn: Binding<Bool>, detail: String? = nil) -> some View {
        DetailRow(title: title, detail: detail) { Toggle(title, isOn: isOn) }
    }

    private var sudoIsOutdated: Bool {
        switch model.sudoApprovals {
        case .outdated, .stale, .otherVersion: true
        case .off, .on: false
        }
    }

    @ViewBuilder private var sudoButton: some View {
        switch model.sudoApprovals {
        case .off: Button("Turn on…") { setSudoApprovals(on: true) }
        case .outdated, .stale, .otherVersion: Button("Update…") { setSudoApprovals(on: true) }
        case .on: Button("Turn off…") { setSudoApprovals(on: false) }
        }
    }

    private func setSudoApprovals(on: Bool) {
        isChangingSudo = true
        sudoError = nil
        Task {
            if let error = await model.setSudoApprovals(on: on), !error.isEmpty {
                sudoError = error
            }
            isChangingSudo = false
        }
    }

    private var sudoText: String {
        // Builds without the helpers (scripts/build-mac-helpers.sh) can only point at the script.
        let turnOn = model.canSetUpSudo ? "turn this on" : "run scripts/enable-mac-sudo.sh"
        let update = model.canSetUpSudo ? "update this" : "run scripts/enable-mac-sudo.sh again"
        switch model.sudoApprovals {
        case .off: return "sudo asks for your password. To approve it with your iPhone first, \(turnOn)."
        case .on: return "sudo waits for your iPhone first, then asks for your password."
        case .outdated(let name): return "\(name) can't approve sudo yet. To add it, \(update)."
        case .stale(let name): return "\(name) isn't paired anymore but can still approve sudo. To take it out, \(update)."
        case .otherVersion: return "sudo still uses another version of \(Brand.name). To use this one, \(update)."
        }
    }
}

private struct ActivitySection: View {
    let log: [AppModel.LogEntry]

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Recent activity").font(.subheadline.weight(.semibold))
            ForEach(log.prefix(5)) { entry in
                HStack(alignment: .firstTextBaseline) {
                    Text(entry.date.formatted(date: .omitted, time: .shortened))
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                    Text(entry.text)
                        .font(.caption)
                        .foregroundStyle(entry.isError ? .red : .primary)
                        .lineLimit(2)
                }
            }
        }
    }
}

enum QRCode {
    static func image(for string: String) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(string.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 10, y: 10)) else { return nil }
        let representation = NSCIImageRep(ciImage: output)
        let image = NSImage(size: representation.size)
        image.addRepresentation(representation)
        return image
    }
}
