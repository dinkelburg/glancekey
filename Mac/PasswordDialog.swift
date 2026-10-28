import AppCore
import AppKit
import ApplicationServices
import Security

/// System password dialogs the app fills in once the iPhone approves: LocalAuthentication's "… is trying to
/// unlock" (coreautha: 1Password, Safari passwords) and administrator dialogs (SecurityAgent: System Settings,
/// installers, scripts). Only Apple-signed dialog processes count, and keystrokes go to the dialog's own process,
/// never to the app in front.
@MainActor
enum PasswordDialog {
    struct Found {
        let pid: pid_t
        let window: AXUIElement
        let title: String
        let detail: String
        /// A keychain prompt for one of this app's own items: another program asking for the saved password.
        let asksForAppSecret: Bool

        /// Still the dialog you were asked about: the same window, saying the same.
        func isSame(as other: Found) -> Bool {
            pid == other.pid && CFEqual(window, other.window) && title == other.title && detail == other.detail
        }
    }

    enum FillResult: Equatable {
        case filled
        case closed
        case failed(String)
    }

    private static let owners: Set<String> = ["coreautha", "SecurityAgent"]
    private static let requirement: SecRequirement? = {
        var requirement: SecRequirement?
        SecRequirementCreateWithString(
            "anchor apple and (identifier \"com.apple.LocalAuthentication.UIAgent\" or identifier \"com.apple.SecurityAgent\")" as CFString,
            [], &requirement)
        return requirement
    }()

    /// The password dialog on screen, if any. Cheap while there is none: it only reads the window list.
    static func find() -> Found? {
        let windows = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] ?? []
        let pids = Set(windows.compactMap { info -> pid_t? in
            guard let owner = info[kCGWindowOwnerName as String] as? String, owners.contains(owner) else { return nil }
            return info[kCGWindowOwnerPID as String] as? pid_t
        })
        for pid in pids where isGenuine(pid) {
            guard let window = dialogWindow(pid: pid) else { continue }
            return describe(window, pid: pid)
        }
        return nil
    }

    private static func describe(_ window: AXUIElement, pid: pid_t) -> Found {
        let texts = texts(in: window)
        return Found(pid: pid, window: window, title: title(of: texts),
                     detail: String((texts.count > 1 ? texts.last! : "Asks for your Mac password").prefix(160)),
                     asksForAppSecret: texts.contains { text in appSecretNames.contains { text.contains($0) } })
    }

    /// How this app's keychain items show up in a keychain prompt: by label, or by service.
    private static let appSecretNames = ["\(Brand.name):", Brand.keychainService("")]

    /// The dialog's lines, e.g. "1Password is trying to unlock." and "Touch ID or enter your password to continue
    /// with 1Password." The program asking can choose some of the words, so invisible characters that could make
    /// them read differently (right-to-left overrides, zero-width spaces, blank-looking ones like the Hangul fillers
    /// and the Braille blank) show as "�".
    private static func texts(in window: AXUIElement) -> [String] {
        window.all { $0.role == kAXStaticTextRole }
            .compactMap { $0.string(kAXValueAttribute) }
            .map { visible($0).components(separatedBy: .newlines).joined(separator: " ").trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    private static func visible(_ text: String) -> String {
        var scalars = String.UnicodeScalarView()
        for scalar in text.unicodeScalars {
            let invisible = scalar.properties.generalCategory == .format || scalar.properties.isDefaultIgnorableCodePoint || scalar == "\u{2800}"
            scalars.append(invisible ? "\u{FFFD}" : scalar)
        }
        return String(scalars)
    }

    private static func title(of texts: [String]) -> String {
        String((texts.first ?? "A password dialog").prefix(160))
    }

    /// Types the password into the dialog and submits it. Returns once the dialog is gone or clearly isn't.
    static func fill(_ dialog: Found, password: String) async -> FillResult {
        guard !dialog.asksForAppSecret, let window = approvedWindow(dialog), describe(window, pid: dialog.pid).isSame(as: dialog)
        else { return .closed }
        var field = window.all(where: \.isSecureField).first
        if field == nil, let button = mainButton(in: window) {
            // A Touch ID dialog: "Use Password…" shows the password field.
            AXUIElementPerformAction(button, kAXPressAction as CFString)
            // The field usually appears in the same window. If that window was replaced instead, only a single new one
            // with the same first line counts, so the password can't go into another dialog that appeared meanwhile.
            for _ in 0..<20 where field == nil {
                await pause(0.1)
                field = window.all(where: \.isSecureField).first
                if field == nil, window.role == nil, dialogWindows(pid: dialog.pid).count == 1 {
                    field = approvedWindow(dialog)?.all(where: \.isSecureField).first
                }
            }
        }
        guard let field, let fieldWindow = field.element(kAXWindowAttribute) ?? approvedWindow(dialog) else {
            return .failed("Couldn't find the password field in the dialog.")
        }
        // Checked again right before typing: the process could have exited, and another taken its number.
        guard approvedWindow(dialog) != nil else { return .closed }
        guard await enter(password, into: field, pid: dialog.pid) else {
            return .failed("The dialog didn't take the password. Type it on your Mac instead.")
        }
        // Submits the window the password went into, not whichever dialog that process shows now.
        if let button = mainButton(in: fieldWindow) {
            AXUIElementPerformAction(button, kAXPressAction as CFString) // OK, or Allow Access
        } else {
            press(Key.return, to: dialog.pid)
        }
        for _ in 0..<20 {
            await pause(0.2)
            guard let window = dialogWindow(pid: dialog.pid), !window.all(where: \.isSecureField).isEmpty else { return .filled }
        }
        return .failed("Typed your password, but the dialog is still open.")
    }

    /// The dialog's window if it still is the one you approved: an Apple-signed process (the same one), and a
    /// window with the same first line. After "Use Password…" the rest of a Touch ID dialog's text changes.
    private static func approvedWindow(_ dialog: Found) -> AXUIElement? {
        guard isGenuine(dialog.pid), let window = dialogWindow(pid: dialog.pid), title(of: texts(in: window)) == dialog.title
        else { return nil }
        return window
    }

    /// Presses Cancel (or Don't Allow), for when you deny on the iPhone.
    static func cancel(_ dialog: Found) {
        guard let window = dialogWindow(pid: dialog.pid), CFEqual(window, dialog.window), let button = cancelButton(in: window) else { return }
        AXUIElementPerformAction(button, kAXPressAction as CFString)
    }

    // MARK: - Steps

    /// Types `text` into the secure field as keystrokes to the dialog's process, or else sets it through
    /// Accessibility. These dialogs report what the field holds, so this checks that it arrived.
    private static func enter(_ text: String, into field: AXUIElement, pid: pid_t) async -> Bool {
        AXUIElementSetAttributeValue(field, kAXFocusedAttribute as CFString, kCFBooleanTrue)
        AXUIElementSetAttributeValue(field, kAXValueAttribute as CFString, "" as CFString)
        for character in text { type(character, to: pid) }
        if await holds(text.count, field) { return true }
        AXUIElementSetAttributeValue(field, kAXValueAttribute as CFString, text as CFString)
        return await holds(text.count, field)
    }

    /// Keystrokes arrive asynchronously, so give the field a moment.
    private static func holds(_ count: Int, _ field: AXUIElement) async -> Bool {
        for _ in 0..<10 {
            guard let length = field.textLength else { return true }
            if length == count { return true }
            await pause(0.1)
        }
        return false
    }

    private static func isGenuine(_ pid: pid_t) -> Bool {
        var code: SecCode?
        guard let requirement,
              SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: pid] as CFDictionary, [], &code) == errSecSuccess,
              let code
        else { return false }
        return SecCodeCheckValidity(code, [], requirement) == errSecSuccess
    }

    // MARK: - Accessibility

    private static func dialogWindow(pid: pid_t) -> AXUIElement? {
        dialogWindows(pid: pid).first
    }

    private static func dialogWindows(pid: pid_t) -> [AXUIElement] {
        let app = AXUIElementCreateApplication(pid)
        AXUIElementSetMessagingTimeout(app, 1)
        let windows = app.attribute(kAXWindowsAttribute) as? [AXUIElement] ?? []
        return windows.filter { !$0.all(where: \.isSecureField).isEmpty || mainButton(in: $0) != nil }
    }

    /// The dialog's only button besides Cancel: "Use Password…" in a Touch ID dialog, else OK or Allow Access.
    private static func mainButton(in window: AXUIElement) -> AXUIElement? {
        let buttons = window.all { $0.role == kAXButtonRole }
        guard buttons.count == 2, let cancel = cancelButton(in: window) else { return nil }
        return buttons.first { !CFEqual($0, cancel) }
    }

    /// These dialogs are SwiftUI: buttons carry their label as a description, and Cancel or Don't Allow comes last.
    private static func cancelButton(in window: AXUIElement) -> AXUIElement? {
        let buttons = window.all { $0.role == kAXButtonRole }
        return window.element(kAXCancelButtonAttribute) ?? buttons.first { $0.label == "Cancel" } ?? (buttons.count == 2 ? buttons.last : nil)
    }

    // MARK: - Keystrokes to one process

    private enum Key {
        static let `return`: CGKeyCode = 36
        static let space: CGKeyCode = 49
    }

    private static let source = CGEventSource(stateID: .hidSystemState)

    private static func press(_ key: CGKeyCode, to pid: pid_t) {
        for keyDown in [true, false] {
            CGEvent(keyboardEventSource: source, virtualKey: key, keyDown: keyDown)?.postToPid(pid)
        }
    }

    /// Sends the character itself rather than a key code, so the keyboard layout doesn't matter.
    private static func type(_ character: Character, to pid: pid_t) {
        var units = Array(String(character).utf16)
        for keyDown in [true, false] {
            guard let event = CGEvent(keyboardEventSource: source, virtualKey: Key.space, keyDown: keyDown) else { continue }
            event.flags = []
            event.keyboardSetUnicodeString(stringLength: units.count, unicodeString: &units)
            event.postToPid(pid)
        }
    }

    private static func pause(_ seconds: Double) async {
        try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
    }
}

extension AXUIElement {
    func attribute(_ name: String) -> CFTypeRef? {
        var value: CFTypeRef?
        return AXUIElementCopyAttributeValue(self, name as CFString, &value) == .success ? value : nil
    }

    func string(_ name: String) -> String? { attribute(name) as? String }

    func element(_ name: String) -> AXUIElement? {
        guard let value = attribute(name), CFGetTypeID(value) == AXUIElementGetTypeID() else { return nil }
        return (value as! AXUIElement)
    }

    var role: String? { string(kAXRoleAttribute) }
    var label: String? { string(kAXTitleAttribute).flatMap { $0.isEmpty ? nil : $0 } ?? string(kAXDescriptionAttribute) }
    var isSecureField: Bool { string(kAXSubroleAttribute) == kAXSecureTextFieldSubrole }
    /// How many characters a text field holds; nil if it won't say.
    var textLength: Int? { (attribute(kAXNumberOfCharactersAttribute) as? Int) ?? string(kAXValueAttribute).map(\.count) }
    var children: [AXUIElement] { attribute(kAXChildrenAttribute) as? [AXUIElement] ?? [] }

    /// Every descendant matching `match`, depth first.
    func all(depth: Int = 0, where match: (AXUIElement) -> Bool) -> [AXUIElement] {
        guard depth < 12 else { return [] }
        return children.flatMap { child in (match(child) ? [child] : []) + child.all(depth: depth + 1, where: match) }
    }
}
