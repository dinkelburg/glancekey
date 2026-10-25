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

        func isSame(as other: Found) -> Bool { pid == other.pid && CFEqual(window, other.window) }
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
            // E.g. "1Password is trying to unlock." and "Touch ID or enter your password to continue with 1Password."
            let texts = window.all { $0.role == kAXStaticTextRole }
                .compactMap { $0.string(kAXValueAttribute) }
                .map { $0.components(separatedBy: .newlines).joined(separator: " ").trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
            return Found(pid: pid, window: window, title: String((texts.first ?? "A password dialog").prefix(160)),
                         detail: String((texts.count > 1 ? texts.last! : "Asks for your Mac password").prefix(160)))
        }
        return nil
    }

    /// Types the password into the dialog and submits it. Returns once the dialog is gone or clearly isn't.
    static func fill(_ dialog: Found, password: String) async -> FillResult {
        guard isGenuine(dialog.pid), let window = dialogWindow(pid: dialog.pid), CFEqual(window, dialog.window) else { return .closed }
        var field = window.all(where: \.isSecureField).first
        if field == nil, let button = mainButton(in: window) {
            // A Touch ID dialog: "Use Password…" shows the password field.
            AXUIElementPerformAction(button, kAXPressAction as CFString)
            for _ in 0..<20 where field == nil {
                await pause(0.1)
                field = dialogWindow(pid: dialog.pid)?.all(where: \.isSecureField).first
            }
        }
        guard let field else { return .failed("Couldn't find the password field in the dialog.") }
        guard await enter(password, into: field, pid: dialog.pid) else {
            return .failed("The dialog didn't take the password. Type it on your Mac instead.")
        }
        if let button = dialogWindow(pid: dialog.pid).flatMap(mainButton(in:)) {
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
        let app = AXUIElementCreateApplication(pid)
        AXUIElementSetMessagingTimeout(app, 1)
        let windows = app.attribute(kAXWindowsAttribute) as? [AXUIElement] ?? []
        return windows.first { !$0.all(where: \.isSecureField).isEmpty || mainButton(in: $0) != nil }
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
