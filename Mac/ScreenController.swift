import AppKit
import ApplicationServices
import CoreGraphics
import IOKit.pwr_mgt

/// Lock-screen detection, waking the display, and typing into the lock screen.
@MainActor
enum ScreenController {
    private enum Key {
        static let a: CGKeyCode = 0
        static let q: CGKeyCode = 12
        static let `return`: CGKeyCode = 36
        static let space: CGKeyCode = 49
        static let delete: CGKeyCode = 51
        static let shift: CGKeyCode = 56
    }

    private static let source = CGEventSource(stateID: .hidSystemState)

    static var isLocked: Bool {
        let session = CGSessionCopyCurrentDictionary() as? [String: Any]
        return (session?["CGSSessionScreenIsLocked"] as? NSNumber)?.boolValue ?? false
    }

    /// Posting keyboard events needs Accessibility (or Input Monitoring "post events") permission.
    static var hasEventAccess: Bool {
        CGPreflightPostEventAccess()
    }

    static func requestEventAccess() {
        if !CGRequestPostEventAccess() {
            NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")!)
        }
    }

    static func wakeDisplay() {
        var assertion: IOPMAssertionID = 0
        guard IOPMAssertionDeclareUserActivity("FaceUnlock" as CFString, kIOPMUserActiveLocal, &assertion) == kIOReturnSuccess else { return }
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { IOPMAssertionRelease(assertion) }
    }

    /// Types the password into the lock screen. Returns whether the Mac ended up unlocked.
    static func unlock(password: String) async -> Bool {
        wakeDisplay()
        nudgeMouse()
        await pause(1.2)
        guard isLocked else { return true }

        // Wake the password field (dismisses the screen saver if one is running), then clear it.
        tapShift()
        await pause(0.4)
        guard isLocked else { return true }
        press(Key.a, flags: .maskCommand)
        press(Key.delete)

        for character in password {
            // Stop as soon as the session is unlocked (e.g. someone unlocked by hand at the same moment): at most
            // one character can reach the app that gets focus, and the password is never submitted there.
            guard isLocked else { return true }
            type(character)
            await pause(0.01)
        }
        guard isLocked else { return true }
        press(Key.return)

        for _ in 0..<24 {
            await pause(0.25)
            if !isLocked { return true }
        }
        return false
    }

    /// Returns whether the Mac ended up locked.
    static func lock() async -> Bool {
        if !lockScreenImmediately() {
            press(Key.q, flags: [.maskCommand, .maskControl])
        }
        for _ in 0..<12 {
            await pause(0.25)
            if isLocked { return true }
        }
        return isLocked
    }

    /// The private call behind  › Lock Screen. Falls back to ⌃⌘Q if it's ever removed.
    private static func lockScreenImmediately() -> Bool {
        guard let handle = dlopen("/System/Library/PrivateFrameworks/login.framework/Versions/Current/login", RTLD_LAZY),
              let symbol = dlsym(handle, "SACLockScreenImmediate")
        else { return false }
        typealias LockScreen = @convention(c) () -> Int32
        _ = unsafeBitCast(symbol, to: LockScreen.self)()
        return true
    }

    private static func pause(_ seconds: Double) async {
        try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
    }

    private static func press(_ key: CGKeyCode, flags: CGEventFlags = []) {
        for keyDown in [true, false] {
            guard let event = CGEvent(keyboardEventSource: source, virtualKey: key, keyDown: keyDown) else { continue }
            event.flags = flags
            event.post(tap: .cghidEventTap)
        }
    }

    private static func tapShift() {
        for keyDown in [true, false] {
            guard let event = CGEvent(keyboardEventSource: source, virtualKey: Key.shift, keyDown: keyDown) else { continue }
            event.flags = keyDown ? .maskShift : []
            event.post(tap: .cghidEventTap)
        }
    }

    /// Sends the character itself rather than a key code, so the keyboard layout doesn't matter.
    private static func type(_ character: Character) {
        var units = Array(String(character).utf16)
        for keyDown in [true, false] {
            guard let event = CGEvent(keyboardEventSource: source, virtualKey: Key.space, keyDown: keyDown) else { continue }
            event.flags = []
            event.keyboardSetUnicodeString(stringLength: units.count, unicodeString: &units)
            event.post(tap: .cghidEventTap)
        }
    }

    private static func nudgeMouse() {
        let location = CGEvent(source: nil)?.location ?? .zero
        CGEvent(mouseEventSource: source, mouseType: .mouseMoved, mouseCursorPosition: location, mouseButton: .left)?
            .post(tap: .cghidEventTap)
    }
}
