import LocalAuthentication

/// Face ID or Touch ID, whichever this iPhone has (an iPhone SE has Touch ID), for what the app says and shows.
enum Biometry {
    static let isTouchID: Bool = {
        let context = LAContext()
        // biometryType is only filled in after asking whether biometrics can be used.
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        return context.biometryType == .touchID
    }()

    static var name: String { isTouchID ? "Touch ID" : "Face ID" }
    static var symbol: String { isTouchID ? "touchid" : "faceid" }
}
