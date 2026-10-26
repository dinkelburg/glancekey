import SwiftUI
import UserNotifications

@main
struct PhoneApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @ObservedObject private var model = PhoneModel.shared
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                .onOpenURL { model.handle(url: $0) }
        }
        .onChange(of: scenePhase, initial: true) { _, phase in
            model.scenePhaseChanged(to: phase)
        }
    }
}

/// Notifications: Apple hands the app its push token, which `PhoneModel` gives the computers, and tapping a
/// notification shows what's waiting.
final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        // Apple asks apps to register at every launch; the token can change. Asking for permission first only
        // shows a prompt if it was never asked, as after an update from the ntfy version, which had the same setting.
        if PhoneModel.shared.notificationsEnabled { Task { await PhoneModel.shared.enableNotifications() } }
        return true
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        PhoneModel.shared.registered(pushToken: deviceToken.map { String(format: "%02x", $0) }.joined())
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        PhoneModel.shared.notificationProblem = "Couldn't turn on notifications: \(error.localizedDescription)"
    }

    /// While the app is open its list updates by itself, so the notification isn't shown.
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        []
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        await PhoneModel.shared.openedFromNotification()
    }
}
