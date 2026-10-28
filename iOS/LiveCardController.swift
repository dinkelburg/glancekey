import ActivityKit
import AppCore
import Foundation
import UIKit

/// Keeps the lock screen card (`LiveCardAttributes`) going. The app starts it when it opens and updates it while it's
/// open; meanwhile it tells the relay where to push it (`Card` in relay/src/index.ts), so the computers' changes reach
/// it while the app is closed. iOS ends a card after eight hours; the relay then starts a new one when a computer
/// locks or asks for something, and iOS wakes the app in the background to hand over where to push that one.
@MainActor
final class LiveCardController {
    static let shared = LiveCardController()

    private enum Defaults {
        static let enabled = "liveCardEnabled"
        static let secret = "liveCardSecret"
        static let key = "liveCardKey"
        static let startToken = "liveCardStartToken"
        static let startDates = "liveCardStartDates"
        static let registration = "liveCardRegistration"
        static let registeredAt = "liveCardRegisteredAt"
        static let relay = "liveCardRelay"
    }

    /// What the app told the relay. Sent again when it changes, and every few hours in case the relay lost it.
    private struct Registration: Codable, Equatable {
        struct Computer: Codable, Equatable {
            var id: String
            var name: String
            var state: String
        }

        var secret: String
        var on: Bool
        var key: String
        var computers: [Computer]
        /// Notifications are on: a new request lights up the iPhone through the card, or, without a card, comes as a
        /// notification to `pushToken`. The computers leave an iPhone with a card out of their own notifications.
        var alerts = false
        var pushToken: String?
        var startToken: String?
        var updateToken: String?
        /// When the card with `updateToken` started, in seconds since 1970.
        var startedAt: Int?
    }

    private(set) var isEnabled: Bool
    /// The card's id on the relay, which the computers get; only the app knows the secret it comes from.
    let cardId: String
    /// Goes into the card's links (`LiveCardLink`).
    let key: String
    private let secret: String
    private var startToken: String?
    private var updateTokens: [String: String] = [:]
    private var startDates: [String: Date]
    private var observed: Set<String> = []
    private var shown: LiveCardAttributes.ContentState?
    /// The card's buttons that are working, by computer or request (`ContentState.Busy`).
    private var busy: [String: LiveCardAttributes.ContentState.Busy] = [:]

    private init() {
        let defaults = UserDefaults.standard
        isEnabled = defaults.object(forKey: Defaults.enabled) as? Bool ?? true
        secret = defaults.string(forKey: Defaults.secret) ?? {
            let secret = randomToken()
            defaults.set(secret, forKey: Defaults.secret)
            return secret
        }()
        key = defaults.string(forKey: Defaults.key) ?? {
            let key = randomToken(byteCount: 18)
            defaults.set(key, forKey: Defaults.key)
            return key
        }()
        cardId = CardId.of(secret: secret)
        startToken = defaults.string(forKey: Defaults.startToken)
        startDates = (defaults.dictionary(forKey: Defaults.startDates) as? [String: Date]) ?? [:]
    }

    /// Whether iOS lets the app show Live Activities (Settings › <app> › Live Activities).
    var isAllowed: Bool { ActivityAuthorizationInfo().areActivitiesEnabled }

    /// The relay the card is on. One relay pushes the whole card, so it only lists the computers on that relay: ours if
    /// any computer uses it, else the first computer's. Computers on another relay notify as usual.
    var relay: URL? {
        let machines = PhoneModel.shared.machines
        return machines.first { Brand.isHostedRelay($0.relay) }?.relay ?? machines.first?.relay
    }

    func isOnCard(_ machine: PairedMachine) -> Bool {
        relay.map { Brand.isSameRelay($0, machine.relay) } ?? false
    }

    /// The card id for a computer: "" when there's no card, or the computer isn't on it, so it stops updating it and
    /// notifies this iPhone itself.
    func cardId(for machine: PairedMachine) -> String {
        isEnabled && isAllowed && isOnCard(machine) ? cardId : ""
    }

    /// At launch, including when iOS starts the app in the background for a card the relay started.
    func start() {
        if #available(iOS 17.2, *) {
            Task {
                for await data in Activity<LiveCardAttributes>.pushToStartTokenUpdates {
                    startToken = Self.hex(data)
                    UserDefaults.standard.set(startToken, forKey: Defaults.startToken)
                    await register()
                }
            }
        }
        Task {
            for await activity in Activity<LiveCardAttributes>.activityUpdates { adopt(activity, isNew: true) }
        }
        for activity in Activity<LiveCardAttributes>.activities { adopt(activity, isNew: false) }
    }

    func setEnabled(_ enabled: Bool) async {
        guard enabled != isEnabled else { return }
        isEnabled = enabled
        UserDefaults.standard.set(enabled, forKey: Defaults.enabled)
        if !enabled {
            shown = nil
            for activity in Activity<LiveCardAttributes>.activities { await activity.end(nil, dismissalPolicy: .immediate) }
        }
        await register()
    }

    /// Shows `state` on the card, starting one if there's none and the app is on screen (iOS only allows that then).
    func show(_ state: LiveCardAttributes.ContentState) async {
        guard isEnabled, isAllowed else { return }
        var state = state
        state.busy = busyList
        if state.computers.isEmpty {
            for activity in Activity<LiveCardAttributes>.activities { await activity.end(nil, dismissalPolicy: .immediate) }
            shown = nil
            return
        }
        if let activity = current {
            if state != shown || activity.activityState == .stale {
                await activity.update(ActivityContent(state: state, staleDate: nil))
            }
        } else if UIApplication.shared.applicationState == .active {
            do {
                let activity = try Activity.request(attributes: LiveCardAttributes(), content: ActivityContent(state: state, staleDate: nil),
                                                    pushType: .token)
                adopt(activity, isNew: true)
            } catch {
                print("Couldn't start the lock screen card: \(error)")
            }
        }
        shown = state
        await register()
    }

    /// Shows a computer's new state on the card right away, after unlocking or locking it.
    func set(_ computer: String, to state: LiveCardAttributes.ContentState.Computer.State) async {
        guard let activity = current else { return }
        var content = activity.content.state
        guard let index = content.computers.firstIndex(where: { $0.id == computer }) else { return }
        content.computers[index].state = state
        await update(activity, to: content)
    }

    /// Takes a request off the card right away, after it was answered.
    func remove(request: String) async {
        guard let activity = current else { return }
        var state = activity.content.state
        state.requests.removeAll { $0.id == request }
        await update(activity, to: state)
    }

    /// Shows that `button` is working on a computer or request (`id`), or, with nil, that it's done.
    func setBusy(_ id: String, _ button: CardButton?) async {
        busy[id] = button.map { .init(id: id, button: $0.rawValue, since: Int(Date().timeIntervalSince1970)) }
        guard let activity = current else { return }
        await update(activity, to: activity.content.state)
    }

    private var busyList: [LiveCardAttributes.ContentState.Busy]? {
        busy.isEmpty ? nil : busy.values.sorted { $0.id < $1.id }
    }

    private func update(_ activity: Activity<LiveCardAttributes>, to state: LiveCardAttributes.ContentState) async {
        var state = state
        state.busy = busyList
        shown = state
        await activity.update(ActivityContent(state: state, staleDate: nil))
    }

    private var current: Activity<LiveCardAttributes>? {
        Activity<LiveCardAttributes>.activities.last { $0.activityState == .active || $0.activityState == .stale }
    }

    private func adopt(_ activity: Activity<LiveCardAttributes>, isNew: Bool) {
        guard observed.insert(activity.id).inserted else { return }
        guard isEnabled else {
            Task { await activity.end(nil, dismissalPolicy: .immediate) }
            return
        }
        if isNew {
            startDates[activity.id] = Date()
            startDates = startDates.filter { $0.value > Date().addingTimeInterval(-12 * 3600) }
            UserDefaults.standard.set(startDates, forKey: Defaults.startDates)
            // A new card replaces any other, so there's only ever one.
            for other in Activity<LiveCardAttributes>.activities where other.id != activity.id {
                Task { await other.end(nil, dismissalPolicy: .immediate) }
            }
        }
        Task {
            for await data in activity.pushTokenUpdates {
                updateTokens[activity.id] = Self.hex(data)
                await register()
            }
        }
    }

    /// Tells the relay where to push the card and what it lists, when that changed.
    private func register() async {
        let model = PhoneModel.shared
        let defaults = UserDefaults.standard
        // The card moved to another relay, or the last computer is gone: turn it off on the relay it was on.
        if let previous = defaults.url(forKey: Defaults.relay), relay.map({ !Brand.isSameRelay($0, previous) }) ?? true {
            guard await post(Registration(secret: secret, on: false, key: key, computers: []), to: previous) else { return }
            for name in [Defaults.relay, Defaults.registration, Defaults.registeredAt] { defaults.removeObject(forKey: name) }
        }
        guard let relay else { return }
        var registration = Registration(secret: secret, on: isEnabled && isAllowed, key: key, computers: [])
        if registration.on {
            registration.computers = model.liveCardContent.computers.map { .init(id: $0.id, name: $0.name, state: $0.state.rawValue) }
            registration.pushToken = model.notificationAddress
            registration.alerts = registration.pushToken != nil
            registration.startToken = startToken
            if let activity = current, let token = updateTokens[activity.id] {
                registration.updateToken = token
                registration.startedAt = startDates[activity.id].map { Int($0.timeIntervalSince1970) }
            }
        }
        let previous = defaults.data(forKey: Defaults.registration).flatMap { try? JSONDecoder().decode(Registration.self, from: $0) }
        let registeredAt = defaults.object(forKey: Defaults.registeredAt) as? Date ?? .distantPast
        guard registration != previous || registeredAt < Date().addingTimeInterval(-6 * 3600) else { return }
        guard await post(registration, to: relay) else { return }
        defaults.set(try? JSONEncoder().encode(registration), forKey: Defaults.registration)
        defaults.set(Date(), forKey: Defaults.registeredAt)
        defaults.set(relay, forKey: Defaults.relay)
    }

    /// Whether the relay took it.
    private func post(_ registration: Registration, to relay: URL) async -> Bool {
        var request = URLRequest(url: relay.appendingPathComponent("v1/card/\(cardId)"), timeoutInterval: 15)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONEncoder().encode(registration)
        // The app may be in the background, woken for a new card.
        let task = UIApplication.shared.beginBackgroundTask(withName: "Lock screen card")
        defer { UIApplication.shared.endBackgroundTask(task) }
        guard let (_, response) = try? await URLSession.shared.data(for: request) else { return false }
        return (response as? HTTPURLResponse)?.statusCode == 200
    }

    private static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}
