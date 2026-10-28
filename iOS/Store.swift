import AppCore
import Foundation
import StoreKit

/// The subscription, and what the app allows without it (`FreeLimits`). Apple checks the subscription on the iPhone,
/// and the iPhone counts its own unlocks and approvals, so neither reaches the relay or us. The limits only apply to
/// the App Store and TestFlight app, and only to computers on the relay we host.
@MainActor
final class Store: ObservableObject {
    static let shared = Store()

    /// One subscription in two lengths, as set up in App Store Connect (and in Unlimited.storekit, for testing in Xcode).
    static let productIDs = ["yearly", "monthly"].map { "nl.dinkelworks.\(Brand.id).unlimited.\($0)" }
    /// Apple's standard terms for apps, which the subscription uses.
    static let terms = URL(string: "https://www.apple.com/legal/internet-services/itunes/dev/stdeula/")!

    private enum Defaults {
        static let use = "freeUse"
        static let limits = "freeLimits"
        static let limitsCheckedAt = "freeLimitsCheckedAt"
    }

    @Published private(set) var subscribed = false
    @Published private(set) var limits: FreeLimits
    @Published private(set) var use: DailyUse

    /// A copy someone built and installed themselves (as scripts/install-iphone.sh does) carries its provisioning
    /// profile; App Store and TestFlight installs, and the simulator, don't. Those copies have no limits.
    let isOwnBuild = Bundle.main.url(forResource: "embedded", withExtension: "mobileprovision") != nil

    var isUnlimited: Bool { subscribed || isOwnBuild }

    private var updates: Task<Void, Never>?

    private init() {
        let defaults = UserDefaults.standard
        limits = defaults.data(forKey: Defaults.limits).flatMap { try? JSONDecoder().decode(FreeLimits.self, from: $0) } ?? .standard
        use = defaults.data(forKey: Defaults.use).flatMap { try? JSONDecoder().decode(DailyUse.self, from: $0) } ?? DailyUse()
    }

    /// At launch: follows renewals, refunds and purchases made on other devices.
    func start() {
        guard updates == nil else { return }
        updates = Task { [weak self] in
            for await update in Transaction.updates {
                if case .verified(let transaction) = update { await transaction.finish() }
                await self?.refresh()
            }
        }
        Task { await refresh() }
    }

    /// Asks StoreKit whether the subscription is active, and the relay, a few times a day, for the limits.
    func refresh() async {
        var active = false
        for await entitlement in Transaction.currentEntitlements {
            if case .verified(let transaction) = entitlement, Self.productIDs.contains(transaction.productID),
               transaction.revocationDate == nil, (transaction.expirationDate ?? .distantFuture) > .now {
                active = true
            }
        }
        subscribed = active
        await refreshLimits()
    }

    private func refreshLimits() async {
        let defaults = UserDefaults.standard
        if let checked = defaults.object(forKey: Defaults.limitsCheckedAt) as? Date, Date.now.timeIntervalSince(checked) < 6 * 3600 { return }
        let request = URLRequest(url: Brand.relay.appending(path: "v1/limits"), cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 10)
        // Without an answer, the limits stay what they were.
        guard let (data, response) = try? await URLSession(configuration: .ephemeral).data(for: request),
              (response as? HTTPURLResponse)?.statusCode == 200,
              let fetched = try? JSONDecoder().decode(FreeLimits.self, from: data) else { return }
        limits = fetched
        defaults.set(try? JSONEncoder().encode(fetched), forKey: Defaults.limits)
        defaults.set(Date.now, forKey: Defaults.limitsCheckedAt)
    }

    /// Whether the free limits apply to a computer on `relay`.
    func isLimited(_ relay: URL) -> Bool {
        !isUnlimited && Brand.hostedRelayHosts.contains(relay.host()?.lowercased() ?? "")
    }

    /// Unlocks and approvals used today, on computers with limits.
    var usedToday: Int { use.count(on: .now) }

    /// Whether `uses` more unlocks or approvals fit in today's free ones.
    func canUse(_ uses: Int) -> Bool {
        guard uses > 0, let perDay = limits.perDay else { return true }
        return usedToday + uses <= perDay
    }

    func recordUse(_ uses: Int) {
        guard uses > 0 else { return }
        use.add(uses, on: .now)
        UserDefaults.standard.set(try? JSONEncoder().encode(use), forKey: Defaults.use)
    }

    /// Whether `machine` is beyond the free number of computers. The first ones paired stay free.
    func isBeyondFreeComputers(_ machine: PairedMachine, among machines: [PairedMachine]) -> Bool {
        guard isLimited(machine.relay), let free = limits.computers else { return false }
        return !machines.filter { isLimited($0.relay) }.prefix(free).contains { $0.machineId == machine.machineId }
    }

    /// Whether pairing a computer on `relay` still fits the free number, apart from the one it replaces.
    func canPair(on relay: URL, replacing machineId: String, among machines: [PairedMachine]) -> Bool {
        guard isLimited(relay), let free = limits.computers else { return true }
        return machines.filter { isLimited($0.relay) && $0.machineId != machineId }.count < free
    }

    /// Why another computer needs the subscription.
    var computerLimitMessage: String { "The free version works with \(Self.computers(limits.computers ?? 0))." }

    /// What the free version allows, in a sentence.
    var freeSummary: String {
        switch (limits.computers, limits.perDay) {
        case let (computers?, perDay?): "The free version works with \(Self.computers(computers)) and \(perDay) unlocks and approvals a day."
        case let (computers?, nil): "The free version works with \(Self.computers(computers))."
        case let (nil, perDay?): "The free version allows \(perDay) unlocks and approvals a day."
        case (nil, nil): "The free version has no limits right now."
        }
    }

    static func computers(_ count: Int) -> String {
        count == 1 ? "1 computer" : "\(count) computers"
    }
}
