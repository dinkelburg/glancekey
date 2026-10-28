import Foundation

/// What the App Store app allows without the subscription, on the relay we host (`Brand.hostedRelayHosts`): this many
/// computers, and this many unlocks and approvals a day, all computers together. The relay says how many
/// (`GET /v1/limits`, relay/src/index.ts), so they can change without an app update. Copies of the app people build
/// themselves, and computers on a relay of their own, have no limits.
public struct FreeLimits: Codable, Equatable, Sendable {
    /// nil: no limit.
    public var computers: Int?
    public var perDay: Int?

    /// Until the relay has said otherwise.
    public static let standard = FreeLimits(computers: 2, perDay: 15)

    public init(computers: Int?, perDay: Int?) {
        self.computers = computers
        self.perDay = perDay
    }
}

/// The unlocks and approvals counted today. The iPhone counts them itself, so they never leave it; a new day (in the
/// iPhone's time zone) starts again from zero. The last few days stay counted too, so setting the clock back to one of
/// them doesn't start it again.
public struct DailyUse: Codable, Equatable, Sendable {
    /// The day counted, as yyyy-MM-dd.
    public var day: String
    public var count: Int
    /// Earlier days, by yyyy-MM-dd: the newest `keptDays`.
    public var earlier: [String: Int]?

    static let keptDays = 7

    public init(day: String = "", count: Int = 0, earlier: [String: Int]? = nil) {
        self.day = day
        self.count = count
        self.earlier = earlier
    }

    public func count(on date: Date, calendar: Calendar = .current) -> Int {
        let today = Self.day(of: date, calendar: calendar)
        return day == today ? count : earlier?[today] ?? 0
    }

    public mutating func add(_ uses: Int, on date: Date, calendar: Calendar = .current) {
        let today = Self.day(of: date, calendar: calendar)
        if day != today {
            var days = earlier ?? [:]
            if !day.isEmpty { days[day] = count }
            count = days.removeValue(forKey: today) ?? 0
            day = today
            // yyyy-MM-dd sorts by date.
            let kept = Set(days.keys.sorted().suffix(Self.keptDays))
            earlier = days.isEmpty ? nil : days.filter { kept.contains($0.key) }
        }
        count += uses
    }

    static func day(of date: Date, calendar: Calendar) -> String {
        let parts = calendar.dateComponents([.year, .month, .day], from: date)
        return String(format: "%04d-%02d-%02d", parts.year ?? 0, parts.month ?? 0, parts.day ?? 0)
    }
}
