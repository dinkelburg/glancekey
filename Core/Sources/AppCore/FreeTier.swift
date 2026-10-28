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
/// iPhone's time zone) starts again from zero.
public struct DailyUse: Codable, Equatable, Sendable {
    /// The day counted, as yyyy-MM-dd.
    public var day: String
    public var count: Int

    public init(day: String = "", count: Int = 0) {
        self.day = day
        self.count = count
    }

    public func count(on date: Date, calendar: Calendar = .current) -> Int {
        day == Self.day(of: date, calendar: calendar) ? count : 0
    }

    public mutating func add(_ uses: Int, on date: Date, calendar: Calendar = .current) {
        let today = Self.day(of: date, calendar: calendar)
        count = (day == today ? count : 0) + uses
        day = today
    }

    static func day(of date: Date, calendar: Calendar) -> String {
        let parts = calendar.dateComponents([.year, .month, .day], from: date)
        return String(format: "%04d-%02d-%02d", parts.year ?? 0, parts.month ?? 0, parts.day ?? 0)
    }
}
