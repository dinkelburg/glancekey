import ActivityKit
import AppCore
import CryptoKit
import Foundation

// The lock screen card, a Live Activity: the paired computers, whether each is locked, and the requests waiting for
// approval, with buttons. Compiled into the app and the widget extension (iOSWidgets), which draws it.
//
// The computers keep it up to date through the relay, which pushes it to the iPhone (relay/src/index.ts, `Card`)
// and builds `ContentState` as JSON there: keep the two in sync. The app starts the card and updates it while it's
// open (`LiveCardController`).

struct LiveCardAttributes: ActivityAttributes {
    struct ContentState: Codable, Hashable {
        struct Computer: Codable, Hashable, Identifiable {
            enum State: String, Codable {
                case locked, unlocked, offline, unknown

                /// A state a newer relay adds shows as unknown instead of failing the whole update.
                init(from decoder: Decoder) throws {
                    self = State(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
                }
            }

            var id: String
            var name: String
            var state: State
        }

        struct Request: Codable, Hashable, Identifiable {
            /// The computer's id.
            var computer: String
            var id: String
            /// What it's for, e.g. "sudo pacman -Syu".
            var title: String
            var detail: String
            /// When the computer stops waiting, in seconds since 1970. Not a Date: ActivityKit decodes those as
            /// seconds since 2001, which the relay would have to know.
            var until: Int

            var expiresAt: Date { Date(timeIntervalSince1970: TimeInterval(until)) }
        }

        /// A button on the card that's working: the computer or request it's for, and since when (seconds since
        /// 1970). Only the app sets it; the relay doesn't send it, so its next update (the computer's new state) ends it.
        struct Busy: Codable, Hashable {
            var id: String
            /// A `CardButton`.
            var button: String
            var since: Int
        }

        var computers: [Computer]
        var requests: [Request]
        /// See `LiveCardLink`.
        var key: String
        var busy: [Busy]?
    }
}

/// The card's buttons, and tapping a request, open the app with one of these links. They carry the
/// card's key, which only the app, the relay and the card know, so the app only acts on links from its own card and
/// not on one that a web page opens. The buttons also carry `shown`, a digest of what the card showed next to them
/// (`shown(_:)`): the app only acts right away when that's what it's about to sign. Otherwise (the command didn't fit on
/// the card, or the relay put other text there) it opens the request or computer and waits for a tap.
enum LiveCardLink: Equatable {
    /// Opens the app, at a request if there is one.
    case open(request: String?)
    case unlock(computer: String, shown: String?)
    case lock(computer: String, shown: String?)
    case approve(computer: String, request: String, shown: String?)

    /// A digest of the text the card showed in full.
    static func shown(_ texts: String...) -> String {
        SHA256.hash(data: Data(texts.joined(separator: "\n").utf8)).prefix(12).map { String(format: "%02x", $0) }.joined()
    }

    func url(key: String) -> URL {
        var components = URLComponents()
        components.scheme = Brand.urlScheme
        components.host = "card"
        var items: [URLQueryItem]
        switch self {
        case .open(let request): items = [.init(name: "do", value: "open")] + (request.map { [.init(name: "request", value: $0)] } ?? [])
        case .unlock(let computer, _): items = [.init(name: "do", value: "unlock"), .init(name: "computer", value: computer)]
        case .lock(let computer, _): items = [.init(name: "do", value: "lock"), .init(name: "computer", value: computer)]
        case .approve(let computer, let request, _):
            items = [.init(name: "do", value: "approve"), .init(name: "computer", value: computer), .init(name: "request", value: request)]
        }
        if let shown { items.append(.init(name: "shown", value: shown)) }
        components.queryItems = items + [.init(name: "key", value: key)]
        return components.url!
    }

    private var shown: String? {
        switch self {
        case .open: nil
        case .unlock(_, let shown), .lock(_, let shown), .approve(_, _, let shown): shown
        }
    }

    /// nil if `url` isn't a card link, or doesn't carry `key`.
    init?(url: URL, key: String) {
        guard url.scheme == Brand.urlScheme, url.host == "card",
              let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems
        else { return nil }
        func value(_ name: String) -> String? { items.first { $0.name == name }?.value }
        guard !key.isEmpty, value("key") == key else { return nil }
        switch (value("do"), value("computer"), value("request")) {
        case ("open", _, let request): self = .open(request: request)
        case ("unlock", let computer?, _): self = .unlock(computer: computer, shown: value("shown"))
        case ("lock", let computer?, _): self = .lock(computer: computer, shown: value("shown"))
        case ("approve", let computer?, let request?): self = .approve(computer: computer, request: request, shown: value("shown"))
        default: return nil
        }
    }
}

/// What the card's buttons do. They open the app (`LiveCardLink`), which asks for Face ID: iOS only lets an app do
/// that while it's on screen, so a button can't do it on the Lock Screen.
enum CardButton: String {
    case unlock, lock, approve
}
