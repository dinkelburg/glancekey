import ActivityKit
import AppCore
import SwiftUI
import WidgetKit

// Draws the lock screen card (iOS/Shared/LiveCard.swift) on the Lock Screen and in the Dynamic Island.

@main
struct Widgets: WidgetBundle {
    var body: some Widget {
        LiveCardWidget()
    }
}

struct LiveCardWidget: Widget {
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: LiveCardAttributes.self) { context in
            CardView(state: context.state, showsHeader: true)
                .padding(.horizontal, 14)
                .padding(.vertical, 12)
                .widgetURL(LiveCardLink.open(request: nil).url(key: context.state.key))
        } dynamicIsland: { context in
            let state = context.state
            let badge = state.badge
            return DynamicIsland {
                DynamicIslandExpandedRegion(.bottom) {
                    CardView(state: state, showsHeader: false)
                        .padding(.horizontal, 4)
                }
            } compactLeading: {
                Image(systemName: badge.symbol)
                    .foregroundStyle(badge.tint)
            } compactTrailing: {
                if let count = badge.count {
                    Text("\(count)")
                        .font(.caption.weight(.semibold).monospacedDigit())
                        .foregroundStyle(badge.tint)
                }
            } minimal: {
                Image(systemName: badge.symbol)
                    .foregroundStyle(badge.tint)
            }
            .widgetURL(LiveCardLink.open(request: nil).url(key: state.key))
            .keylineTint(CardColor.blue)
        }
    }
}

private enum CardColor {
    static let blue = Color(red: 0.18, green: 0.49, blue: 0.96)
    static let locked = Color.orange
    static let unlocked = Color.green
}

private typealias Computer = LiveCardAttributes.ContentState.Computer
private typealias Request = LiveCardAttributes.ContentState.Request
private typealias Busy = LiveCardAttributes.ContentState.Busy

private extension LiveCardAttributes.ContentState {
    var waiting: [Request] { requests.filter { $0.expiresAt > .now } }
    var locked: [Computer] { computers.filter { $0.state == .locked } }
    var offline: [Computer] { computers.filter { $0.state == .offline } }
    var allUnlocked: Bool { computers.allSatisfy { $0.state == .unlocked } }

    /// For the Dynamic Island: what's waiting, else what's locked, else whether all are unlocked.
    var badge: (symbol: String, tint: Color, count: Int?) {
        if !waiting.isEmpty { return ("key.fill", CardColor.blue, waiting.count) }
        if !locked.isEmpty { return ("lock.fill", CardColor.locked, locked.count) }
        if allUnlocked { return ("lock.open.fill", CardColor.unlocked, nil) }
        return ("wifi.slash", .gray, nil)
    }

    var summary: String {
        var parts: [String] = []
        if !locked.isEmpty { parts.append("\(locked.count) locked") }
        if !offline.isEmpty { parts.append("\(offline.count) offline") }
        if !waiting.isEmpty { parts.append("\(waiting.count) waiting") }
        return parts.isEmpty && allUnlocked ? "All unlocked" : parts.joined(separator: " · ")
    }

    func name(of computer: String) -> String {
        computers.first { $0.id == computer }?.name ?? ""
    }

    /// The button working on a computer or request. One that hasn't finished in a minute has stopped (the app was
    /// ended, say), so its buttons show again.
    func busy(_ id: String) -> Busy? {
        busy?.first { $0.id == id && Date(timeIntervalSince1970: TimeInterval($0.since)) > .now.addingTimeInterval(-60) }
    }
}

/// The rows, as many as fit: iOS cuts a Live Activity off at 160 points. Requests come first, then the computers,
/// locked ones first.
private struct CardView: View {
    let state: LiveCardAttributes.ContentState
    let showsHeader: Bool

    private static let height: CGFloat = 160 - 24
    private static let headerHeight: CGFloat = 17
    private static let spacing: CGFloat = 6
    private static let requestHeight: CGFloat = 34
    private static let computerHeight: CGFloat = 26

    private var rows: (requests: [Request], computers: [Computer]) {
        let requests = Array(state.waiting.prefix(2))
        let room = Self.height - (showsHeader ? Self.headerHeight : 0) - CGFloat(requests.count) * (Self.requestHeight + Self.spacing)
        let fitting = max(0, Int(room / (Self.computerHeight + Self.spacing)))
        let sorted = state.computers.filter { $0.state == .locked } + state.computers.filter { $0.state != .locked }
        return (requests, Array(sorted.prefix(fitting)))
    }

    var body: some View {
        let (requests, computers) = rows
        let hidden = state.computers.count - computers.count

        VStack(alignment: .leading, spacing: Self.spacing) {
            if showsHeader {
                HStack {
                    Text(Brand.name).font(.subheadline.weight(.semibold))
                    Spacer()
                    Text(hidden > 0 ? "\(state.summary) · \(hidden) more" : state.summary)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .frame(height: Self.headerHeight)
            }
            ForEach(requests) { request in
                RequestRow(request: request, computerName: state.name(of: request.computer), key: state.key, busy: state.busy(request.id))
                    .frame(height: Self.requestHeight)
            }
            ForEach(computers) { computer in
                ComputerRow(computer: computer, busy: state.busy(computer.id), key: state.key)
                    .frame(height: Self.computerHeight)
            }
        }
    }
}

private struct ComputerRow: View {
    let computer: Computer
    let busy: Busy?
    let key: String

    var body: some View {
        // Unlock and Lock only work right away when the whole name fits: when it's cut off, two computers could look the
        // same, so the link says nothing was shown and the app opens the computer instead.
        ViewThatFits(in: .horizontal) {
            row(fitsInFull: true)
            row(fitsInFull: false)
        }
    }

    private func row(fitsInFull: Bool) -> some View {
        HStack(spacing: 8) {
            Circle()
                .fill(color)
                .frame(width: 7, height: 7)
            Text(computer.name)
                .font(.subheadline.weight(.semibold))
                .lineLimit(1)
                .fixedSize(horizontal: fitsInFull, vertical: false)
            Spacer(minLength: 4)
            Text(stateName)
                .font(.caption)
                .foregroundStyle(.secondary)
            if let busy {
                BusyLabel(busy: busy)
            } else {
                switch computer.state {
                case .locked:
                    Link(destination: LiveCardLink.unlock(computer: computer.id, shown: shown(fitsInFull)).url(key: key)) {
                        CapsuleLabel("Unlock", prominent: true)
                    }
                case .unlocked:
                    Link(destination: LiveCardLink.lock(computer: computer.id, shown: shown(fitsInFull)).url(key: key)) {
                        CapsuleLabel("Lock", prominent: false)
                    }
                case .offline, .unknown:
                    EmptyView()
                }
            }
        }
    }

    private func shown(_ fitsInFull: Bool) -> String? {
        fitsInFull ? LiveCardLink.shown(computer.name) : nil
    }

    private var color: Color {
        switch computer.state {
        case .locked: CardColor.locked
        case .unlocked: CardColor.unlocked
        case .offline, .unknown: .gray
        }
    }

    private var stateName: String {
        switch computer.state {
        case .locked: "Locked"
        case .unlocked: "Unlocked"
        case .offline: "Offline"
        case .unknown: ""
        }
    }
}

private struct RequestRow: View {
    let request: Request
    let computerName: String
    let key: String
    let busy: Busy?

    var body: some View {
        // Approve only works right away when the whole command fits on the card. When it's cut off, the link says
        // nothing was shown, so the app opens the request and waits for a tap on Approve there.
        ViewThatFits(in: .horizontal) {
            row(fitsInFull: true)
            row(fitsInFull: false)
        }
    }

    private func row(fitsInFull: Bool) -> some View {
        HStack(spacing: 8) {
            // Tapping the request itself opens it in the app.
            Link(destination: LiveCardLink.open(request: request.id).url(key: key)) {
                VStack(alignment: .leading, spacing: 1) {
                    Text(request.title)
                        .font(.system(.footnote, design: .monospaced).weight(.semibold))
                        .lineLimit(1)
                        .fixedSize(horizontal: fitsInFull, vertical: false)
                    HStack(spacing: 4) {
                        Text(computerName)
                            .fixedSize(horizontal: fitsInFull, vertical: false)
                        if request.expiresAt > .now && ApprovalWait.showsCountdown(until: request.expiresAt) {
                            Text("·")
                            // A timer asks for more room than it shows, which would make every request look cut off.
                            Text(timerInterval: Date.now...request.expiresAt, countsDown: true)
                                .monospacedDigit()
                                .frame(maxWidth: 52, alignment: .leading)
                        }
                    }
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            if let busy {
                BusyLabel(busy: busy)
            } else {
                // Deny is in the app, a tap on the request away; the card keeps the room for the command.
                let shown = fitsInFull ? LiveCardLink.shown(request.title, computerName) : nil
                Link(destination: LiveCardLink.approve(computer: request.computer, request: request.id, shown: shown).url(key: key)) {
                    CapsuleLabel("Approve", prominent: true)
                }
            }
        }
    }
}

/// In place of the buttons while one works. Live Activities don't run animations, but a timer's progress ring fills
/// by itself.
private struct BusyLabel: View {
    let busy: Busy

    var body: some View {
        let started = Date(timeIntervalSince1970: TimeInterval(busy.since))
        HStack(spacing: 6) {
            ProgressView(timerInterval: started...started.addingTimeInterval(15), countsDown: false) {
                EmptyView()
            } currentValueLabel: {
                EmptyView()
            }
            .progressViewStyle(.circular)
            .tint(CardColor.blue)
            .frame(width: 14, height: 14)
            Text(title)
        }
        .font(.caption.weight(.semibold))
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .background(Capsule().fill(Color.primary.opacity(0.14)))
    }

    private var title: String {
        switch CardButton(rawValue: busy.button) {
        case .unlock: "Unlocking…"
        case .lock: "Locking…"
        case .approve: "Approving…"
        case nil: "Working…"
        }
    }
}

private struct CapsuleLabel: View {
    let title: String
    let prominent: Bool

    init(_ title: String, prominent: Bool) {
        self.title = title
        self.prominent = prominent
    }

    var body: some View {
        Text(title)
            .font(.caption.weight(.semibold))
            .foregroundStyle(prominent ? .white : .primary)
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .background(Capsule().fill(prominent ? CardColor.blue : Color.primary.opacity(0.14)))
    }
}
