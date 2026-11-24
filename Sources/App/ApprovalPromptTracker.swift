import Foundation

/// What the approval card shows, decided from the connection state
/// alone (DESIGN.md §29.1). Foundation only, so the contract runs in
/// scripts/approval-prompt-test.sh without AppKit or a Helper.
///
/// - approval: the engine knows a login is waiting on the phone (the
///   Cisco engine, right after the password went in).
/// - ownLogin: the own connection is logging in; openconnect gives no
///   approval signal yet (§16.5), so the card says "when the request
///   arrives on the phone" instead of claiming one is pending.
/// - establishing: the login went through, the tunnel is being set up.
/// - connected / ended / other: the wait is over one way or another.
///
/// Every new wait counts as one request in the series that runs until
/// connected or disconnected; a hidden card stays hidden for that wait
/// only, the next request shows it again.
struct ApprovalPromptTracker {
    enum Signal: Equatable {
        case approval, ownLogin, newAttempt, gatewayReply, configuring, establishing, connected, ended, other
        /// Nobody approved in time; the engine asks again in this many
        /// seconds (-1: not stated).
        case expired(Int)
    }

    enum Kind: Equatable { case approval, ownLogin }
    enum Stage: Equatable { case waiting, gatewayReply, configuring, establishing, connected, expired }

    struct Card: Equatable {
        var kind: Kind
        /// 1 for the first request since the last connect/disconnect.
        var request: Int
        var since: Date
        var stage: Stage = .waiting
        /// When the engine sends the next request (expired stage).
        var retryAt: Date? = nil
    }

    enum Effect: Equatable {
        case none
        /// Show (or replace) the card.
        case show(Card)
        /// Same wait, new stage: update the card in place.
        case update(Card)
        /// Connected: show the success state briefly, then go.
        case finish(Card)
        case hide
    }

    /// The engine saw the HTTP reply to the credential request. A reply may also reject the login.
    static func ownLoginSignal(_ detail: String) -> Signal {
        if detail.hasPrefix("spawning openconnect (attempt ") { return .newAttempt }
        if detail.hasPrefix(expiredPrefix) { return .expired(retryDelay(detail) ?? -1) }
        switch detail {
        case "approval answered": return .gatewayReply
        case "tunnel negotiation accepted": return .configuring
        default: return .ownLogin
        }
    }

    /// Both engines report an expired approval as
    /// "手机上的批准已超时，N 秒后…" or "…，N 分钟后…" (§21.19, §30.9).
    static let expiredPrefix = "手机上的批准已超时"

    static func retryDelay(_ detail: String) -> Int? {
        for (unit, scale) in [(" 秒后", 1), (" 分钟后", 60)] {
            guard let range = detail.range(of: unit) else { continue }
            let digits = detail[..<range.lowerBound].reversed().prefix { $0.isNumber }
            if let value = Int(String(digits.reversed())) { return value * scale }
        }
        return nil
    }

    private(set) var card: Card?
    private(set) var hidden = false
    private var requests = 0

    var isVisible: Bool { card != nil && !hidden }

    mutating func handle(_ signal: Signal, now: Date = Date()) -> Effect {
        switch signal {
        case .newAttempt:
            // Later status readbacks cannot turn an answered request back into a phone prompt.
            // Only a new CLI attempt or a real new approval wait can start one.
            return close(success: false)
        case .approval, .ownLogin:
            if signal == .ownLogin, card?.stage == .gatewayReply || card?.stage == .configuring
                || card?.stage == .expired { return .none }
            let kind: Kind = signal == .approval ? .approval : .ownLogin
            if let card, card.kind == kind, card.stage == .waiting {
                return .none  // the same state pushed again
            }
            // Only phone requests count: "logging in" turning into a
            // real approval wait is still the first request.
            if kind == .approval { requests += 1 }
            let wasHidden = card?.kind == .ownLogin && card?.stage == .waiting && hidden
            let next = Card(kind: kind, request: max(requests, 1), since: now)
            card = next
            // Hidden while logging in = hidden for this login's approval too.
            hidden = wasHidden
            return wasHidden ? .none : .show(next)
        case .gatewayReply, .configuring:
            let stage: Stage = signal == .configuring ? .configuring : .gatewayReply
            guard card?.stage != stage, !(card?.stage == .configuring && stage == .gatewayReply) else { return .none }
            let previous = card
            let next = Card(kind: .ownLogin, request: previous?.request ?? max(requests, 1),
                            since: previous?.since ?? now, stage: stage)
            card = next
            if hidden { return .none }
            return previous == nil ? .show(next) : .update(next)
        case .expired(let seconds):
            // The wait is over without an answer: say so and when the next
            // request goes out, instead of "网关已回应" (user, 2026-11-24).
            if card?.stage == .expired { return .none }
            let previous = card
            let next = Card(kind: previous?.kind ?? .approval, request: max(requests, 1), since: now,
                            stage: .expired, retryAt: seconds >= 0 ? now.addingTimeInterval(TimeInterval(seconds)) : nil)
            card = next
            let wasHidden = hidden
            hidden = false
            return previous == nil || wasHidden ? .show(next) : .update(next)
        case .establishing:
            guard var current = card, current.stage == .waiting || current.stage == .gatewayReply else { return .none }
            current.stage = .establishing
            card = current
            return hidden ? .none : .update(current)
        case .connected:
            requests = 0
            return close(success: true)
        case .ended:
            requests = 0
            return close(success: false)
        case .other:
            return close(success: false)
        }
    }

    /// The user hid the card: it stays away for this wait only.
    mutating func hide() {
        hidden = true
    }

    private mutating func close(success: Bool) -> Effect {
        defer { card = nil; hidden = false }
        guard var current = card else { return .none }
        if hidden { return .hide }
        if success {
            current.stage = .connected
            return .finish(current)
        }
        return .hide
    }
}

extension ApprovalPromptTracker.Card {
    var title: String {
        switch (stage, kind) {
        case (.expired, _): return "手机上的批准已超时"
        case (.gatewayReply, _): return "网关已回应"
        case (.configuring, _): return "正在配置 VPN 网络"
        case (.connected, _): return "已连接"
        case (.establishing, .approval): return "已批准，正在连接…"
        case (.establishing, .ownLogin): return "正在建立连接…"
        case (.waiting, .approval): return "请在手机上批准 VPN 登录"
        case (.waiting, .ownLogin): return "正在登录 VPN"
        }
    }

    /// The line under the title, with the time waited so far.
    func subtitle(now: Date) -> String {
        switch stage {
        case .connected: return "可以继续工作了"
        case .expired:
            // Short enough for the bubble's one line.
            let count = request > 1 ? "第 \(request) 次 · " : ""
            guard let retryAt else { return count + "稍后重新发起" }
            let left = retryAt.timeIntervalSince(now)
            return left > 0.5 ? count + Self.clock(left) + " 后重新发起" : "正在重新发起…"
        case .configuring: return "隧道协商完成 · " + Self.clock(now.timeIntervalSince(since))
        case .gatewayReply: return "等待连接结果 · " + Self.clock(now.timeIntervalSince(since))
        case .establishing: return "马上就好"
        case .waiting:
            let waited = "已等 " + Self.clock(now.timeIntervalSince(since))
            switch kind {
            case .approval:
                return request > 1 ? "第 \(request) 次请求 · \(waited)" : "登录请求已发到手机 · \(waited)"
            case .ownLogin:
                return "收到手机请求请批准 · " + Self.clock(now.timeIntervalSince(since))
            }
        }
    }

    /// m:ss, never negative.
    static func clock(_ seconds: TimeInterval) -> String {
        let s = max(0, Int(seconds))
        return String(format: "%d:%02d", s / 60, s % 60)
    }
}
