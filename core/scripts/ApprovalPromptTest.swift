import Foundation

// Approval card contract (DESIGN.md §29): Sources/App/ApprovalPromptTracker.swift
// alone. Which state stream shows, updates, finishes or hides the card.

var failures = 0
func check(_ ok: Bool, _ name: String) {
    print(ok ? "PASS" : "FAIL", name)
    if !ok { failures += 1 }
}

@main
struct ApprovalPromptTest {
    static func main() {
        let t0 = Date(timeIntervalSince1970: 1_000_000)
        func at(_ s: TimeInterval) -> Date { t0.addingTimeInterval(s) }
        typealias T = ApprovalPromptTracker

        // 1 Cisco: password in -> approval -> approved -> connected
        var t = T()
        check(t.handle(.other, now: at(0)) == .none, "nothing to hide before a wait")
        check(t.handle(.establishing, now: at(0)) == .none, "connecting without a wait shows nothing")
        guard case .show(let c1) = t.handle(.approval, now: at(1)) else {
            check(false, "approval shows the card"); exit(1)
        }
        check(c1.kind == .approval && c1.request == 1 && c1.stage == .waiting, "first request, waiting")
        check(t.handle(.approval, now: at(2)) == .none, "the same state pushed again changes nothing")
        check(c1.title == "请在手机上批准 Cisco 登录", "title: \(c1.title)")
        check(c1.subtitle(now: at(24)) == "登录请求已发到手机 · 已等 0:23", "subtitle: \(c1.subtitle(now: at(24)))")
        guard case .update(let c2) = t.handle(.establishing, now: at(30)) else {
            check(false, "approved -> establishing updates"); exit(1)
        }
        check(c2.stage == .establishing && c2.title == "已批准，正在连接…", "establishing: \(c2.title)")
        guard case .finish(let c3) = t.handle(.connected, now: at(33)) else {
            check(false, "connected finishes"); exit(1)
        }
        check(c3.stage == .connected && c3.title == "已连接", "connected card")
        check(!t.isVisible && t.handle(.connected, now: at(34)) == .none, "card gone after finishing")

        // 2 approval expired -> retry -> second request; count resets on connect
        _ = t.handle(.approval, now: at(100))
        check(t.handle(.other, now: at(220)) == .hide, "expired approval (retry wait) hides")
        guard case .show(let c4) = t.handle(.approval, now: at(280)) else {
            check(false, "new push shows again"); exit(1)
        }
        check(c4.request == 2 && c4.subtitle(now: at(345)) == "第 2 次请求 · 已等 1:05",
              "second request: \(c4.subtitle(now: at(345)))")
        _ = t.handle(.connected, now: at(300))
        guard case .show(let c5) = t.handle(.approval, now: at(900)) else {
            check(false, "after connect"); exit(1)
        }
        check(c5.request == 1, "request count resets after connecting")

        // 3 hidden by the user: stays hidden for this wait, back next request
        t.hide()
        check(!t.isVisible, "hidden")
        check(t.handle(.approval, now: at(901)) == .none, "repeat push keeps it hidden")
        check(t.handle(.establishing, now: at(902)) == .none, "no update while hidden")
        check(t.handle(.other, now: at(903)) == .hide, "wait ends")
        guard case .show(let c6) = t.handle(.approval, now: at(960)) else {
            check(false, "next request shows again"); exit(1)
        }
        check(c6.request == 2, "hidden wait still counted")
        t.hide()
        check(t.handle(.connected, now: at(970)) == .hide, "connected while hidden: no success flash")

        // 4 manual disconnect during a wait hides and resets the count
        _ = t.handle(.approval, now: at(1000))
        check(t.handle(.ended, now: at(1010)) == .hide, "disconnect hides")
        if case .show(let c7) = t.handle(.approval, now: at(1100)) {
            check(c7.request == 1, "count reset by disconnect")
        } else { check(false, "show after disconnect") }

        // 5 own connection: logging in, honest wording
        var o = T()
        guard case .show(let o1) = o.handle(.ownLogin, now: at(0)) else {
            check(false, "own login shows"); exit(1)
        }
        check(o1.title == "正在登录 Cisco" && o1.subtitle(now: at(9)) == "收到手机请求请批准 · 0:09",
              "own wording: \(o1.subtitle(now: at(9)))")
        if case .update(let o2) = o.handle(.establishing, now: at(12)) {
            check(o2.title == "正在建立连接…", "own establishing: \(o2.title)")
        } else { check(false, "own establishing updates") }
        if case .finish = o.handle(.connected, now: at(14)) {} else { check(false, "own finishes") }

        // 6 own connection: logging in, then the engine sees the approval wait
        var w = T()
        _ = w.handle(.ownLogin, now: at(0))
        if case .show(let w1) = w.handle(.approval, now: at(4)) {
            check(w1.kind == .approval && w1.request == 1, "login -> approval is still request 1 (got \(w1.request))")
        } else { check(false, "login -> approval shows the approval card") }
        _ = w.handle(.other, now: at(130))
        if case .show(let w2) = w.handle(.approval, now: at(190)) {
            check(w2.request == 2, "re-asked approval is request 2")
        } else { check(false, "re-ask shows") }
        var h = T()
        _ = h.handle(.ownLogin, now: at(0))
        h.hide()
        check(h.handle(.approval, now: at(4)) == .none, "hidden during login stays hidden for its approval")

        // The own engine reports an HTTP result before the tunnel or its protection is ready.
        var response = T()
        _ = response.handle(.approval, now: at(23))
        if case .update(let reply) = response.handle(.gatewayReply, now: at(51)) {
            check(reply.title == "网关已回应" && reply.subtitle(now: at(55)) == "等待连接结果 · 0:32",
                  "reply clears the phone instruction and keeps elapsed time")
            check(response.handle(.gatewayReply, now: at(56)) == .none, "repeated reply does not restart the wait")
        } else { check(false, "gateway response updates the visible approval card") }
        if case .update(let configuring) = response.handle(.configuring, now: at(52)) {
            check(configuring.title == "正在配置 Cisco 网络" && configuring.subtitle(now: at(54)).hasSuffix("0:31"),
                  "accepted tunnel changes the stage without reporting a connected VPN")
        } else { check(false, "negotiated tunnel updates the card") }
        check(response.handle(.gatewayReply, now: at(55)) == .none, "late generic reply cannot undo tunnel negotiation")
        check(T.ownLoginSignal("tunnel negotiation accepted") == .configuring, "only complete negotiation selects configuring")
        check(response.handle(.ownLogin, now: at(56)) == .none, "an unrelated status cannot repeat the phone instruction")
        if case .finish = response.handle(.connected, now: at(67)) {} else { check(false, "actual readiness closes response stage") }
        _ = response.handle(.ownLogin, now: at(80))
        response.hide()
        check(response.handle(.gatewayReply, now: at(84)) == .none && !response.isVisible,
              "a hidden wait remains hidden on gateway reply")
        check(response.handle(.ended, now: at(85)) == .hide, "a rejected login ends without success")
        if case .show = response.handle(.approval, now: at(90)) {} else { check(false, "a fresh attempt can prompt again") }
        check(T.ownLoginSignal("approval answered") == .gatewayReply && T.ownLoginSignal("openconnect exited") == .ownLogin,
              "only the credential HTTP response selects the response stage")

        _ = response.handle(.gatewayReply, now: at(92))
        check(response.handle(.newAttempt, now: at(95)) == .hide, "new attempt retires the old reply")
        if case .show(let retry) = response.handle(.ownLogin, now: at(98)) {
            check(retry.stage == .waiting && retry.since == at(98), "retry gets its own waiting clock")
        } else { check(false, "fresh login may prompt again") }

        check(T.Card.clock(-3) == "0:00" && T.Card.clock(3600) == "60:00", "clock")

        // An expired request says so and counts down to the next one (2026-11-24).
        check(T.ownLoginSignal("手机上的批准已超时，30 秒后重新发起批准") == .expired(30)
              && T.ownLoginSignal("手机上的批准已超时，5 分钟后重新发起批准") == .expired(300)
              && T.ownLoginSignal("手机上的批准已超时") == .expired(-1), "expiry details parse")
        var expiry = T()
        _ = expiry.handle(.approval, now: at(0))
        _ = expiry.handle(.gatewayReply, now: at(100))
        if case .update(let late) = expiry.handle(.expired(120), now: at(101)) {
            check(late.title == "手机批准已超时" && late.subtitle(now: at(101)) == "2:00 后自动重发"
                  && late.subtitle(now: at(220)) == "0:01 后自动重发"
                  && late.subtitle(now: at(222)) == "正在重新发起…", "expiry replaces the gateway reply and counts down")
        } else { check(false, "expiry updates the card") }
        check(expiry.handle(.expired(120), now: at(110)) == .none, "the same expiry pushed again changes nothing")
        check(expiry.handle(.ownLogin, now: at(111)) == .none, "a status readback keeps the expiry card")
        check(expiry.handle(.newAttempt, now: at(221)) == .hide, "the next attempt retires the expiry card")
        if case .show(let second) = expiry.handle(.approval, now: at(222)) {
            check(second.request == 2 && second.subtitle(now: at(222)).hasPrefix("第 2 次请求"), "the next push counts as request 2")
        } else { check(false, "next push shows") }
        _ = expiry.handle(.expired(60), now: at(322))
        check(expiry.card?.subtitle(now: at(322)) == "第 2 次 · 1:00 后重发", "later expiries name the count")
        var hiddenExpiry = T()
        _ = hiddenExpiry.handle(.approval, now: at(0))
        hiddenExpiry.hide()
        if case .show = hiddenExpiry.handle(.expired(30), now: at(100)) {} else { check(false, "expiry ends a hidden wait and shows") }

        print(failures == 0 ? "ALL PASS" : "\(failures) FAILED")
        exit(failures == 0 ? 0 : 1)
    }
}
