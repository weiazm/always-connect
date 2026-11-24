import Foundation

// The App talks to these stand-ins only in scripts/egress-notification-test.sh.
// No notification is delivered to the desktop and no VPN client is started.
protocol UNUserNotificationCenterDelegate: AnyObject {}

final class UNUserNotificationCenter {
    static let shared = UNUserNotificationCenter()
    static func current() -> UNUserNotificationCenter { shared }

    weak var delegate: UNUserNotificationCenterDelegate?
    private(set) var categories: [UNNotificationCategory] = []
    private(set) var requests: [UNNotificationRequest] = []

    func setNotificationCategories(_ categories: [UNNotificationCategory]) {
        self.categories = categories
    }

    func requestAuthorization(options: Set<NotificationOption>, completionHandler: (Bool, Error?) -> Void) {
        completionHandler(true, nil)
    }

    func add(_ request: UNNotificationRequest, withCompletionHandler: ((Error?) -> Void)?) {
        requests.append(request)
        withCompletionHandler?(nil)
    }
}

enum NotificationOption { case alert, sound, banner, foreground }
let UNNotificationDefaultActionIdentifier = "default"

final class SettingsWindow {
    static let shared = SettingsWindow()
    private(set) var opened: [(String?, UInt32?)] = []

    func show(tab: String?, egressRule: UInt32? = nil) { opened.append((tab, egressRule)) }
}
typealias UNNotificationPresentationOptions = Set<NotificationOption>

struct UNNotificationAction {
    let identifier: String
    let title: String
    let options: [NotificationOption]
}

struct UNNotificationCategory {
    let identifier: String
    let actions: [UNNotificationAction]
    let intentIdentifiers: [String]
    let options: [NotificationOption]
}

final class UNMutableNotificationContent {
    var title = ""
    var body = ""
    var categoryIdentifier = ""
    var userInfo: [AnyHashable: Any] = [:]
}

struct UNTimeIntervalNotificationTrigger {
    let timeInterval: TimeInterval
    let repeats: Bool
}

struct UNNotificationRequest {
    let identifier: String
    let content: UNMutableNotificationContent
    let trigger: UNTimeIntervalNotificationTrigger
}

struct UNNotification { let request: UNNotificationRequest }

struct UNNotificationResponse {
    let actionIdentifier: String
    let notification: UNNotification
}

enum ProfileStore {
    static func loadAppSettings() -> AppSettings { AppSettings() }
    struct AppSettings { let notificationAggregation = true }
}

final class ApprovalPrompt {
    static let shared = ApprovalPrompt()
    let takesOverApprovalNotice = false
}

final class HelperClient {
    static let shared = HelperClient()
    enum State { case connected, reconnecting, awaitingApproval }
    private(set) var trusted: [(group: UInt32, started: Double)] = []
    private(set) var disconnects = 0

    func trustEgress(group: UInt32, started: Double) { trusted.append((group, started)) }
    func disconnect() { disconnects += 1 }
}

@main
struct EgressNotificationHarness {
    static let center = UNUserNotificationCenter.current()
    static let notifier = Notifier.shared

    static func check(_ condition: Bool, _ message: String) {
        guard condition else {
            fputs("FAIL \(message)\n", stderr)
            exit(1)
        }
        print("PASS \(message)")
    }

    static func observation(evidence: String = "direct", address: String = "2001:db8:9::7") -> EgressProtection.Observation {
        .init(host: "tested.example", method: "trace", country: "YY", ip: "198.51.100.7",
              error: nil, evidence: evidence, peerAddress: address)
    }

    static func group(_ level: String, reason: String? = nil,
                      observed: [EgressProtection.Observation] = [observation()]) -> EgressProtection.GroupState {
        .init(id: UInt32.max, name: "Fixture", state: level == "ok" ? "ok" : "blocked", lastCheck: 1235,
              observed: observed, reason: reason, level: level, blockedCount: 3,
              lastBlockedHost: "tested.example", lastBlockedCountry: "YY")
    }

    static func status(_ group: EgressProtection.GroupState, checking: [UInt32] = []) -> EgressProtection.Status {
        let record = EgressProtection.BlockRecord(started: 1234.125, ended: nil, group: group.id, name: group.name,
            host: "tested.example", observed: [observation()], expected: ["ZZ"])
        return .init(running: true, checking: checking, groups: [group], records: [record])
    }

    static func respond(_ identifier: String, to request: UNNotificationRequest) {
        let response = UNNotificationResponse(actionIdentifier: identifier, notification: .init(request: request))
        var completed = false
        notifier.userNotificationCenter(center, didReceive: response) { completed = true }
        check(completed, "\(identifier) completes the system callback")
        var drained = false
        DispatchQueue.main.async { drained = true }
        let deadline = Date(timeIntervalSinceNow: 2)
        while !drained && Date() < deadline {
            RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.01))
        }
        check(drained, "the action had a turn on the main queue")
    }

    static func main() {
        checkExitRanges()
        var ledger = EgressNoticeLedger()
        let partial = group("partial")
        let unknown = group("unknown")
        let red = group("blocked", reason: "no-direct-method")
        let ok = group("ok")
        let outgoing = ledger.update([partial])
        check(outgoing.count == 1 && ledger.update([partial]).isEmpty, "partial notification only fires once per rule/session")
        notifier.egressNotice(outgoing[0])
        check(center.requests.count == 1, "one notification was delivered to the stand-in")
        let banner = center.requests[0]
        let category = center.categories.first { $0.identifier == banner.content.categoryIdentifier }
        check(category?.actions.map(\.title) == ["查看"] && center.delegate === notifier, "banner only offers View")
        check(banner.content.title.contains("tested.example") && banner.content.body.contains("已拦下 3 次连接"),
              "banner describes actual gated connections")
        respond("trust-egress", to: banner)
        check(SettingsWindow.shared.opened.isEmpty, "an action from an older version cannot open or write a rule")
        respond(Notifier.reviewEgressAction, to: banner)
        check(SettingsWindow.shared.opened.count == 1 && SettingsWindow.shared.opened[0].0 == "split"
              && SettingsWindow.shared.opened[0].1 == partial.id, "View opens the specific protected rule")
        var presented: UNNotificationPresentationOptions = []
        notifier.userNotificationCenter(center, willPresent: .init(request: banner)) { presented = $0 }
        check(presented == [.banner, .sound], "foreground banner presentation still works")

        check(ledger.update([unknown]).isEmpty, "unknown status cannot announce recovery")
        let blocked = ledger.update([red])
        check(blocked.count == 1 && blocked[0].kind == .blocked && ledger.update([red]).isEmpty,
              "red escalation notifies only once")
        notifier.egressNotice(blocked[0])
        check(center.requests.last!.content.body.contains("无法核实网站本身的出口"), "red alert names the reason")
        check(ledger.update([unknown]).isEmpty, "red to unknown is not a recovery")
        let recovery = ledger.update([ok])
        check(recovery.count == 1 && recovery[0].kind == .recovered && ledger.update([ok]).isEmpty,
              "known recovery notifies only once")
        notifier.egressNotice(recovery[0])
        check(center.requests.last!.content.title == "网站已恢复", "recovery describes restored availability")
        var nextSession = EgressNoticeLedger()
        check(nextSession.update([partial]).count == 1, "a new logical session starts fresh")

        let unknownCheck = status(unknown, checking: [partial.id])
        check(unknownCheck.panelCaption(checkingFor: 0.99) == "尚未核实出口"
              && unknownCheck.panelCaption(checkingFor: 1.0) == "正在核对出口",
              "the panel suppresses short checks")
        check(status(ok).panelCaption(checkingFor: 2) == "正常" && status(partial).displayLevel == .partial
              && status(red).displayLevel == .blocked, "availability levels stay distinct")
        check(status(ok).panelCaption(checkingFor: 0, expectedRules: [ok.id, 10]) == "尚未核实出口",
              "a rule missing from a snapshot prevents a normal status")

        let local = EgressProtection(enabled: true, groups: [.init(id: partial.id, name: partial.name,
            enabled: true, members: [.init(pattern: "tested.example", method: "trace")], expect: ["ZZ"])])
        let known = status(partial)
        guard let approval = known.approvals(for: partial.id).first else { exit(1) }
        check(known.permits(approval, in: local) && approval.country == "YY", "matching current direct evidence can start confirmation")
        let unchanged = EgressProtection.Group(id: 8, name: "An independently edited rule")
        var latest = local
        latest.groups.append(unchanged)
        let saved = approval.applying(["ZZ", "YY"], then: local, now: latest, sameSession: true)
        check(saved?.groups[0].expect == ["ZZ", "YY"] && saved?.groups[1] == unchanged,
              "successful receipt changes only this rule's allowed country")
        var altered = local
        altered.groups[0].name = "Edited after the confirmation"
        check(approval.applying(nil, then: local, now: local, sameSession: true) == nil
              && approval.applying(["ZZ", "YY"], then: local, now: altered, sameSession: true) == nil
              && approval.applying(["ZZ", "YY"], then: local, now: local, sameSession: false) == nil,
              "failure, a competing edit and a new session all leave preferences unchanged")
        for changed in [group("partial", observed: [observation(address: "198.51.100.8")]),
                        group("partial", observed: [observation(evidence: "proxy")]),
                        group("partial", observed: [observation(evidence: "member")]),
                        group("partial", observed: [observation(evidence: "third-party")]),
                        group("partial", observed: [observation(evidence: "unknown")]), red, ok] {
            check(!status(changed).permits(approval, in: local) && status(changed).approvals(for: partial.id).isEmpty,
                  "stale, unconfirmed or whole-rule evidence cannot be approved")
        }
        let historical = try! JSONDecoder().decode(EgressProtection.Observation.self, from: Data(
            #"{"host":"old.example","method":"trace","country":"YY"}"#.utf8))
        check(historical.evidenceKind == .unknown && EgressProtection.directFailures([historical], expected: ["ZZ"]) == nil,
              "legacy observations decode without authorizing trust")
        notifier.notifyGatewayCertificateFailure()
        check(center.requests.last!.content.categoryIdentifier.isEmpty, "certificate rejection offers no policy action")
        checkUnknownWeb()
    }

    static func checkUnknownWeb() {
        let config = EgressProtection(enabled: true, groups: [.init(id: 1, name: "Fixture", enabled: true)])
        check(config.blocksUnidentifiedWeb, "active old config defaults to blocking unidentified web")
        var off = config
        off.blockUnidentifiedWeb = false
        check(!off.blocksUnidentifiedWeb && off.groups == config.groups,
              "closing the switch does not change protected rules")
        let data = Data(#"{"running":true,"checking":[],"groups":[],"records":[],"unknownWebCount":7,"unknownWeb":[{"address":"198.51.100.17","lastReason":"ech","port":443,"count":5,"allowed":false,"approvalId":"fixture-approval"},{"address":"2001:db8::8","port":8443,"count":2,"allowed":true,"approvalId":"fixture-withdraw"}]}"#.utf8)
        let decoder = JSONDecoder()
        var status = try! decoder.decode(EgressProtection.Status.self, from: data)
        let monitor = EgressProtection.Status.monitoring(data)!
        check(monitor.unknownWebCount == 7 && monitor.unknownWeb == nil,
              "the panel reads real counts without retaining addresses or approval IDs")
        if let rows = try? JSONDecoder().decode(EgressProtection.Status.self, from: data).unknownWeb {
            check(rows[0].identityExplanation?.contains("加密掩护名") == true && rows[1].identityExplanation == nil,
                  "only the latest observed ECH extension explains an unidentified connection")
        } else { check(false, "unknown web rows decode") }
        let beforeCount = Data(#"{"running":true,"checking":[],"groups":[],"records":[],"unknownWeb":[{"count":5}]}"#.utf8)
        check(EgressProtection.Status.monitoring(beforeCount)?.unknownWebCount == nil,
              "an older backend's missing scalar is unknown, with no fallback scan")
        let approve = status.unknownWeb![0].change!
        let withdraw = status.unknownWeb![1].change!
        check(approve.endpoint.label == "198.51.100.17:443" && withdraw.endpoint.label == "[2001:db8::8]:8443",
              "both address formats keep the single port explicit")
        check(status.permits(approve, config: config) && !status.permits(approve, config: off)
              && status.permits(withdraw, config: off) && !status.applied(approve),
              "only the current blocked row can allow, and existing exceptions remain revocable")
        let incorrect = EgressUnknownWebChange(endpoint: .init(address: approve.endpoint.address, port: 80),
                                               allow: true, approvalId: approve.approvalId)
        let stale = EgressUnknownWebChange(endpoint: approve.endpoint, allow: true, approvalId: "earlier-session")
        check(!status.permits(incorrect, config: config) && !status.permits(stale, config: config)
              && !status.permits(approve, config: .init()),
              "a different port, session token or inactive policy cannot approve")
        let oldRow = EgressProtection.UnknownWebRecord(address: "198.51.100.17", port: 443, count: 5,
                                                        allowed: false, approvalId: nil)
        let network = EgressProtection.UnknownWebRecord(address: "198.51.100.0/24", port: 443, count: 5,
                                                         allowed: false, approvalId: "fixture")
        check(oldRow.change == nil && network.change == nil, "old records and whole subnets offer no approval")
        status.unknownWeb = []
        check(!status.permits(approve, config: config) && !status.applied(withdraw), "an empty or vanished record cannot act as a receipt")
        status.unknownWeb = [
            .init(address: approve.endpoint.address, port: approve.endpoint.port, count: 5, allowed: true,
                  approvalId: "fixture-new"),
            .init(address: withdraw.endpoint.address, port: withdraw.endpoint.port, count: 2, allowed: false,
                  approvalId: "fixture-new-withdraw"),
        ]
        check(status.applied(approve) && status.applied(withdraw) && !status.permits(approve, config: config),
              "backend readback must show the actual allow or revoke state")
        let expired = EgressProtection.Status(running: false, checking: [], groups: [], records: [], unknownWeb: status.unknownWeb)
        check(!expired.applied(approve) && !expired.permits(withdraw, config: config),
              "session end invalidates the event and receipt")

        notifier.unknownEgressNotice(count: monitor.unknownWebCount!)
        let alert = center.requests.last!
        let category = center.categories.first { $0.identifier == alert.content.categoryIdentifier }
        check(category?.actions.map(\.title) == ["查看"] && alert.content.userInfo.isEmpty
              && !alert.content.body.contains(approve.endpoint.address),
              "unknown-web notification has a review action and no endpoint or token")
        respond(Notifier.reviewEgressAction, to: alert)
        check(SettingsWindow.shared.opened.last?.0 == "unknown-egress", "notification opens the current blocked connections list")
    }

    static func checkExitRanges() {
        let decoder = JSONDecoder()
        let old = Data(#"{"enabled":true,"groups":[{"id":7,"name":"Fixture","enabled":true,"members":[{"pattern":"site.example","method":"trace"}],"cidrs":["203.0.113.0/24"],"expect":["ZZ"]}],"methods":[]}"#.utf8)
        let model = try! decoder.decode(EgressProtection.self, from: old)
        let rule = model.groups[0]
        check(!rule.exitRangeCheck && rule.exitRanges.isEmpty, "legacy rules do not enable prefix checks")
        let summary = Data(#"{"host":"site.example","method":"trace","status":"ok","resolvedAddressCount":3,"probedAddressCount":3,"truncated":false,"coverageIncomplete":false,"proofId":"fixture-proof","results":[{"address":"203.0.113.1","method":"trace","status":"ok","country":"ZZ","exitIP":"198.51.100.17"},{"address":"203.0.113.2","method":"trace","status":"ok","country":"YY","exitIP":"192.0.2.8"},{"address":"203.0.113.3","method":"trace","status":"ok","country":"ZZ"}]}"#.utf8)
        let probe = try! decoder.decode(EgressProtection.SetupProbe.self, from: summary)
        let offers = EgressExitRangeOffer.from([probe.host: probe], countries: rule.expect, config: model)
        guard let offer = offers.first, let ip = offer.suggestions.addresses.first else { exit(1) }
        check(offer.suggestions.addresses.count == 1 && ip.single == "198.51.100.17/32" && ip.subnet == "198.51.100.0/24",
              "suggestions use only real exitIP from an allowed country, never the destination field")
        var unattested = probe
        unattested.proofId = nil
        var reference = model
        reference.methods = [.init(id: "trace", name: "Reference", url: "https://query.example/",
                                   extract: .init(kind: .kv, key: "loc"))]
        check(EgressExitRangeOffer.from([probe.host: unattested], countries: rule.expect, config: model).isEmpty
              && EgressExitRangeOffer.from([probe.host: probe], countries: rule.expect, config: reference).isEmpty,
              "old and third-party responses cannot start exit range approval")
        let ipv6 = EgressExitAddress("2001:db8:7::8")!
        check(ipv6.single == "2001:db8:7::8/128" && ipv6.subnet == "2001:db8:7::/64"
              && EgressExitRangeSuggestions(addresses: [ipv6]).recommended == [ipv6.single],
              "IPv6 defaults to exact /128, with explicit /64 available")
        let choice = EgressExitRangeSelection(proof: offer.proof, ranges: [ip.single])
        let wider = EgressExitRangeSelection(proof: offer.proof, ranges: ["198.51.0.0/16"])
        check(!wider.verified(in: offers) && !choice.verified(in: []), "missing or wider choices cannot be confirmed")
        guard let setup = EgressExitRangeSetup(proposed: model, previous: model, group: rule.id,
                                              selection: choice, offers: offers) else { exit(1) }
        check(!model.groups[0].exitRangeCheck && setup.proposed.groups[0].exitRanges == [ip.single]
              && setup.proposed.groups[0].cidrs == rule.cidrs && setup.proposed.groups[0].expect == rule.expect,
              "a draft changes neither the old preferences nor destination ranges or countries")
        var changed = model
        changed.groups[0].name = "Concurrent edit"
        check(setup.applying(accepted: nil, now: model, sameSession: true) == nil
              && setup.applying(accepted: false, now: model, sameSession: true) == nil
              && setup.applying(accepted: true, now: setup.proposed, sameSession: true) == nil
              && setup.applying(accepted: true, now: model, sameSession: false) == nil
              && setup.applying(accepted: true, now: changed, sameSession: true) == nil,
              "timeout, expired or used proof, changed session and competing edits preserve preferences")
        guard let enabled = setup.applying(accepted: true, now: model, sameSession: true) else { exit(1) }
        let current = enabled.groups[0]
        let miss = EgressProtection.Observation(host: "site.example", method: "trace", country: "ZZ",
            ip: "192.0.2.70", error: nil, evidence: "direct", peerAddress: "203.0.113.1",
            failureReason: "exit-range-mismatch", approvalId: "fixture-approval")
        let record = EgressProtection.BlockRecord(started: 5, ended: nil, group: rule.id, name: rule.name,
                                                 host: "older.example", observed: [], expected: ["YY"])
        func snapshot(_ observation: EgressProtection.Observation, reason: String? = nil) -> EgressProtection.Status {
            .init(running: true, checking: [], groups: [.init(id: rule.id, name: "Fixture", state: "blocked", lastCheck: 6,
                  observed: [observation], reason: reason, level: "partial", blockedCount: 1)], records: [record])
        }
        let status = snapshot(miss)
        guard let incident = status.exitChanges(for: current).first else { exit(1) }
        let approval = incident.approval(for: incident.exit.subnet)
        let roundTrip = try! decoder.decode(EgressExitRangeApproval.self, from: JSONEncoder().encode(approval))
        check(status.permits(approval, in: enabled)
              && roundTrip.observation.approvalId == "fixture-approval"
              && !status.permits(incident.approval(for: "192.0.0.0/8"), in: enabled)
              && status.approvals(for: rule.id).isEmpty
              && status.panelCaption(checkingFor: 0).contains("出口地址不在允许范围"),
              "current range evidence retains its approval ID and is independent of the first record and country approval")
        var borrowed = miss
        borrowed.evidence = "proxy"
        var stale = miss
        stale.peerAddress = "203.0.113.2"
        var unavailable = miss
        unavailable.failureReason = "exit-ip-unavailable"
        var changedApprovalID = miss
        changedApprovalID.approvalId = "changed-approval"
        var withoutApprovalID = miss
        withoutApprovalID.approvalId = nil
        check(!snapshot(borrowed).permits(approval, in: enabled)
              && !snapshot(stale).permits(approval, in: enabled)
              && !snapshot(changedApprovalID).permits(approval, in: enabled)
              && snapshot(withoutApprovalID).exitChanges(for: current).isEmpty
              && !snapshot(miss, reason: "failed-target-overflow").permits(approval, in: enabled)
              && snapshot(unavailable).exitChanges(for: current).isEmpty
              && snapshot(unavailable).panelCaption(checkingFor: 0).contains("查不到出口地址"),
              "borrowed, changed, locked and missing-IP evidence cannot authorize a range")
        let accepted = [ip.single, incident.exit.subnet]
        check(approval.applying(accepted, then: enabled, now: enabled, sameSession: true)?.groups[0].exitRanges == accepted
              && approval.applying([], then: enabled, now: enabled, sameSession: true) == nil
              && approval.applying(accepted, then: enabled, now: model, sameSession: true) == nil,
              "only the exact successful receipt updates the rule's exit ranges")
    }
}
