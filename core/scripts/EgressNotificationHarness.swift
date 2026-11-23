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

    func show(tab: String?, egressRule: UInt32?) { opened.append((tab, egressRule)) }
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
    }
}
