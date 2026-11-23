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

enum NotificationOption { case alert, sound, banner }
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
    static let actions = HelperClient.shared

    static func check(_ condition: Bool, _ message: String) {
        guard condition else {
            fputs("FAIL \(message)\n", stderr)
            exit(1)
        }
        print("PASS \(message)")
    }

    static func record(country: String?, evidence: String? = "direct", peer: String? = "2001:db8:9::7") -> EgressProtection.BlockRecord {
        .init(started: 1234.125, ended: nil, group: UInt32.max, name: "Fixture",
              host: "follows.example", observed: [
                .init(host: "healthy.example", method: "trace", country: "ZZ", ip: nil, error: nil, evidence: "member"),
                .init(host: "tested.example", method: "trace", country: country,
                      ip: country == nil ? nil : "198.51.100.7", error: country == nil ? "timeout" : nil,
                      evidence: evidence, peerAddress: peer),
              ], expected: ["ZZ"])
    }

    static func current(_ record: EgressProtection.BlockRecord, reason: String? = nil,
                        observed: [EgressProtection.Observation]? = nil) -> EgressProtection.GroupState {
        .init(id: record.group, name: record.name, state: "blocked", lastCheck: 1235,
              observed: observed ?? record.observed, reason: reason)
    }

    static func respond(_ identifier: String, to request: UNNotificationRequest) {
        let response = UNNotificationResponse(actionIdentifier: identifier, notification: .init(request: request))
        var completed = false
        notifier.userNotificationCenter(center, didReceive: response) { completed = true }
        check(completed, "\(identifier) completes the system callback")
        // Do not infer a no-op just because the action is queued on main.
        var drained = false
        DispatchQueue.main.async { drained = true }
        let deadline = Date(timeIntervalSinceNow: 2)
        while !drained && Date() < deadline {
            RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.01))
        }
        check(drained, "the action was given time to run on the main queue")
    }

    static func main() {
        let mismatch = record(country: "YY")
        notifier.egressBlocked(mismatch, current: current(mismatch))
        check(center.requests.count == 1, "mismatch submits one notification")
        let blocked = center.requests[0]
        let category = center.categories.first { $0.identifier == blocked.content.categoryIdentifier }
        check(center.delegate === notifier, "Notifier registers as the system delegate")
        check(category?.actions.map(\.title) == ["信任新出口", "继续拦截"], "mismatch offers both actions")
        guard let trust = category?.actions.first?.identifier, let keep = category?.actions.last?.identifier else {
            exit(1)
        }
        check(blocked.content.title.contains(mismatch.name)
              && blocked.content.body.contains("tested.example（目的地址 2001:db8:9::7）：YY（出口 IP 198.51.100.7）")
              && blocked.content.body.contains("直接观测")
              && blocked.content.body.contains("部分地址出口未通过")
              && blocked.content.body.contains("其他可直接检查的地址仍逐条验证")
              && blocked.content.body.contains("跟随本组和仅有代理观测的连接会等异常地址恢复")
              && blocked.content.body.contains("预期出口：ZZ")
              && !blocked.content.body.contains("healthy.example"), "notification identifies the mismatch")
        var foreground: UNNotificationPresentationOptions = []
        notifier.userNotificationCenter(center, willPresent: .init(request: blocked)) { foreground = $0 }
        check(foreground == [.banner, .sound], "foreground presentation requests a banner and sound")

        respond(keep, to: blocked)
        check(actions.trusted.isEmpty && actions.disconnects == 0, "keep blocking changes neither policy nor VPN state")
        respond(trust, to: blocked)
        check(actions.trusted.count == 1 && actions.trusted[0].group == mismatch.group
              && actions.trusted[0].started == mismatch.started, "trust forwards the exact group and block time")

        let missed = record(country: nil)
        notifier.egressBlocked(missed, current: current(missed))
        check(center.requests.count == 2, "unavailable probe submits one notification")
        let unavailable = center.requests[1]
        check(unavailable.content.categoryIdentifier.isEmpty
              && unavailable.content.body.contains("未查到"), "unknown country is shown without a trust action")

        notifier.egressRecovered(mismatch.name)
        check(center.requests.count == 3, "recovery submits one notification")
        let recovered = center.requests[2]
        check(recovered.content.title == "出口已恢复" && recovered.content.body == mismatch.name
              && recovered.content.categoryIdentifier.isEmpty
              && recovered.content.userInfo.isEmpty, "recovery identifies the group and carries no trust payload")
        respond(trust, to: recovered)
        check(actions.trusted.count == 1 && actions.disconnects == 0, "missing action metadata cannot change the policy")
        notifier.notifyGatewayCertificateFailure()
        let certificate = center.requests.last!.content
        check(certificate.title == "VPN 网关证书校验失败" && certificate.body.contains("网络拦截状态")
              && certificate.userInfo.isEmpty && certificate.categoryIdentifier.isEmpty, "certificate notice names the cause and offers no trust override")

        for (evidence, caption) in [("proxy", "按借用身份查到（代理观测）"),
                                     ("third-party", EgressProtection.Method.thirdPartyCaption),
                                     ("member", "按网站名查询"), ("other", "来源未记录")] {
            let reference = record(country: "YY", evidence: evidence)
            notifier.egressBlocked(reference, current: current(reference))
            let content = center.requests.last!.content
            check(content.body.contains(caption) && content.categoryIdentifier.isEmpty && content.userInfo.isEmpty,
                  "\(evidence) evidence has a label and no trust action")
        }
        for reason in [EgressProtection.BlockReason.noDirectMethod, .failedTargetOverflow] {
            notifier.egressBlocked(mismatch, current: current(mismatch, reason: reason.rawValue))
            let content = center.requests.last!.content
            check(content.body.contains(reason.caption) && content.body.contains("编辑检测方式或停用这组")
                  && content.categoryIdentifier.isEmpty && content.userInfo.isEmpty,
                  "\(reason.rawValue) explains the hold and offers no trust action")
        }
        let stale = record(country: "YY", peer: "198.51.100.8")
        let unspecified = record(country: "YY", peer: nil)
        let wrongType = record(country: "YY", evidence: "proxy")
        for candidate in [stale, unspecified, wrongType] {
            check(mismatch.directTargetsToTrust(current: current(candidate)) == nil,
                  "a change in peer address or evidence invalidates the action")
        }
        let reference = record(country: "AA", evidence: "third-party").observed[1]
        check(mismatch.directTargetsToTrust(current: current(mismatch, observed: mismatch.observed + [reference]))?.map(\.country) == ["YY"],
              "third-party reference never contributes a country to trust")
        let historical = try! JSONDecoder().decode(EgressProtection.Observation.self, from: Data(
            #"{"host":"old.example","method":"trace","country":"YY"}"#.utf8))
        check(historical.evidenceKind == .unknown
              && EgressProtection.directFailures([historical], expected: ["ZZ"]) == nil,
              "legacy records decode as unknown and cannot authorize trust")
        let oldContent = UNMutableNotificationContent()
        oldContent.categoryIdentifier = "egress-blocked"
        oldContent.userInfo = ["group": mismatch.group, "started": mismatch.started]
        let fromOldBuild = UNNotificationRequest(identifier: "legacy", content: oldContent, trigger: blocked.trigger)
        respond(trust, to: fromOldBuild)
        check(actions.trusted.count == 1, "an already delivered notification from a previous build cannot proxy trust")

        checkGroupActivation()
    }

    static func checkGroupActivation() {
        let urls = ["https://{host}/trace", "https://{host}:8443/trace", "https://{host}",
                    "https://{host}.query.example/", "https://query.example/{host}", "https://{host}:0/x"]
        let methods = urls.enumerated().map { index, url in
            EgressProtection.Method(id: "fixture-\(index)", name: "Fixture", url: url,
                                    extract: .init(kind: .kv, key: "loc"))
        }
        check(methods.map(\.isDirect) == [true, true, true, false, false, false], "direct methods require exactly the host placeholder")
        let direct = methods[1]
        let thirdParty = methods[3]
        let observation: (EgressProtection.Method) -> EgressProtection.Observation = { method in
            .init(host: "one.example", method: method.id, country: "ZZ", ip: nil, error: nil)
        }
        check(EgressProtection.Method.preferredDirectMethod([thirdParty, direct], observations: [observation(thirdParty)]) == nil
              && EgressProtection.Method.preferredDirectMethod([thirdParty, direct],
                  observations: [observation(thirdParty), observation(direct)]) == direct.id,
              "third-party results never select the initial method")

        let legacyBytes = Data(#"{"enabled":true,"groups":[{"id":1,"name":"Older","enabled":true,"members":[{"pattern":"one.example","method":"remote"}],"cidrs":[],"expect":["ZZ"]}],"methods":[{"id":"remote","name":"Remote","url":"https://query.example/","head":false,"extract":{"kind":"kv","key":"loc"}}]}"#.utf8)
        let legacy = try! JSONDecoder().decode(EgressProtection.self, from: legacyBytes)
        check(legacy.isActive && legacy.directMembers(in: legacy.groups[0]).isEmpty
              && legacy.permitsActivation(comparedTo: legacy), "an enabled legacy group stays armed")
        var off = legacy
        off.enabled = false
        check(off.permitsActivation(comparedTo: EgressProtection())
              && !legacy.permitsActivation(comparedTo: off),
              "an inert import is accepted, and a third-party-only group cannot enable the feature")
        var groupOff = legacy
        check(groupOff.disableGroup(1) && !groupOff.isActive && groupOff.groups[0].members == legacy.groups[0].members
              && !legacy.permitsActivation(comparedTo: groupOff), "explicit stop preserves configuration and cannot silently re-enable")
        var fixed = legacy
        fixed.methods.append(direct)
        fixed.groups[0].members[0].method = direct.id
        check(fixed.permitsActivation(comparedTo: groupOff), "a direct method permits activation")
    }
}
