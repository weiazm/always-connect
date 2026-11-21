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

    static func record(country: String?) -> EgressProtection.BlockRecord {
        .init(started: 1234.125, ended: nil, group: UInt32.max, name: "Fixture",
              host: "follows.example", observed: [
                .init(host: "healthy.example", method: "trace", country: "ZZ", ip: nil, error: nil),
                .init(host: "tested.example", method: "trace", country: country,
                      ip: country == nil ? nil : "198.51.100.7", error: country == nil ? "timeout" : nil),
              ], expected: ["ZZ"])
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
        notifier.egressBlocked(mismatch)
        check(center.requests.count == 1, "mismatch submits one notification")
        let blocked = center.requests[0]
        let category = center.categories.first { $0.identifier == blocked.content.categoryIdentifier }
        check(center.delegate === notifier, "Notifier registers as the system delegate")
        check(category?.actions.map(\.title) == ["信任新出口", "继续拦截"], "mismatch offers both actions")
        guard let trust = category?.actions.first?.identifier, let keep = category?.actions.last?.identifier else {
            exit(1)
        }
        check(blocked.content.title.contains(mismatch.name)
              && blocked.content.body.contains("tested.example：YY（198.51.100.7）")
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

        notifier.egressBlocked(record(country: nil))
        check(center.requests.count == 2, "unavailable probe submits one notification")
        let unavailable = center.requests[1]
        check(unavailable.content.categoryIdentifier.isEmpty
              && unavailable.content.body.contains("tested.example：未查到"), "unknown country is shown without a trust action")

        notifier.egressRecovered(mismatch.name)
        check(center.requests.count == 3, "recovery submits one notification")
        let recovered = center.requests[2]
        check(recovered.content.title == "出口已恢复" && recovered.content.body == mismatch.name
              && recovered.content.categoryIdentifier.isEmpty
              && recovered.content.userInfo.isEmpty, "recovery identifies the group and carries no trust payload")
        respond(trust, to: recovered)
        check(actions.trusted.count == 1 && actions.disconnects == 0, "missing action metadata cannot change the policy")
    }
}
