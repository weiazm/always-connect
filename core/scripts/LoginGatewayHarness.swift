import Foundation
import Security

@main
enum LoginGatewayHarness {
    static func check(_ condition: @autoclosure () -> Bool, _ label: String) {
        guard condition() else {
            FileHandle.standardError.write(Data("FAIL \(label)\n".utf8))
            exit(1)
        }
        print("PASS \(label)")
    }

    static func waitFor(_ condition: () -> Bool) -> Bool {
        let deadline = DispatchTime.now() + .seconds(2)
        while !condition() && DispatchTime.now() < deadline {
            RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.01))
        }
        return condition()
    }

    static func prepared(_ target: GatewayAddress, anchor: SecCertificate?, expected: (String?, Bool),
                         intent: GatewayAddress? = nil, ipv4Only: Bool = false, label: String) {
        let preparation = LoginGatewayPreparation()
        let finished = DispatchSemaphore(value: 0)
        preparation.onTestFinish = { finished.signal() }
        preparation.testAnchor = anchor
        preparation.confirmDirect()
        check(preparation.prepareWhileDirect(target, ipv4Only: ipv4Only) == .preparing, "\(label) starts preparing")
        check(finished.wait(timeout: .now() + 3) == .success, "\(label) finishes")
        let status: LoginGatewayPreparation.Status = expected.0 != nil ? .ready
            : expected.1 || intent != nil ? .certificateRejected : .unavailable
        check(preparation.status(for: target) == status, "\(label) reports the right preparation state")
        check(preparation.takeResultForIntent(intent ?? target) == expected, label)
        check(preparation.takeResultForIntent(target) == (nil, false), "\(label) cannot be reused")
    }

    static func main() throws {
        let args = CommandLine.arguments
        let anchorData = try Data(contentsOf: URL(fileURLWithPath: args[1]))
        let anchor = SecCertificateCreateWithData(nil, anchorData as CFData)!
        let gateway = GatewayAddress("https://localhost:\(args[2])/profile")!
        let wrongName = GatewayAddress("https://127.0.0.1:\(args[2])")!
        let stalled = GatewayAddress("https://127.0.0.1:\(args[3])")!
        let mutualTLS = GatewayAddress("https://localhost:\(args[4])")!
        let delayed = GatewayAddress("https://localhost:\(args[5])")!
        let support = URL(fileURLWithPath: args[6])

        prepared(gateway, anchor: anchor, expected: ("127.0.0.1", false), ipv4Only: true,
                 label: "trusted hostname gives the numeric IPv4 TLS peer")
        prepared(wrongName, anchor: anchor, expected: (nil, true), label: "wrong hostname reports trust rejection without an address")
        prepared(gateway, anchor: nil, expected: (nil, true), label: "untrusted issuer reports trust rejection without an address")
        prepared(wrongName, anchor: anchor, expected: (nil, false), intent: gateway,
                 label: "a rejection is unavailable to a different hostname")
        prepared(wrongName, anchor: anchor, expected: (nil, false), intent: stalled,
                 label: "a rejection is unavailable to a different port")
        prepared(mutualTLS, anchor: anchor, expected: (nil, false),
                 label: "failure to present a client certificate is not a server trust rejection")
        prepared(delayed, anchor: nil, expected: (nil, false),
                 label: "a server responding with TLS after the deadline does not report rejection")
        check(LoginGatewayCache.lookup(in: support, target: gateway).isEmpty, "preparation has no persistent side effect")
        check(LoginGatewayCache.rememberConnected(in: support, target: gateway, peer: "192.0.2.8"), "service records a synthetic connected peer")
        check(LoginGatewayCache.lookup(in: support, target: gateway) == ["192.0.2.8"], "service reads back only the synthetic connected peer")

        let preparation = LoginGatewayPreparation()
        preparation.prepareWhileDirect(gateway)
        check(preparation.takeForIntent(gateway) == nil, "preparation starts disabled")
        preparation.confirmDirect()
        let finished = DispatchSemaphore(value: 0)
        preparation.onTestFinish = { finished.signal() }
        preparation.prepareWhileDirect(stalled)
        let began = DispatchTime.now()
        check(preparation.takeResultForIntent(stalled) == (nil, false), "connection intent consumes no pending result")
        check(DispatchTime.now().uptimeNanoseconds - began.uptimeNanoseconds < 250_000_000, "connection intent does not wait for TLS")
        preparation.prepareWhileDirect(gateway)
        check(finished.wait(timeout: .now() + .milliseconds(2200)) == .timedOut, "cancelled transport cannot finish or start another preparation")

        preparation.confirmDirect()
        preparation.prepareWhileDirect(stalled)
        check(finished.wait(timeout: .now() + .milliseconds(2400)) == .success, "a silent server reaches the two-second deadline")
        check(preparation.takeResultForIntent(stalled) == (nil, false), "timeout supplies neither an address nor a rejection")

        preparation.testAnchor = anchor
        preparation.confirmDirect()
        preparation.prepareWhileDirect(wrongName)
        check(finished.wait(timeout: .now() + 3) == .success, "rejection is ready before cancellation")
        preparation.cancel()
        check(preparation.takeResultForIntent(wrongName) == (nil, false), "cancellation discards a ready rejection")

        preparation.confirmDirect()
        preparation.prepareWhileDirect(gateway)
        check(finished.wait(timeout: .now() + 3) == .success, "trusted TLS is ready after cancellation")
        check(preparation.takeForIntent(gateway) == "127.0.0.1", "address-only callers still receive the candidate")

        let joining = LoginGatewayPreparation()
        var starts = 0
        var passiveReplies = 0
        var joinedReplies = 0
        joining.onTestStart = { starts += 1 }
        joining.confirmDirect()
        joining.prepareWhileDirect(stalled) { passiveReplies += 1 }
        let joinTime = DispatchTime.now()
        let joined = joining.prepareWhileDirect(stalled, ipv4Only: false,
                                                deadline: joinTime + .milliseconds(200)) { joinedReplies += 1 }
        check(joined == .preparing && starts == 1, "joining a live lookup reuses the same TLS transport")
        check(waitFor { joinedReplies == 1 }, "only the new observer receives completion")
        check(DispatchTime.now().uptimeNanoseconds - joinTime.uptimeNanoseconds < 1_200_000_000,
              "joining a lookup can shorten its deadline")
        check(passiveReplies == 0 && joining.status(for: stalled) == .unavailable,
              "timeout retires the transport without an address or a passive callback")
        check(joining.takeResultForIntent(stalled) == (nil, false), "expired transport cannot supply a late result")

        joining.confirmDirect()
        joining.testAnchor = anchor
        joining.prepareWhileDirect(stalled) { passiveReplies += 1 }
        joining.prepareWhileDirect(gateway) { joinedReplies += 1 }
        check(waitFor { joinedReplies == 2 }, "replacement target completes its own preparation")
        check(passiveReplies == 0 && starts == 3 && joining.takeForIntent(gateway) == "127.0.0.1",
              "moving to a different target retires the old callback and returns its own address")
    }
}
