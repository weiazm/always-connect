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

    static func prepared(_ target: GatewayAddress, anchor: SecCertificate?, expected: String?, label: String) {
        let preparation = LoginGatewayPreparation()
        let finished = DispatchSemaphore(value: 0)
        preparation.onTestFinish = { finished.signal() }
        preparation.testAnchor = anchor
        preparation.confirmDirect()
        preparation.prepareWhileDirect(target)
        check(finished.wait(timeout: .now() + 3) == .success, "\(label) finishes")
        check(preparation.takeForIntent(target) == expected, label)
        check(preparation.takeForIntent(target) == nil, "\(label) cannot be reused")
    }

    static func main() throws {
        let args = CommandLine.arguments
        let anchorData = try Data(contentsOf: URL(fileURLWithPath: args[1]))
        let anchor = SecCertificateCreateWithData(nil, anchorData as CFData)!
        let gateway = GatewayAddress("https://localhost:\(args[2])/profile")!
        let wrongName = GatewayAddress("https://127.0.0.1:\(args[2])")!
        let stalled = GatewayAddress("https://127.0.0.1:\(args[3])")!
        let mutualTLS = GatewayAddress("https://localhost:\(args[4])")!
        let support = URL(fileURLWithPath: args[5])

        prepared(gateway, anchor: anchor, expected: "127.0.0.1", label: "trusted hostname gives the numeric TLS peer")
        prepared(wrongName, anchor: anchor, expected: nil, label: "trusted issuer with wrong hostname gives no candidate")
        prepared(gateway, anchor: nil, expected: nil, label: "untrusted issuer gives no candidate")
        prepared(mutualTLS, anchor: anchor, expected: nil, label: "gateway requiring a client certificate gives no candidate without credentials")
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
        check(preparation.takeForIntent(stalled) == nil, "connection intent consumes no pending result")
        check(DispatchTime.now().uptimeNanoseconds - began.uptimeNanoseconds < 250_000_000, "connection intent does not wait for TLS")
        preparation.prepareWhileDirect(gateway)
        check(finished.wait(timeout: .now() + .milliseconds(2200)) == .timedOut, "cancelled transport cannot finish or start another preparation")

        preparation.confirmDirect()
        preparation.prepareWhileDirect(stalled)
        check(finished.wait(timeout: .now() + .milliseconds(2400)) == .success, "a silent server reaches the two-second deadline")
        check(preparation.takeForIntent(stalled) == nil, "timeout cannot supply an address")
    }
}
