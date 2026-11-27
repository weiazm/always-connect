import Foundation
import Security

/// End-to-end Swift+Rust cross-language harness (§71):
/// Swift `EgressProbe.exchange` (NWConnection on lo0 + SecTrust)
/// -> Rust `OneShotBridge` (127.0.0.1 + libproc PID ownership check)
/// -> Rust `split_proxy::open_for_probe` (SOCKS5)
/// -> local SOCKS5 proxy -> local TLS `/cdn-cgi/trace` server.
@main struct EgressProxyBridgeHarness {
    static func take(_ ptr: UnsafeMutablePointer<CChar>?) -> String? {
        guard let ptr else { return nil }
        defer { ac_string_free(ptr) }
        return String(cString: ptr)
    }

    static func check(_ cond: Bool, _ msg: String) {
        if !cond {
            fputs("FAIL \(msg)\n", stderr)
            exit(1)
        }
        print("PASS \(msg)")
    }

    static func main() throws {
        let caPath = CommandLine.arguments[1]
        let socksPort = Int(CommandLine.arguments[2])!
        let modeFile = CommandLine.arguments[3]
        let supportDir = CommandLine.arguments[4]
        let host = "protected.example.invalid"

        let caData = try Data(contentsOf: URL(fileURLWithPath: caPath))
        EgressProbe.testAnchor = SecCertificateCreateWithData(nil, caData as CFData)

        // Wire the real production EgressProbe.exchange callback into Rust ProxyOnly.
        ac_proxy_only_set_egress_probe_with_peer(nil) { _, json, length, peer, capacity in
            EgressProbe.exchange(json, length: length, peerBuffer: peer, capacity: capacity)
        }

        let rules = "proxy:0 socks5 127.0.0.1 \(socksPort)\nvia:0:domain:\(host)\n"
        let network = "{\"interface\":\"lo0\",\"dns\":[\"127.0.0.1\"]}"
        let egressJSON = """
        {"enabled":true,"prefetch":0,"groups":[{"id":1,"name":"BridgeRule","enabled":true,"sites":["\(host)"],"expect":["ZZ"],"unverified":"block"}]}
        """

        var errPtr: UnsafeMutablePointer<CChar>?
        guard let handle = ac_proxy_only_start_with_egress(
            rules, network, egressJSON, supportDir, "bridge-test", true, &errPtr
        ) else {
            let reason = take(errPtr) ?? "unknown"
            fputs("FAIL start proxy-only: \(reason)\n", stderr)
            exit(1)
        }
        defer { ac_proxy_only_stop_handover(handle, false) }

        // 1. Server returns loc=ZZ -> Allow through real NWConnection + OneShotBridge + libproc + SOCKS5 + TLS.
        try "ZZ".write(toFile: modeFile, atomically: true, encoding: .utf8)
        let v1 = ac_proxy_only_check_egress_target(handle, 0, host)
        check(v1 == 1, "Swift EgressProbe -> Rust OneShotBridge (libproc PID check) -> SOCKS5 -> TLS allows ZZ")
        let s1 = take(ac_proxy_only_egress_status(handle)) ?? "{}"
        check(s1.contains("\"state\":\"ok\"") && s1.contains("\"path\":\"proxy:0\"") && s1.contains("\"country\":\"ZZ\""),
              "egress status records ok on proxy:0 with country ZZ")

        // Second check hits half_life cache without probing again (server request count checked by caller).
        let v1Cached = ac_proxy_only_check_egress_target(handle, 0, host)
        check(v1Cached == 1, "cached proxy:0 allow verdict reused without re-probing")

        // 2. Server switches to loc=YY; invalidate cache via rule update -> Block.
        try "YY".write(toFile: modeFile, atomically: true, encoding: .utf8)
        ac_proxy_only_update_rules(handle, rules)
        let v2 = ac_proxy_only_check_egress_target(handle, 0, host)
        check(v2 == 0, "wrong country YY is blocked via real bridge probe")
        let s2 = take(ac_proxy_only_egress_status(handle)) ?? "{}"
        check(s2.contains("\"state\":\"blocked\"") && s2.contains("\"path\":\"proxy:0\"") && s2.contains("\"country\":\"YY\""),
              "egress status records blocked on proxy:0 with country YY")

        // 3. Server recovers to loc=ZZ -> recheckEgressFailures re-probes through OneShotBridge and recovers!
        try "ZZ".write(toFile: modeFile, atomically: true, encoding: .utf8)
        let rechecked = ac_proxy_only_recheck_egress(handle, 1)
        check(rechecked, "recheckEgressFailures completes over real bridge")
        let s3 = take(ac_proxy_only_egress_status(handle)) ?? "{}"
        check(s3.contains("\"state\":\"ok\""), "status recovers to ok after recheck")
        check(ac_proxy_only_check_egress_target(handle, 0, host) == 1, "connection allowed after recheck recovery")

        // 4. Server returns loc=YY again -> Block -> approve YY on proxy:0 (without peerAddress) -> Allow!
        try "YY".write(toFile: modeFile, atomically: true, encoding: .utf8)
        ac_proxy_only_update_rules(handle, rules)
        check(ac_proxy_only_check_egress_target(handle, 0, host) == 0, "wrong country YY blocks again")
        let s4 = take(ac_proxy_only_egress_status(handle)) ?? "{}"
        let statusObj = try JSONSerialization.jsonObject(with: Data(s4.utf8)) as! [String: Any]
        let records = statusObj["records"] as! [[String: Any]]
        let openRecord = records.first { $0["ended"] == nil || $0["ended"] is NSNull }!
        let started = (openRecord["started"] as! NSNumber).doubleValue
        let obsArray = openRecord["observed"] as! [[String: Any]]
        let evidenceData = try JSONSerialization.data(withJSONObject: obsArray[0])
        let evidenceStr = String(decoding: evidenceData, as: UTF8.self)
        check(obsArray[0]["peerAddress"] == nil && (obsArray[0]["path"] as? String) == "proxy:0",
              "proxy:0 observation has path=proxy:0 and no peerAddress")
        let approved = take(ac_proxy_only_allow_egress_country(handle, egressJSON, 1, started, "YY", evidenceStr))
        check(approved?.contains("\"YY\"") == true && approved?.contains("\"ZZ\"") == true,
              "allowEgressCountry accepts proxy:0 observation without peerAddress")
        check(ac_proxy_only_check_egress_target(handle, 0, host) == 1,
              "connection allowed after approving YY on proxy:0")

        // 5. Untrusted CA (testAnchor = nil) fails closed with 0 HTTP requests sent.
        EgressProbe.testAnchor = nil
        ac_proxy_only_update_rules(handle, rules)
        check(ac_proxy_only_check_egress_target(handle, 0, host) == 0,
              "untrusted server certificate fails closed over bridge")
    }
}

@_silgen_name("ac_string_free")
private func ac_string_free(_ ptr: UnsafeMutablePointer<CChar>?)
@_silgen_name("ac_proxy_only_set_egress_probe_with_peer")
private func ac_proxy_only_set_egress_probe_with_peer(
    _ ctx: UnsafeMutableRawPointer?,
    _ cb: (@convention(c) (UnsafeMutableRawPointer?, UnsafePointer<CChar>, UnsafeMutablePointer<Int>,
                           UnsafeMutablePointer<UInt8>?, Int) -> UnsafeMutablePointer<UInt8>?)?
)
@_silgen_name("ac_proxy_only_start_with_egress")
private func ac_proxy_only_start_with_egress(
    _ rules: UnsafePointer<CChar>, _ network: UnsafePointer<CChar>, _ egress: UnsafePointer<CChar>?,
    _ support: UnsafePointer<CChar>, _ boot: UnsafePointer<CChar>, _ noRoutes: Bool,
    _ error: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> OpaquePointer?
@_silgen_name("ac_proxy_only_update_rules")
private func ac_proxy_only_update_rules(_ handle: OpaquePointer, _ rules: UnsafePointer<CChar>)
@_silgen_name("ac_proxy_only_egress_status")
private func ac_proxy_only_egress_status(_ handle: OpaquePointer) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_proxy_only_recheck_egress")
private func ac_proxy_only_recheck_egress(_ handle: OpaquePointer, _ group: UInt32) -> Bool
@_silgen_name("ac_proxy_only_allow_egress_country")
private func ac_proxy_only_allow_egress_country(
    _ handle: OpaquePointer, _ cfg: UnsafePointer<CChar>, _ group: UInt32, _ started: Double,
    _ country: UnsafePointer<CChar>, _ evidence: UnsafePointer<CChar>
) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_proxy_only_check_egress_target")
private func ac_proxy_only_check_egress_target(
    _ handle: OpaquePointer, _ proxyIndex: Int, _ host: UnsafePointer<CChar>
) -> Int32
@_silgen_name("ac_proxy_only_stop_handover")
private func ac_proxy_only_stop_handover(_ handle: OpaquePointer, _ handover: Bool)
