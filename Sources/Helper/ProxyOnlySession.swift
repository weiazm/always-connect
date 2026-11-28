import Foundation

/// Proxies with Cisco off (DESIGN.md §69.20): a thin shell over the Rust
/// session (core/src/proxy_only.rs). The service decides when it runs
/// (HelperDaemon.reconcileProxyOnly, the rule is the core's); this only
/// starts, feeds and stops it, and tells it about network changes.
final class ProxyOnlySession {
    private var handle: OpaquePointer?

    /// The local network the session asks for every name it does not proxy.
    static func network() -> String {
        let physical = PhysicalNetwork.current(preferring: "en0")
        let interface = physical?.interface
        let dns = interface.map { LocalDNS.servers(for: $0) } ?? []
        var wire: [String: Any] = ["dns": dns]
        if let physical { wire["interface"] = physical.interface; wire["gateway"] = physical.gateway }
        let data = (try? JSONSerialization.data(withJSONObject: wire)) ?? Data("{}".utf8)
        return String(decoding: data, as: UTF8.self)
    }

    private static var probeInstalled = false

    private static func installProbeIfNeeded() {
        guard !probeInstalled else { return }
        probeInstalled = true
        ac_proxy_only_set_egress_probe_with_peer(nil) { _, request, length, peer, capacity in
            EgressProbe.exchange(request, length: length, peerBuffer: peer, capacity: capacity)
        }
    }

    /// nil and the reason when it cannot start.
    static func start(rules: String, egressJSON: String? = nil) -> (ProxyOnlySession?, String?) {
        installProbeIfNeeded()
        var error: UnsafeMutablePointer<CChar>?
        let handle = ac_proxy_only_start_with_egress(rules, network(), egressJSON,
                                                     CLIOrchestrator.defaultSupportDir.path,
                                                     BootSession.id ?? "", TestSeam.isActive, &error)
        guard let handle else { return (nil, NetworkGuard.take(error) ?? "只开代理没能启动") }
        let session = ProxyOnlySession()
        session.handle = handle
        return (session, nil)
    }

    func update(rules: String) { if let handle { ac_proxy_only_update_rules(handle, rules) } }
    func updateEgress(_ json: String?) { if let handle { ac_proxy_only_update_egress(handle, json) } }
    func networkChanged() { if let handle { ac_proxy_only_update_network(handle, Self.network()) } }
    var statusJSON: String { handle.flatMap { NetworkGuard.take(ac_proxy_only_status($0)) } ?? "{}" }
    func egressStatus() -> String { handle.flatMap { NetworkGuard.take(ac_proxy_only_egress_status($0)) } ?? "{}" }
    func recheckEgressFailures(_ group: UInt32) -> Bool {
        handle.map { ac_proxy_only_recheck_egress($0, group) } ?? false
    }
    func allowEgressCountry(_ country: String, group: UInt32, started: Double, evidence: String,
                            expected: EgressProtection) -> [String]? {
        guard let handle, let cfg = try? JSONEncoder().encode(expected),
              let json = NetworkGuard.take(ac_proxy_only_allow_egress_country(
                  handle, String(decoding: cfg, as: UTF8.self), group, started, country, evidence)) else { return nil }
        return try? JSONDecoder().decode([String].self, from: Data(json.utf8))
    }

    func stop(handover: Bool = false) {
        guard let handle else { return }
        self.handle = nil
        ac_proxy_only_stop_handover(handle, handover)
    }

    deinit { stop(handover: false) }

    static func shouldRun(wanted: Bool, engineActive: Bool, ciscoActive: Bool) -> Bool {
        ac_proxy_only_should_run(wanted, engineActive, ciscoActive)
    }

    static func removeLeftover() { ac_proxy_only_remove_leftover() }
}

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
@_silgen_name("ac_proxy_only_update_egress")
private func ac_proxy_only_update_egress(_ handle: OpaquePointer, _ json: UnsafePointer<CChar>?)
@_silgen_name("ac_proxy_only_update_network")
private func ac_proxy_only_update_network(_ handle: OpaquePointer, _ network: UnsafePointer<CChar>)
@_silgen_name("ac_proxy_only_status")
private func ac_proxy_only_status(_ handle: OpaquePointer) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_proxy_only_egress_status")
private func ac_proxy_only_egress_status(_ handle: OpaquePointer) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_proxy_only_recheck_egress")
private func ac_proxy_only_recheck_egress(_ handle: OpaquePointer, _ group: UInt32) -> Bool
@_silgen_name("ac_proxy_only_allow_egress_country")
private func ac_proxy_only_allow_egress_country(
    _ handle: OpaquePointer, _ cfg: UnsafePointer<CChar>, _ group: UInt32, _ started: Double,
    _ country: UnsafePointer<CChar>, _ evidence: UnsafePointer<CChar>
) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_proxy_only_stop_handover")
private func ac_proxy_only_stop_handover(_ handle: OpaquePointer, _ handover: Bool)
@_silgen_name("ac_proxy_only_should_run")
private func ac_proxy_only_should_run(_ wanted: Bool, _ engineActive: Bool, _ ciscoActive: Bool) -> Bool
@_silgen_name("ac_proxy_only_remove_leftover")
private func ac_proxy_only_remove_leftover()
