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
        if let interface { wire["interface"] = interface }
        let data = (try? JSONSerialization.data(withJSONObject: wire)) ?? Data("{}".utf8)
        return String(decoding: data, as: UTF8.self)
    }

    /// nil and the reason when it cannot start.
    static func start(rules: String) -> (ProxyOnlySession?, String?) {
        var error: UnsafeMutablePointer<CChar>?
        let handle = ac_proxy_only_start(rules, network(), CLIOrchestrator.defaultSupportDir.path,
                                         BootSession.id ?? "", TestSeam.isActive, &error)
        guard let handle else { return (nil, NetworkGuard.take(error) ?? "只开代理没能启动") }
        let session = ProxyOnlySession()
        session.handle = handle
        return (session, nil)
    }

    func update(rules: String) { if let handle { ac_proxy_only_update_rules(handle, rules) } }
    func networkChanged() { if let handle { ac_proxy_only_update_network(handle, Self.network()) } }
    var statusJSON: String { handle.flatMap { NetworkGuard.take(ac_proxy_only_status($0)) } ?? "{}" }

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

@_silgen_name("ac_proxy_only_start")
private func ac_proxy_only_start(_ rules: UnsafePointer<CChar>, _ network: UnsafePointer<CChar>,
                                 _ support: UnsafePointer<CChar>, _ boot: UnsafePointer<CChar>, _ noRoutes: Bool,
                                 _ error: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> OpaquePointer?
@_silgen_name("ac_proxy_only_update_rules")
private func ac_proxy_only_update_rules(_ handle: OpaquePointer, _ rules: UnsafePointer<CChar>)
@_silgen_name("ac_proxy_only_update_network")
private func ac_proxy_only_update_network(_ handle: OpaquePointer, _ network: UnsafePointer<CChar>)
@_silgen_name("ac_proxy_only_status")
private func ac_proxy_only_status(_ handle: OpaquePointer) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_proxy_only_stop_handover")
private func ac_proxy_only_stop_handover(_ handle: OpaquePointer, _ handover: Bool)
@_silgen_name("ac_proxy_only_should_run")
private func ac_proxy_only_should_run(_ wanted: Bool, _ engineActive: Bool, _ ciscoActive: Bool) -> Bool
@_silgen_name("ac_proxy_only_remove_leftover")
private func ac_proxy_only_remove_leftover()
