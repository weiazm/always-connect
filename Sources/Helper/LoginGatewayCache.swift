import Foundation

/// Background-service bridge. The caller passes the service's trusted support
/// directory and records only the actual peer of an established session.
enum LoginGatewayCache {
    static func lookup(in supportDir: URL, target: GatewayAddress) -> [String] {
        read(in: supportDir, target: target) ?? []
    }

    static func read(in supportDir: URL, target: GatewayAddress) -> [String]? {
        guard let raw = ac_login_cache_lookup(supportDir.path, target.host, target.port) else { return nil }
        defer { ac_login_cache_freeString(raw) }
        return String(cString: raw).split(separator: ",").map(String.init)
    }

    @discardableResult
    static func rememberConnected(in supportDir: URL, target: GatewayAddress, peer: String) -> Bool {
        ac_login_cache_remember(supportDir.path, target.host, target.port, peer)
    }
}

@_silgen_name("ac_login_cache_lookup")
private func ac_login_cache_lookup(_ directory: UnsafePointer<CChar>, _ host: UnsafePointer<CChar>,
                                   _ port: UInt16) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_login_cache_remember")
private func ac_login_cache_remember(_ directory: UnsafePointer<CChar>, _ host: UnsafePointer<CChar>,
                                     _ port: UInt16, _ address: UnsafePointer<CChar>) -> Bool
@_silgen_name("ac_string_free")
private func ac_login_cache_freeString(_ text: UnsafeMutablePointer<CChar>)
