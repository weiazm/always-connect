import Foundation

/// A proxy and the sites that go through it (DESIGN.md §六十九). The rules
/// use the split list's syntax and parser (ListRule); networks and geoip
/// are refused because the proxy is chosen from the name before any
/// address exists (no DNS server is asked about a proxied name).
struct ProxyRoute: Codable, Equatable, Identifiable {
    enum Kind: String, Codable, CaseIterable, Identifiable {
        case socks5, http
        var id: String { rawValue }
        var label: String { self == .socks5 ? "SOCKS5" : "HTTP" }
    }

    var id = UUID()
    var name: String
    var kind: Kind
    var host: String
    var port: Int
    var sites: [String]
    var enabled: Bool = true

    var address: String { host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)" }
    var summary: String { "\(kind.label) · \(address) · \(sites.count) 条规则" }

    static func validHost(_ host: String) -> Bool {
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:")
        return !host.isEmpty && host.count <= 253 && host.unicodeScalars.allSatisfy(allowed.contains)
    }

    static func validPort(_ port: Int) -> Bool { (1...65535).contains(port) }

    /// Decoding is lenient so a future field never drops the user's list.
    init(id: UUID = UUID(), name: String, kind: Kind, host: String, port: Int, sites: [String], enabled: Bool = true) {
        self.id = id; self.name = name; self.kind = kind; self.host = host; self.port = port
        self.sites = sites; self.enabled = enabled
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
        kind = (try? c.decodeIfPresent(Kind.self, forKey: .kind)) ?? .socks5
        host = try c.decodeIfPresent(String.self, forKey: .host) ?? ""
        port = try c.decodeIfPresent(Int.self, forKey: .port) ?? 0
        sites = try c.decodeIfPresent([String].self, forKey: .sites) ?? []
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
    }
}

extension AppSettings {
    /// The proxies as the background service reads them, inside the split
    /// list: "proxy:<n> <kind> <host> <port>" and "via:<n>:<rule>" per
    /// expanded rule, in the user's order (the first proxy whose rules
    /// match a name takes it). A service without proxies ignores both
    /// kinds of line, so those names stay in the VPN there, never direct.
    var proxyLines: [String] {
        var out: [String] = []
        let routes = (proxyRoutes ?? []).filter { $0.enabled && !$0.sites.isEmpty }
        for (index, route) in routes.enumerated() {
            // An invalid address still declares the proxy (it is refused
            // there): its sites must not fall back to another path.
            let host = ProxyRoute.validHost(route.host) ? route.host : "invalid"
            let port = ProxyRoute.validPort(route.port) ? route.port : 0
            out.append("proxy:\(index) \(route.kind.rawValue) \(host) \(port)")
            // The same expansion as the split list (Rust core, §66.30);
            // networks and geoip never become proxy rules.
            let rules = route.sites.compactMap(ListRule.parse).filter { rule in
                if case .geoip = rule { return false }
                return !rule.isNetwork
            }
            for item in GeoData.expand(rules.map(\.text), networks: false).split(separator: "\n")
                where !item.isEmpty && !item.hasPrefix("ipcidr:") {
                out.append("via:\(index):\(item)")
            }
        }
        return out
    }
}
