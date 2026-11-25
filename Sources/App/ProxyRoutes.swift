import Foundation

/// A proxy and the sites that go through it (DESIGN.md §六十九). The rules
/// use the split list's syntax and parser (ListRule): names and site lists
/// pick the proxy before any DNS lookup; geoip and networks pick it from
/// the VPN DNS answer's address, and written networks are also routed so
/// connections straight to an address go through it.
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
    /// Username for the proxy; the password is in the keychain.
    var username: String?
    /// Changes whenever the password is saved, so the App process reads
    /// the keychain again (once per run per password, §21.12).
    var passwordStamp: String?

    var address: String { host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)" }
    var summary: String {
        let login = (username ?? "").isEmpty ? "" : " · 用户 \(username!)"
        return "\(kind.label) · \(address)\(login) · \(sites.count) 条规则"
    }
    /// The keychain item for this proxy's password.
    var keychainServer: String { "proxy-\(id.uuidString)" }

    static func validHost(_ host: String) -> Bool {
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:")
        return !host.isEmpty && host.count <= 253 && host.unicodeScalars.allSatisfy(allowed.contains)
    }

    static func validPort(_ port: Int) -> Bool { (1...65535).contains(port) }

    /// Decoding is lenient so a future field never drops the user's list.
    init(id: UUID = UUID(), name: String, kind: Kind, host: String, port: Int, sites: [String], enabled: Bool = true,
         username: String? = nil, passwordStamp: String? = nil) {
        self.id = id; self.name = name; self.kind = kind; self.host = host; self.port = port
        self.sites = sites; self.enabled = enabled; self.username = username; self.passwordStamp = passwordStamp
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
        username = try c.decodeIfPresent(String.self, forKey: .username)
        passwordStamp = try c.decodeIfPresent(String.self, forKey: .passwordStamp)
    }
}

/// Proxy passwords, read from the keychain at most once per run per saved
/// password (the stamp changes on every save).
enum ProxyPasswords {
    private static let lock = NSLock()
    private static var cache: [String: String] = [:]
    /// Stand-in for the keychain (tests).
    static var read: (ProxyRoute) -> String? = { route in
        KeychainStore.read(server: route.keychainServer, username: "proxy")
    }

    static func password(for route: ProxyRoute) -> String? {
        guard let stamp = route.passwordStamp, !(route.username ?? "").isEmpty else { return nil }
        let key = "\(route.id.uuidString)|\(stamp)"
        lock.lock(); defer { lock.unlock() }
        if let known = cache[key] { return known }
        guard let value = read(route), !value.isEmpty else { return nil }
        cache[key] = value
        return value
    }

    static func save(_ password: String, for route: ProxyRoute) -> Bool {
        KeychainStore.save(server: route.keychainServer, username: "proxy", password: password)
    }

    static func delete(for route: ProxyRoute) {
        _ = KeychainStore.delete(server: route.keychainServer, username: "proxy")
    }
}

/// RFC 3986 unreserved characters stay; everything else is %XX, so a
/// value never contains a space or another field's separator.
func proxyFieldEncode(_ value: String) -> String {
    let unreserved = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")
    return value.unicodeScalars.map { scalar in
        unreserved.contains(scalar) ? String(scalar) : String(scalar).utf8.map { String(format: "%%%02X", $0) }.joined()
    }.joined()
}

extension AppSettings {
    /// The proxies as the background service reads them, inside the split
    /// list: "proxy:<n> <kind> <host> <port> [<user> <password>]", then
    /// "via:<n>:<rule>" per expanded rule (geoip as "ipcidr:") and
    /// "vianet:<n>:<cidr>" per written network, in the user's order (the
    /// first proxy whose rules match takes the site). A service without
    /// proxies ignores every such line, so those sites stay in the VPN
    /// there, never direct.
    var proxyLines: [String] {
        var out: [String] = []
        let routes = (proxyRoutes ?? []).filter { $0.enabled && !$0.sites.isEmpty }
        for (index, route) in routes.enumerated() {
            // An invalid address still declares the proxy (it is refused
            // there): its sites must not fall back to another path.
            let host = ProxyRoute.validHost(route.host) ? route.host : "invalid"
            let port = ProxyRoute.validPort(route.port) ? route.port : 0
            var line = "proxy:\(index) \(route.kind.rawValue) \(host) \(port)"
            if let user = route.username, !user.isEmpty {
                // A missing password still sends the username: the proxy's
                // refusal names the problem instead of a silent change.
                let password = ProxyPasswords.password(for: route) ?? ""
                line += " \(proxyFieldEncode(user)) \(password.isEmpty ? "%00" : proxyFieldEncode(password))"
            }
            out.append(line)
            let rules = route.sites.compactMap(ListRule.parse)
            for rule in rules {
                if case .network(let cidr) = rule { out.append("vianet:\(index):\(cidr)") }
            }
            // The same expansion as the split list (Rust core, §66.30).
            let named = rules.filter { !$0.isNetwork }.map(\.text)
            for item in GeoData.expand(named, networks: false).split(separator: "\n") where !item.isEmpty {
                out.append("via:\(index):\(item)")
            }
        }
        return out
    }
}
