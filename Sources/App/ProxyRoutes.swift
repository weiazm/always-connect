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

/// A proxy written as one line, the way proxies are usually shared:
/// `socks5://user:pass@1.2.3.4:1080`, `socks5h://…`, `http://host:8080`,
/// `user:pass@host:port` or `host:port` (SOCKS5), `[::1]:1080`, and the
/// Surge / Clash style `socks5, host, port[, user, pass]` (an optional
/// `name =` in front names it).
struct ProxyLink: Equatable {
    var kind: ProxyRoute.Kind
    var host: String
    var port: Int
    var username: String?
    var password: String?
    var name: String?
    /// The type was not written: SOCKS5 was assumed (shown to the user).
    var assumedKind = false

    enum Parsed: Equatable {
        case link(ProxyLink)
        case problem(String)
        var link: ProxyLink? { if case .link(let value) = self { return value } else { return nil } }
        var problem: String? { if case .problem(let value) = self { return value } else { return nil } }
    }

    var summary: String {
        let address = host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
        var text = "\(kind.label)\(assumedKind ? "（未写类型，按 SOCKS5）" : "") · \(address)"
        if let username { text += " · 用户 \(username)\(password == nil ? "" : "，带密码")" }
        return text
    }

    /// The line to show when editing: never the password.
    static func display(_ route: ProxyRoute) -> String {
        let host = route.host.contains(":") ? "[\(route.host)]" : route.host
        let user = (route.username ?? "").isEmpty ? "" : proxyFieldEncode(route.username!) + "@"
        return "\(route.kind.rawValue)://\(user)\(host):\(route.port)"
    }

    static func parse(_ input: String) -> Parsed {
        var text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return .problem("填一个代理地址，例如 socks5://1.2.3.4:1080") }
        if text.contains(",") { return parseList(text) }
        var kind = ProxyRoute.Kind.socks5
        var assumed = true
        if let range = text.range(of: "://") {
            switch text[..<range.lowerBound].lowercased() {
            case "socks5", "socks5h", "socks": kind = .socks5
            case "http": kind = .http
            case "https": return .problem("暂不支持 HTTPS（加密）代理，请用 http:// 或 socks5://")
            case "socks4", "socks4a": return .problem("不支持 SOCKS4，请用 SOCKS5")
            default: return .problem("认不出代理类型，支持 socks5:// 和 http://")
            }
            assumed = false
            text = String(text[range.upperBound...])
        }
        // A "#name" names it; a path or query after the address is not part of it.
        var name: String?
        if let hash = text.firstIndex(of: "#") {
            name = String(text[text.index(after: hash)...]).removingPercentEncoding.flatMap { $0.isEmpty ? nil : $0 }
            text = String(text[..<hash])
        }
        if let cut = text.firstIndex(where: { $0 == "/" || $0 == "?" }) { text = String(text[..<cut]) }
        var username: String?
        var password: String?
        if let at = text.lastIndex(of: "@") {
            let login = text[..<at]
            text = String(text[text.index(after: at)...])
            let parts = login.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            username = parts.first.flatMap { String($0).removingPercentEncoding }
            password = parts.count > 1 ? String(parts[1]).removingPercentEncoding : nil
            if username?.isEmpty ?? true { return .problem("@ 前面的用户名是空的") }
            if password?.isEmpty == true { password = nil }
        }
        let host: String
        let portText: Substring
        if text.hasPrefix("[") {
            guard let close = text.firstIndex(of: "]") else { return .problem("IPv6 地址少了 ]") }
            host = String(text[text.index(after: text.startIndex)..<close])
            let rest = text[text.index(after: close)...]
            guard rest.hasPrefix(":") else { return .problem("缺端口，例如 [::1]:1080") }
            portText = rest.dropFirst()
        } else {
            guard let colon = text.lastIndex(of: ":") else { return .problem("缺端口，例如 1.2.3.4:1080") }
            host = String(text[..<colon])
            portText = text[text.index(after: colon)...]
        }
        return build(kind: kind, assumed: assumed, host: host, port: String(portText), username: username, password: password, name: name)
    }

    /// `[name =] socks5|http, host, port[, user, pass][, key=value…]`.
    private static func parseList(_ line: String) -> Parsed {
        var text = line
        var name: String?
        if let equals = text.firstIndex(of: "="), !text[..<equals].contains(",") {
            name = text[..<equals].trimmingCharacters(in: .whitespaces)
            text = String(text[text.index(after: equals)...])
        }
        let fields = text.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.contains("=") }
        guard fields.count >= 3 else { return .problem("逗号写法要有 类型, 地址, 端口") }
        let kind: ProxyRoute.Kind
        switch fields[0].lowercased() {
        case "socks5", "socks5h", "socks": kind = .socks5
        case "http": kind = .http
        case "https", "socks5-tls": return .problem("暂不支持加密的代理，请用 http 或 socks5")
        default: return .problem("认不出代理类型 \(fields[0])，支持 socks5 和 http")
        }
        let host = fields[1].trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        return build(kind: kind, assumed: false, host: host, port: fields[2],
                     username: fields.count > 3 && !fields[3].isEmpty ? fields[3] : nil,
                     password: fields.count > 4 && !fields[4].isEmpty ? fields[4] : nil, name: name)
    }

    private static func build(kind: ProxyRoute.Kind, assumed: Bool, host: String, port: String,
                              username: String?, password: String?, name: String?) -> Parsed {
        guard ProxyRoute.validHost(host) else { return .problem("地址只能是 IP 或域名，例如 1.2.3.4 或 proxy.example.com") }
        guard let number = Int(port), ProxyRoute.validPort(number) else { return .problem("端口是 1–65535 之间的数字") }
        if (username?.utf8.count ?? 0) > 255 || (password?.utf8.count ?? 0) > 255 { return .problem("用户名和密码各最多 255 字节") }
        return .link(ProxyLink(kind: kind, host: host, port: number, username: username, password: password,
                                  name: name, assumedKind: assumed))
    }
}
