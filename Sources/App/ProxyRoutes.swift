import Foundation

@_silgen_name("ac_hysteria_parse_uri")
private func ac_hysteria_parse_uri(_ uri: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_string_free")
private func proxy_routes_string_free(_ s: UnsafeMutablePointer<CChar>?)

/// A proxy and the sites that go through it (DESIGN.md §六十九, §七十). The rules
/// use the split list's syntax and parser (ListRule): names and site lists
/// pick the proxy before any DNS lookup; geoip and networks pick it from
/// the VPN DNS answer's address, and written networks are also routed so
/// connections straight to an address go through it.
struct ProxyRoute: Codable, Equatable, Identifiable {
    enum Kind: String, Codable, CaseIterable, Identifiable {
        case socks5, http, hysteria2
        var id: String { rawValue }
        var label: String {
            switch self {
            case .socks5: return "SOCKS5"
            case .http: return "HTTP"
            case .hysteria2: return "Hysteria2"
            }
        }
    }

    var id = UUID()
    var name: String
    var kind: Kind
    var host: String
    var port: Int
    var sites: [String]
    var enabled: Bool = true
    /// Username for SOCKS5/HTTP; the password is in the keychain.
    var username: String?
    /// Changes whenever the password (or Hysteria2 auth) is saved, so the App
    /// process reads the keychain again (once per run per password, §21.12).
    var passwordStamp: String?
    /// Hysteria2 port specification (e.g. "443", "443,5000-6000", "20000-50000").
    var hysteriaPorts: String?
    var sni: String?
    var pinSHA256: String?
    var obfs: String?
    /// Changes whenever the Hysteria2 obfs-password is saved in the vault.
    var obfsPasswordStamp: String?
    var ech: String?
    var upMbps: Int?
    var downMbps: Int?
    var hopSeconds: Int?

    var effectivePorts: String {
        if let p = hysteriaPorts, !p.isEmpty { return p }
        return port > 0 ? "\(port)" : "443"
    }

    var address: String {
        if kind == .hysteria2 { return "\(host):\(effectivePorts)" }
        return host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }
    var rowSubtitle: String {
        if kind == .hysteria2 { return "Hysteria2 · \(host):\(effectivePorts)" }
        return ProxyLink.display(self).replacingOccurrences(of: "://", with: " · ")
    }
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
         username: String? = nil, passwordStamp: String? = nil, hysteriaPorts: String? = nil, sni: String? = nil,
         pinSHA256: String? = nil, obfs: String? = nil, obfsPasswordStamp: String? = nil, ech: String? = nil,
         upMbps: Int? = nil, downMbps: Int? = nil, hopSeconds: Int? = nil) {
        self.id = id; self.name = name; self.kind = kind; self.host = host; self.port = port
        self.sites = sites; self.enabled = enabled; self.username = username; self.passwordStamp = passwordStamp
        self.hysteriaPorts = hysteriaPorts; self.sni = sni; self.pinSHA256 = pinSHA256; self.obfs = obfs
        self.obfsPasswordStamp = obfsPasswordStamp; self.ech = ech; self.upMbps = upMbps
        self.downMbps = downMbps; self.hopSeconds = hopSeconds
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
        hysteriaPorts = try c.decodeIfPresent(String.self, forKey: .hysteriaPorts)
        sni = try c.decodeIfPresent(String.self, forKey: .sni)
        pinSHA256 = try c.decodeIfPresent(String.self, forKey: .pinSHA256)
        obfs = try c.decodeIfPresent(String.self, forKey: .obfs)
        obfsPasswordStamp = try c.decodeIfPresent(String.self, forKey: .obfsPasswordStamp)
        ech = try c.decodeIfPresent(String.self, forKey: .ech)
        upMbps = try c.decodeIfPresent(Int.self, forKey: .upMbps)
        downMbps = try c.decodeIfPresent(Int.self, forKey: .downMbps)
        hopSeconds = try c.decodeIfPresent(Int.self, forKey: .hopSeconds)
    }
}

/// Proxy passwords, read from the keychain at most once per run per saved
/// password (the stamp changes on every save).
enum ProxyPasswords {
    private static let lock = NSLock()
    private static var cache: [String: String] = [:]
    /// Stand-ins for the keychain (tests).
    static var read: (ProxyRoute) -> String? = { route in
        KeychainStore.read(server: route.keychainServer, username: "proxy")
    }
    static var readObfs: (ProxyRoute) -> String? = { route in
        KeychainStore.read(server: route.keychainServer, username: "proxy-obfs")
    }

    static func password(for route: ProxyRoute) -> String? {
        guard let stamp = route.passwordStamp else { return nil }
        if route.kind != .hysteria2, (route.username ?? "").isEmpty { return nil }
        let key = "\(route.id.uuidString)|\(stamp)"
        lock.lock(); defer { lock.unlock() }
        if let known = cache[key] { return known }
        guard let value = read(route), !value.isEmpty else { return nil }
        cache[key] = value
        return value
    }

    static func obfsPassword(for route: ProxyRoute) -> String? {
        guard route.kind == .hysteria2, let stamp = route.obfsPasswordStamp, !(route.obfs ?? "").isEmpty else { return nil }
        let key = "\(route.id.uuidString)|obfs|\(stamp)"
        lock.lock(); defer { lock.unlock() }
        if let known = cache[key] { return known }
        guard let value = readObfs(route), !value.isEmpty else { return nil }
        cache[key] = value
        return value
    }

    static func save(_ password: String, for route: ProxyRoute) -> Bool {
        KeychainStore.save(server: route.keychainServer, username: "proxy", password: password)
    }

    static func saveObfs(_ password: String, for route: ProxyRoute) -> Bool {
        KeychainStore.save(server: route.keychainServer, username: "proxy-obfs", password: password)
    }

    static func deleteObfs(for route: ProxyRoute) {
        _ = KeychainStore.delete(server: route.keychainServer, username: "proxy-obfs")
    }

    static func delete(for route: ProxyRoute) {
        _ = KeychainStore.delete(server: route.keychainServer, username: "proxy")
        _ = KeychainStore.delete(server: route.keychainServer, username: "proxy-obfs")
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

extension ProxyRoute {
    /// "<kind> <host> <port> [<user> <password>]" or
    /// "hysteria2 <host> <ports> auth=<enc> ..." as the Rust core reads it.
    /// An invalid address still declares the proxy (it is refused there):
    /// its sites must not fall back to another path.
    func serverLine(password: String?, obfsPassword: String? = nil) -> String {
        if kind == .hysteria2 {
            let safeHost = Self.validHost(host) && !host.contains(":") ? proxyFieldEncode(host) : "invalid"
            let ports = proxyFieldEncode(effectivePorts)
            let auth = (password ?? "").isEmpty ? "%00" : proxyFieldEncode(password!)
            var parts = ["hysteria2", safeHost, ports, "auth=\(auth)"]
            if let sni, !sni.isEmpty { parts.append("sni=\(proxyFieldEncode(sni))") }
            if let pinSHA256, !pinSHA256.isEmpty { parts.append("pin=\(proxyFieldEncode(pinSHA256))") }
            if let obfs, !obfs.isEmpty {
                parts.append("obfs=\(proxyFieldEncode(obfs))")
                let opw = (obfsPassword ?? "").isEmpty ? "%00" : proxyFieldEncode(obfsPassword!)
                parts.append("obfs_password=\(opw)")
            }
            if let ech, !ech.isEmpty { parts.append("ech=\(proxyFieldEncode(ech))") }
            if let upMbps { parts.append("upmbps=\(upMbps)") }
            if let downMbps { parts.append("downmbps=\(downMbps)") }
            if let hopSeconds { parts.append("hop=\(hopSeconds)") }
            return parts.joined(separator: " ")
        }
        let host = Self.validHost(host) ? host : "invalid"
        let port = Self.validPort(port) ? port : 0
        var line = "\(kind.rawValue) \(host) \(port)"
        if let user = username, !user.isEmpty {
            let password = password ?? ""
            line += " \(proxyFieldEncode(user)) \(password.isEmpty ? "%00" : proxyFieldEncode(password))"
        }
        return line
    }
}

extension AppSettings {
    var proxiesOn: Bool { proxiesPaused != true }

    /// The proxies the background service gets, in order: proxy n in its
    /// status is the n-th of these.
    var activeProxyRoutes: [ProxyRoute] {
        guard proxiesOn else { return [] }
        return (proxyRoutes ?? []).filter { $0.enabled && !$0.sites.isEmpty }
    }

    /// The proxies' own servers never go through Cisco (DESIGN §69.21,
    /// user: 「那我建议所有代理地址都默认直连，不要走公司」「不要走cisco」;
    /// for Hysteria2 there is no other way, §70.6: QUIC's first packet does
    /// not fit the tunnel). Treated like a 分流直连 entry the user wrote: a
    /// name as "full:" for the own connection's DNS split, an IPv4 address
    /// as a /32 network. A proxy on this Mac (loopback) needs neither.
    private var proxyServers: [String] {
        var seen = Set<String>()
        return activeProxyRoutes.map { $0.host.lowercased() }
            .filter { host in
                ProxyRoute.validHost(host) && !host.contains(":") && host != "localhost" && !host.hasPrefix("127.")
                    && seen.insert(host).inserted
            }
    }
    var proxyServerDirectRules: [String] {
        proxyServers.filter { !isValidIPv4Address($0) }.map { "full:\($0)" }
    }
    var proxyServerDirectNetworks: [String] {
        proxyServers.filter(isValidIPv4Address).map { "\($0)/32" }
    }

    /// What the service gets when the split list is off: the proxy
    /// servers' own way around Cisco, then the proxies.
    var proxyRuleText: String {
        (proxyServerDirectRules + proxyLines).joined(separator: "\n")
    }

    /// The proxies as the background service reads them, inside the split
    /// list: "proxy:<n> <kind> ...", then "via:<n>:<rule>" per expanded rule
    /// (geoip as "ipcidr:") and "vianet:<n>:<cidr>" per written network, in
    /// the user's order. An older service ignores unknown lines or types and
    /// refuses connections to unknown proxies (fail closed).
    var proxyLines: [String] {
        var out: [String] = []
        for (index, route) in activeProxyRoutes.enumerated() {
            let line = route.serverLine(password: ProxyPasswords.password(for: route),
                                        obfsPassword: ProxyPasswords.obfsPassword(for: route))
            out.append("proxy:\(index) " + line)
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
/// `hysteria2://…` / `hy2://…`, `user:pass@host:port` or `host:port` (SOCKS5),
/// `[::1]:1080`, and the Surge / Clash style `socks5, host, port[, user, pass]`.
struct ProxyLink: Equatable {
    var kind: ProxyRoute.Kind
    var host: String
    var port: Int
    var username: String?
    var password: String?
    var name: String?
    /// The type was not written: SOCKS5 was assumed (shown to the user).
    var assumedKind = false
    /// Hysteria2 fields (parsed by the Rust core).
    var ports: String? = nil
    var sni: String? = nil
    var pinSHA256: String? = nil
    var obfs: String? = nil
    var obfsPassword: String? = nil
    var ech: String? = nil
    var upMbps: Int? = nil
    var downMbps: Int? = nil
    var hopSeconds: Int? = nil
    var hysteriaSummary: String? = nil

    enum Parsed: Equatable {
        case link(ProxyLink)
        case problem(String)
        var link: ProxyLink? { if case .link(let value) = self { return value } else { return nil } }
        var problem: String? { if case .problem(let value) = self { return value } else { return nil } }
    }

    var summary: String {
        if kind == .hysteria2, let hysteriaSummary { return hysteriaSummary }
        let address = host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
        var text = "\(kind.label)\(assumedKind ? "（未写类型，按 SOCKS5）" : "") · \(address)"
        if let username { text += " · 用户 \(username)\(password == nil ? "" : "，带密码")" }
        return text
    }

    /// The line to show when editing: never the password or obfs-password.
    static func display(_ route: ProxyRoute) -> String {
        if route.kind == .hysteria2 {
            var params: [String] = []
            if let sni = route.sni, !sni.isEmpty { params.append("sni=\(proxyFieldEncode(sni))") }
            if let pin = route.pinSHA256, !pin.isEmpty { params.append("pinSHA256=\(proxyFieldEncode(pin))") }
            if let obfs = route.obfs, !obfs.isEmpty { params.append("obfs=\(proxyFieldEncode(obfs))") }
            if let ech = route.ech, !ech.isEmpty { params.append("ech=\(proxyFieldEncode(ech))") }
            if let u = route.upMbps { params.append("upmbps=\(u)") }
            if let d = route.downMbps { params.append("downmbps=\(d)") }
            if let h = route.hopSeconds { params.append("hop=\(h)") }
            let query = params.isEmpty ? "" : "/?" + params.joined(separator: "&")
            return "hysteria2://\(route.host):\(route.effectivePorts)\(query)"
        }
        let host = route.host.contains(":") ? "[\(route.host)]" : route.host
        let user = (route.username ?? "").isEmpty ? "" : proxyFieldEncode(route.username!) + "@"
        return "\(route.kind.rawValue)://\(user)\(host):\(route.port)"
    }

    /// Whether a proxy server still goes through Cisco under `settings`:
    /// not yet among the saved proxies' servers, the direct list or the
    /// local networks (the editor saves before checking such one, §69.21).
    static func serverStillThroughCisco(host: String, settings: AppSettings) -> Bool {
        if settings.proxyServerDirectRules.contains("full:\(host.lowercased())") { return false }
        let isIP = isValidIPv4Address(host)
        if DirectSites.covering(DirectSites.sites(settings), host: isIP ? nil : host, address: isIP ? host : "") != nil {
            return false
        }
        if isIP {
            // Check private/loopback ranges and configured allow networks (LAN).
            let lanAndPrivate = settings.effectiveAllowNetworks + ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
            let asDirect = lanAndPrivate.map { DirectSite(name: $0, domains: [$0]) }
            if DirectSites.covering(asDirect, host: nil, address: host) != nil {
                return false
            }
        }
        return true
    }

    static func parse(_ input: String) -> Parsed {
        var text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return .problem("填一个代理地址，例如 socks5://1.2.3.4:1080 或 hy2://密码@主机:443") }
        let lower = text.lowercased()
        if lower.hasPrefix("hysteria2://") || lower.hasPrefix("hy2://")
            || lower.hasPrefix("hysteria2+realm://") || lower.hasPrefix("hy2+realm://")
            || lower.hasPrefix("hysteria2+realm+http://") || lower.hasPrefix("hy2+realm+http://") {
            return parseHysteria(text)
        }
        if text.contains(",") { return parseList(text) }
        var kind = ProxyRoute.Kind.socks5
        var assumed = true
        if let range = text.range(of: "://") {
            switch text[..<range.lowerBound].lowercased() {
            case "socks5", "socks5h", "socks": kind = .socks5
            case "http": kind = .http
            case "https": return .problem("暂不支持 HTTPS（加密）代理，请用 http:// 或 socks5://")
            case "socks4", "socks4a": return .problem("不支持 SOCKS4，请用 SOCKS5")
            default: return .problem("认不出代理类型，支持 socks5://、http:// 和 hysteria2://（hy2://）")
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

    private static func parseHysteria(_ input: String) -> Parsed {
        guard let raw = ac_hysteria_parse_uri(input) else { return .problem("无法解析 Hysteria2 链接") }
        defer { proxy_routes_string_free(raw) }
        struct WireURI: Decodable {
            var host: String
            var ports: String
            var firstPort: Int
            var auth: String?
            var sni: String?
            var pinSha256: String?
            var obfs: String?
            var obfsPassword: String?
            var ech: String?
            var upMbps: Int?
            var downMbps: Int?
            var hopSecs: Int?
            var name: String?
            var summary: String
        }
        struct Envelope: Decodable {
            var ok: Bool
            var uri: WireURI?
            var error: String?
        }
        guard let out = try? JSONDecoder().decode(Envelope.self, from: Data(String(cString: raw).utf8)) else {
            return .problem("无法解析 Hysteria2 链接")
        }
        guard out.ok, let u = out.uri else {
            return .problem(out.error ?? "Hysteria2 链接格式不对")
        }
        return .link(ProxyLink(
            kind: .hysteria2,
            host: u.host,
            port: u.firstPort,
            username: nil,
            password: u.auth,
            name: u.name,
            assumedKind: false,
            ports: u.ports,
            sni: u.sni,
            pinSHA256: u.pinSha256,
            obfs: u.obfs,
            obfsPassword: u.obfsPassword,
            ech: u.ech,
            upMbps: u.upMbps,
            downMbps: u.downMbps,
            hopSeconds: u.hopSecs,
            hysteriaSummary: u.summary
        ))
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
