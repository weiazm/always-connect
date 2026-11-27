import Darwin
import Foundation

@_silgen_name("ac_list_rule_valid")
private func ac_list_rule_valid(_ rule: UnsafePointer<CChar>) -> Bool

/// One rule line, the same for the split list ("不走 VPN 的名单",
/// DESIGN.md §26.13) and exit protection (§66.30: one parser, one
/// syntax). The syntax is v2fly/domain-list-community's, the source of
/// the site lists themselves (and what v2ray and Xray read):
///   example.com          the site and all its subdomains
///                        ("domain:example.com" is the same)
///   full:www.example.com that name only
///   keyword:example      any name containing it
///   regexp:^a\d+\.example\.com$  any name matching it
///   geosite:github       a ready-made site list, optionally
///   geosite:google@cn    only its rules with that attribute
///   geosite:google@!cn   only its rules without that attribute
///   geoip:cn             any name whose address is in China mainland
///   192.168.0.0/16       a network (also a single address)
/// Names and site lists are expanded here into the background service's
/// rule kinds. In the split list, networks go to the drop-protection
/// allowlist (and, in split mode, direct routes), so they also work under
/// Cisco; exit protection checks them as addresses.
enum ListRule: Equatable {
    case domain(String)
    case full(String)
    case keyword(String)
    case regexp(String)
    case geosite(String, attribute: String?)
    case geoip(String)
    case network(String)

    static func parse(_ input: String) -> ListRule? {
        var s = input.trimmingCharacters(in: .whitespacesAndNewlines)
        // A pasted Clash/Surge line is only an input: it is stored and shown
        // in this syntax (user, 2026-11-24: "保存时做格式归一化，转成 v2fly 格式").
        if let converted = fromRuleLine(s) { s = converted }
        let lower = s.lowercased()
        func value(_ prefix: String) -> String? {
            lower.hasPrefix(prefix) ? String(s.dropFirst(prefix.count)).trimmingCharacters(in: .whitespaces) : nil
        }
        let rule: ListRule
        if let name = value("geosite:") {
            let parts = name.lowercased().split(separator: "@", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
            guard let list = parts.first, !list.isEmpty else { return nil }
            let attribute = parts.count == 2 ? parts[1] : nil
            if GeoData.available {
                guard GeoData.hasList(list) else { return nil }
                if let attribute, !attribute.hasPrefix("!"), GeoData.ruleCount(list, attribute: attribute) == 0 { return nil }
            }
            // Before the first download a list name is kept as written (the
            // background service's check below still vets its form).
            rule = .geosite(list, attribute: attribute)
        } else if let code = value("geoip:") {
            guard GeoData.geoipCountries.contains(code.lowercased()) else { return nil }
            rule = .geoip(code.lowercased())
        } else if let name = value("full:") {
            guard let name = domainName(name) else { return nil }
            rule = .full(name)
        } else if let word = value("keyword:") {
            guard !word.isEmpty else { return nil }
            rule = .keyword(word.lowercased())
        } else if let pattern = value("regexp:") {
            guard !pattern.isEmpty else { return nil }
            rule = .regexp(pattern)
        } else if let name = value("domain:") {
            guard let name = domainName(name) else { return nil }
            rule = .domain(name)
        } else if isValidCIDR(s) {
            rule = .network(s)
        } else if isValidIPv4Address(s) {
            rule = .network(s + "/32")
        } else if let name = domainName(s) {
            rule = .domain(name)
        } else {
            return nil
        }
        // The background service's own check (core egress_control::valid_rule):
        // a regexp it cannot compile is refused here, not silently dropped there.
        return ac_list_rule_valid(rule.text) ? rule : nil
    }

    /// A typed name cleaned of scheme, path and port; never an address:
    /// "192.0.2.0/33" must not become the domain "192.0.2.0".
    private static func domainName(_ input: String) -> String? {
        guard let name = DirectSites.clean(input), !isValidIPv4Address(name) else { return nil }
        return name
    }

    /// "DOMAIN-SUFFIX,example.com[,policy]" and the like, in this syntax;
    /// nil when the line is not one. The policy field is dropped.
    private static func fromRuleLine(_ line: String) -> String? {
        guard !line.lowercased().hasPrefix("regexp:"), line.contains(",") else { return nil }
        let fields = line.split(separator: ",", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespaces) }
        guard fields.count >= 2, !fields[1].isEmpty else { return nil }
        let value = fields[1]
        switch fields[0].uppercased() {
        case "DOMAIN-SUFFIX": return "domain:" + value
        case "DOMAIN": return "full:" + value
        case "DOMAIN-KEYWORD": return "keyword:" + value
        case "DOMAIN-REGEX": return "regexp:" + value
        case "GEOSITE": return "geosite:" + value
        case "GEOIP": return "geoip:" + value
        case "IP-CIDR": return value
        default: return nil
        }
    }

    /// Why `input` is not a rule, in the user's words; nil when it is.
    static func problem(_ input: String) -> String? {
        let lower = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !lower.isEmpty, parse(input) == nil else { return nil }
        if lower.hasPrefix("geosite:") {
            return lower.contains("@") ? "这个清单里没有带这个标记的条目" : "没有叫这个名字的网站清单"
        }
        if lower.hasPrefix("geoip:") { return "目前只支持 geoip:cn" }
        if lower.hasPrefix("regexp:") { return "正则表达式写得不对" }
        return "认不出来：可以写网址、full:、keyword:、regexp:、geosite:清单名、geoip 或网段"
    }

    /// The stored and shown form.
    var text: String {
        switch self {
        case .domain(let d): return d
        case .full(let d): return "full:" + d
        case .keyword(let k): return "keyword:" + k
        case .regexp(let r): return "regexp:" + r
        case .geosite(let name, let attribute): return "geosite:" + name + (attribute.map { "@" + $0 } ?? "")
        case .geoip(let code): return "geoip:" + code
        case .network(let cidr): return cidr
        }
    }

    /// What kind of line it is, shown under it.
    var kind: String {
        switch self {
        case .domain: return "网站（含子域名）"
        case .full: return "只这一个域名"
        case .keyword: return "域名里含这个词"
        case .regexp: return "域名符合这个正则"
        case .geosite(let name, _):
            return GeoData.available ? "网站清单 · \(GeoData.ruleCount(name)) 条规则" : "网站清单 · 还没下载，下载后生效"
        case .geoip: return "国家 IP · 解析到这些地址的网站"
        case .network: return "网段"
        }
    }

    var isNetwork: Bool { if case .network = self { return true } else { return false } }

    /// The background service's entries for this one rule (tests and
    /// checks; the services get whole lists expanded by GeoData.expand).
    var expanded: [String] {
        if isNetwork { return [] }
        return GeoData.expand([text], networks: false).split(separator: "\n").map(String.init)
    }
}

func isValidIPv4Address(_ value: String) -> Bool {
    var a = in_addr()
    return inet_pton(AF_INET, value, &a) == 1
}

@_silgen_name("ac_geodata_configure")
private func ac_geodata_configure(_ geosite: UnsafePointer<CChar>, _ geoip: UnsafePointer<CChar>)
@_silgen_name("ac_geodata_available")
private func ac_geodata_available() -> Bool
@_silgen_name("ac_geodata_has_list")
private func ac_geodata_has_list(_ name: UnsafePointer<CChar>) -> Bool
@_silgen_name("ac_geodata_rule_count")
private func ac_geodata_rule_count(_ name: UnsafePointer<CChar>, _ attribute: UnsafePointer<CChar>?) -> Int64
@_silgen_name("ac_geodata_expand")
private func ac_geodata_expand(_ lines: UnsafePointer<CChar>, _ networks: Bool) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_geodata_split_networks")
private func ac_geodata_split_networks(_ networks: UnsafePointer<CChar>, _ exceptions: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_string_free")
private func geodata_string_free(_ value: UnsafeMutablePointer<CChar>?)

/// The site lists and geoip:cn, read by the Rust core (core/src/geodata.rs,
/// DESIGN.md §66.30; user 2026-11-25: "这种逻辑肯定要下沉到rust做"). The
/// site lists are not part of the App: GeoUpdater downloads them to
/// Application Support. The core maps that file in place, locates only the
/// lists asked for and expands rules into one text, so the App never holds
/// the expanded entries as separate strings. geoip-cn.txt is bundled.
enum GeoData {
    static let geoipCountries: Set<String> = ["cn"]

    /// Where the download goes; uninstall removes the folder with the rest (§31).
    static var updateDirectory: URL {
        if let dir = ProcessInfo.processInfo.environment["ALWAYSCONNECT_GEO_DIR"] {
            return URL(fileURLWithPath: dir)  // the harness never touches the user's copy
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/AlwaysConnect/GeoData")
    }

    static var siteListFile: URL {
        if let dir = ProcessInfo.processInfo.environment["ALWAYSCONNECT_GEODATA"] {
            return URL(fileURLWithPath: dir).appendingPathComponent("geosite.txt")
        }
        return updateDirectory.appendingPathComponent("geosite.txt")
    }

    private static var geoipFile: String {
        if let dir = ProcessInfo.processInfo.environment["ALWAYSCONNECT_GEODATA"] {
            return URL(fileURLWithPath: dir).appendingPathComponent("geoip-cn.txt").path
        }
        return (Bundle.main.url(forResource: "geoip-cn", withExtension: "txt")
            ?? Bundle.main.url(forResource: "geoip-cn", withExtension: "txt", subdirectory: "GeoData"))?.path ?? ""
    }

    /// The core's paths, set on first use.
    private static let configured: Void = { ac_geodata_configure(siteListFile.path, geoipFile) }()

    /// Before any core call that reads the lists without going through here.
    static func prepare() { _ = configured }

    /// The site lists have been downloaded (until then geosite: rules are
    /// kept as written and match nothing).
    static var available: Bool { _ = configured; return ac_geodata_available() }

    static func hasList(_ name: String) -> Bool { _ = configured; return ac_geodata_has_list(name) }

    /// How many rules a list has (with an attribute: only those carrying
    /// it), counted in the core without keeping them.
    static func ruleCount(_ name: String, attribute: String? = nil) -> Int {
        _ = configured
        if let attribute { return Int(ac_geodata_rule_count(name, attribute)) }
        return Int(ac_geodata_rule_count(name, nil))
    }

    /// Stored rule lines as the background service's entries, one per
    /// line, in order and without repeats. Networks become "ipcidr:"
    /// entries only when asked for (exit protection).
    static func expand(_ lines: [String], networks: Bool) -> String {
        _ = configured
        guard let out = ac_geodata_expand(lines.joined(separator: "\n"), networks) else { return "" }
        defer { geodata_string_free(out) }
        return String(cString: out)
    }

    static func subtract(_ exceptions: [String], from networks: [String]) -> [String] {
        guard !exceptions.isEmpty, !networks.isEmpty else { return networks }
        _ = configured
        guard let out = ac_geodata_split_networks(networks.joined(separator: "\n"), exceptions.joined(separator: "\n")) else { return [] }
        defer { geodata_string_free(out) }
        return String(cString: out).split(separator: "\n").map(String.init)
    }
}

/// The networks the Mac sits on right now, for "本地局域网直连"
/// (§26.13, user: not a fixed 192.168): every wired/Wi-Fi interface's
/// own subnet, never wider than a /16.
enum LocalNetwork {
    static func current() -> [String] {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return [] }
        defer { freeifaddrs(list) }
        var out: [String] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            let name = String(cString: entry.pointee.ifa_name)
            guard name.hasPrefix("en"), entry.pointee.ifa_flags & UInt32(IFF_UP) != 0,
                  let addr = entry.pointee.ifa_addr, addr.pointee.sa_family == sa_family_t(AF_INET),
                  let mask = entry.pointee.ifa_netmask else { continue }
            let a = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
            var m = mask.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
            if a >> 16 == 0xA9FE { continue }  // 169.254 link-local: no real network
            if m < 0xFFFF_0000 { m = 0xFFFF_0000 }
            let bits = m.nonzeroBitCount
            let net = a & m
            let cidr = "\(net >> 24).\(net >> 16 & 0xFF).\(net >> 8 & 0xFF).\(net & 0xFF)/\(bits)"
            if !out.contains(cidr) { out.append(cidr) }
        }
        return out
    }
}

extension AppSettings {
    /// "本地局域网直连", on unless switched off.
    var isAutoLANOn: Bool { autoLAN ?? true }

    /// The list's parsed rules, in order, as they apply now: empty while 分流直连 is paused
    /// (§69.9), so neither names nor networks go direct.
    var listRules: [ListRule] {
        guard directOn else { return [] }
        return DirectSites.sites(self).flatMap(\.domains).compactMap(ListRule.parse)
    }

    var directOn: Bool { directPaused != true }

    /// What the drop-protection allowlist (and split-mode direct routes)
    /// get: the list's networks, plus the local network when on.
    var effectiveAllowNetworks: [String] {
        var out = listRules.compactMap { rule -> String? in
            if case .network(let cidr) = rule { return cidr } else { return nil }
        }
        if directOn { out = GeoData.subtract(directExceptions ?? [], from: out) }
        if isAutoLANOn { out += LocalNetwork.current().filter { !out.contains($0) } }
        out += proxyServerDirectNetworks.filter { !out.contains($0) }
        return out
    }
}
