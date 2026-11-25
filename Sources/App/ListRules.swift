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
            let parts = name.lowercased().split(separator: "@", maxSplits: 1).map(String.init)
            guard let list = parts.first, !list.isEmpty else { return nil }
            let attribute = parts.count == 2 ? parts[1] : nil
            if GeoData.available {
                guard GeoData.hasList(list) else { return nil }
                if let attribute, GeoData.geosite(list, attribute: attribute).isEmpty { return nil }
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

    /// The background service's rule kinds (DNSForwarder's SplitRules,
    /// the exit gate's ProtectedSites). A network is [] here: the split
    /// list routes it, exit protection sends it as "ipcidr:".
    var expanded: [String] {
        switch self {
        case .domain(let d): return [d]
        case .full, .keyword, .regexp: return [text]
        case .geosite(let name, let attribute): return GeoData.geosite(name, attribute: attribute)
        case .geoip(let code): return GeoData.geoip(code).map { "ipcidr:" + $0 }
        case .network: return []
        }
    }
}

func isValidIPv4Address(_ value: String) -> Bool {
    var a = in_addr()
    return inet_pton(AF_INET, value, &a) == 1
}

/// The site lists and geoip:cn. The site lists are not part of the App
/// (DESIGN.md §66.30, user 2026-11-25: "默认app都不带"): GeoUpdater
/// downloads the whole catalogue to Application Support and this reads it
/// in place, memory-mapped. Only the lists asked for are located (a scan
/// for their "[name]" line) and only their positions are kept, never an
/// index of all of them (user: "内存只留用到的数据"). A changed file (an
/// update by this or the other App process) is noticed by its modification
/// time. geoip-cn.txt is bundled.
enum GeoData {
    static let geoipCountries: Set<String> = ["cn"]

    private static let lock = NSLock()
    /// The file, memory-mapped (clean pages the system can drop).
    private static var mapped: Data?
    /// Positions of the lists asked for so far (nil = not in the file).
    private static var found: [String: Range<Int>?] = [:]
    /// Which file was read: its path and modification time.
    private static var loaded: (path: String, modified: timespec)?

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

    /// The site lists have been downloaded (until then geosite: rules are
    /// kept as written and match nothing).
    static var available: Bool { FileManager.default.fileExists(atPath: siteListFile.path) }

    private static func bundled(_ name: String) -> URL? {
        if let dir = ProcessInfo.processInfo.environment["ALWAYSCONNECT_GEODATA"] {
            return URL(fileURLWithPath: dir).appendingPathComponent(name)
        }
        let base = (name as NSString).deletingPathExtension
        return Bundle.main.url(forResource: base, withExtension: "txt")
            ?? Bundle.main.url(forResource: base, withExtension: "txt", subdirectory: "GeoData")
    }

    private static func modified(_ path: String) -> timespec? {
        var info = stat()
        return stat(path, &info) == 0 ? info.st_mtimespec : nil
    }

    /// The mapped file, re-read when it changed; the list positions with it.
    private static func current() -> Data {
        let file = siteListFile
        let stamp = modified(file.path)
        if let mapped, let loaded, loaded.path == file.path,
           loaded.modified.tv_sec == stamp?.tv_sec, loaded.modified.tv_nsec == stamp?.tv_nsec {
            return mapped
        }
        let data = stamp == nil ? Data() : (try? Data(contentsOf: file, options: .alwaysMapped)) ?? Data()
        mapped = data
        found = [:]
        loaded = stamp.map { (file.path, $0) }
        return data
    }

    /// Where one list's lines sit in `data`: the lines after "[name]" up
    /// to the next "[" line. Scans only for that header.
    static func range(of name: String, in data: Data) -> Range<Int>? {
        let header = Array(("[" + name + "]\n").utf8)
        return data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> Range<Int>? in
            let bytes = raw.bindMemory(to: UInt8.self)
            let count = bytes.count
            var start: Int?
            var i = 0
            while i < count {
                // i is the start of a line.
                if bytes[i] == UInt8(ascii: "["), i + header.count <= count,
                   header.indices.allSatisfy({ bytes[i + $0] == header[$0] }) {
                    start = i + header.count
                    break
                }
                while i < count && bytes[i] != 0x0A { i += 1 }
                i += 1
            }
            guard let start else { return nil }
            var end = start
            while end < count && bytes[end] != UInt8(ascii: "[") {
                while end < count && bytes[end] != 0x0A { end += 1 }
                end += 1
            }
            return start..<min(end, count)
        }
    }

    private static func lines(_ name: String) -> [Substring] {
        lock.lock()
        let data = current()
        let range: Range<Int>?
        if let known = found[name] {
            range = known
        } else {
            range = Self.range(of: name, in: data)
            found[name] = .some(range)
        }
        lock.unlock()
        guard let range, !range.isEmpty, range.upperBound <= data.count else { return [] }
        return String(decoding: data[range], as: UTF8.self).split(separator: "\n")
    }

    static func hasList(_ name: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        let data = current()
        if let known = found[name] { return known != nil }
        let range = Self.range(of: name, in: data)
        found[name] = .some(range)
        return range != nil
    }

    /// How many rules a list has, without keeping them.
    static func ruleCount(_ name: String) -> Int { lines(name).count }

    /// "d:x @a" -> "domain:x", "f:" -> "full:", "k:" -> "keyword:",
    /// "r:" -> "regexp:"; with an attribute, only lines carrying it.
    static func geosite(_ name: String, attribute: String?) -> [String] {
        let kinds: [Character: String] = ["d": "domain:", "f": "full:", "k": "keyword:", "r": "regexp:"]
        return lines(name).compactMap { line in
            let parts = line.split(separator: " ")
            guard let head = parts.first, head.count > 2, let prefix = kinds[head.first!] else { return nil }
            if let attribute, !parts.dropFirst().contains(Substring("@" + attribute)) { return nil }
            return prefix + head.dropFirst(2)
        }
    }

    /// Read when asked and not kept, like the site lists (§32.4): it is
    /// needed only when the list is sent to the background service.
    static func geoip(_ code: String) -> [String] {
        guard code == "cn" else { return [] }
        let text = bundled("geoip-cn.txt").flatMap { try? String(contentsOf: $0, encoding: .utf8) } ?? ""
        return text.split(separator: "\n").map(String.init).filter(isValidCIDR)
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

    /// The list's parsed rules, in order.
    var listRules: [ListRule] {
        DirectSites.sites(self).flatMap(\.domains).compactMap(ListRule.parse)
    }

    /// What the drop-protection allowlist (and split-mode direct routes)
    /// get: the list's networks, plus the local network when on.
    var effectiveAllowNetworks: [String] {
        var out = listRules.compactMap { rule -> String? in
            if case .network(let cidr) = rule { return cidr } else { return nil }
        }
        if isAutoLANOn { out += LocalNetwork.current().filter { !out.contains($0) } }
        return out
    }
}
