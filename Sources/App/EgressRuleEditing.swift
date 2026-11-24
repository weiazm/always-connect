import Foundation

@_silgen_name("ac_egress_rule_valid")
private func ac_egress_rule_valid(_ rule: UnsafePointer<CChar>) -> Bool
@_silgen_name("ac_egress_match_targets")
private func ac_egress_match_targets(_ config: UnsafePointer<CChar>, _ targets: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
@_silgen_name("ac_string_free")
private func egress_string_free(_ value: UnsafeMutablePointer<CChar>?)

extension EgressProtection.Unverified {
    var label: String {
        switch self {
        case .allow: return "放行"
        case .whenWrong: return "有异常就拦"
        case .block: return "一律拦"
        }
    }

    var explanation: String {
        switch self {
        case .allow: return "查不到出口的连接照常放行。"
        case .whenWrong: return "同一保护里有服务器走错出口时，查不到出口的连接也先拦住。"
        case .block: return "每条查不到出口的连接都拦住。"
        }
    }
}

struct EgressRuleInput {
    static let siteLimit = 256
    static let groupLimit = 16

    struct Line: Equatable {
        let site: String
        let group: String?
    }

    struct Issue: Identifiable {
        let id: Int
        let message: String
    }

    var lines: [Line] = []
    var issues: [Issue] = []

    init(_ input: String) {
        for (index, raw) in input.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline).enumerated() {
            let text = raw.trimmingCharacters(in: .whitespaces)
            guard !text.isEmpty, !text.hasPrefix("#"), !text.hasPrefix("//") else { continue }
            if let line = Self.parse(text) {
                lines.append(line)
            } else {
                let kind = text.split(separator: ",", maxSplits: 1).first.map { $0.trimmingCharacters(in: .whitespaces) } ?? text
                let message = text.contains(",") && !Self.types.contains(kind.uppercased())
                    ? "不支持 \(kind.prefix(40))" : "规则写法或值无效"
                issues.append(Issue(id: index + 1, message: message))
            }
        }
    }

    private static let types: Set<String> = [
        "DOMAIN-SUFFIX", "DOMAIN", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "GEOSITE", "IP-CIDR", "GEOIP"
    ]

    private static func parse(_ text: String) -> Line? {
        // Raw split-list regexes can themselves contain commas.
        if text.hasPrefix("regexp:") || !text.contains(",") {
            return canonical(text).map { Line(site: $0, group: nil) }
        }
        guard var fields = csvFields(text), fields.count >= 2 else { return nil }
        let kind = fields[0].uppercased()
        if (kind == "IP-CIDR" || kind == "GEOIP"), fields.last?.lowercased() == "no-resolve",
           fields.count > 2 {
            fields.removeLast()
        }
        guard fields.count == 2 || fields.count == 3 else { return nil }
        let value = fields[1]
        let group = fields.count == 3 ? fields[2] : nil
        let rule: String
        switch kind {
        case "DOMAIN-SUFFIX":
            rule = value.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "*."))
            guard rule.contains("."), ac_egress_rule_valid(rule), !rule.contains(":") && !rule.contains("/") else { return nil }
        case "DOMAIN": rule = "full:" + value.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        case "DOMAIN-KEYWORD": rule = "keyword:" + value.lowercased()
        case "DOMAIN-REGEX": rule = "regexp:" + value
        case "GEOSITE": rule = "geosite:" + value
        case "GEOIP": rule = "geoip:" + value
        case "IP-CIDR":
            guard isValidCIDR(value) || isValidIPv4Address(value) else { return nil }
            rule = value
        default: return nil
        }
        guard let site = canonical(rule),
              kind != "DOMAIN-SUFFIX" || (!site.contains(":") && !site.contains("/")) else { return nil }
        return Line(site: site, group: group.flatMap { $0.isEmpty ? nil : $0 })
    }

    private static func canonical(_ text: String) -> String? {
        let lower = text.lowercased()
        let rule: String
        if lower.hasPrefix("full:") {
            rule = "full:" + lower.dropFirst(5).trimmingCharacters(in: CharacterSet(charactersIn: "."))
        } else if lower.hasPrefix("keyword:") {
            rule = lower
        } else if text.hasPrefix("regexp:") {
            rule = text
        } else {
            guard let parsed = ListRule.parse(text) else { return nil }
            // A malformed CIDR must not turn into a domain through URL cleanup.
            if case .domain(let domain) = parsed, isValidIPv4Address(domain) { return nil }
            if case .geosite(let name, let attribute) = parsed, let attribute,
               GeoData.geosite(name, attribute: attribute).isEmpty { return nil }
            rule = parsed.text
        }
        guard ac_egress_rule_valid(rule) else { return nil }
        return rule
    }

    var groupCount: Int { Set(lines.map(\.group)).count }

    func adding(to old: [String]) -> [String] {
        var seen = Set(old)
        return old + lines.map(\.site).filter { seen.insert($0).inserted }
    }

    /// Editing replaces the whole list. Every non-comment line must parse.
    var replacementSites: [String]? {
        guard issues.isEmpty else { return nil }
        let sites = adding(to: [])
        return (1...Self.siteLimit).contains(sites.count) ? sites : nil
    }

    static func clashText(_ sites: [String]) -> String {
        sites.map { clash($0) }.joined(separator: "\n")
    }

    static func clash(_ site: String, group: String? = nil) -> String {
        let pair = site.split(separator: ":", maxSplits: 1)
        let kind: String
        let value: String
        if pair.count == 2 {
            switch pair[0] {
            case "full": kind = "DOMAIN"
            case "keyword": kind = "DOMAIN-KEYWORD"
            case "regexp": kind = "DOMAIN-REGEX"
            case "geosite": kind = "GEOSITE"
            case "geoip": kind = "GEOIP"
            default: kind = "DOMAIN-SUFFIX"
            }
            value = pair[0] == "geoip" ? pair[1].uppercased() : String(pair[1])
        } else {
            kind = isValidCIDR(site) ? "IP-CIDR" : "DOMAIN-SUFFIX"
            value = site
        }
        return ([kind, value] + (group.map { [$0] } ?? [])).map { field in
            guard field.contains(",") || field.contains("\"") else { return field }
            return "\"" + field.replacingOccurrences(of: "\"", with: "\"\"") + "\""
        }.joined(separator: ",")
    }

    private static func csvFields(_ text: String) -> [String]? {
        var fields: [String] = []
        var field = ""
        var quoted = false
        var chars = text[...]
        while let char = chars.popFirst() {
            if char == "\"" {
                if quoted && chars.first == "\"" {
                    field.append(char)
                    _ = chars.popFirst()
                } else {
                    quoted.toggle()
                }
            } else if char == "," && !quoted {
                fields.append(field.trimmingCharacters(in: .whitespaces))
                field = ""
            } else {
                field.append(char)
            }
        }
        guard !quoted else { return nil }
        fields.append(field.trimmingCharacters(in: .whitespaces))
        return fields
    }
}

extension EgressProtection {
    /// A disabled master switch from an older build must not arm its rules
    /// when the interface uses per-rule switches.
    var rulesForEditing: Self {
        guard !enabled else { return self }
        var result = self
        for index in result.groups.indices { result.groups[index].enabled = false }
        return result
    }

    mutating func updateEnabledFromRules() {
        enabled = groups.contains(where: \.enabled)
    }

    var forBackgroundService: Self {
        var result = withoutExpandedMatches
        guard enabled else { return result }
        var expanded: [String: [String]] = [:]
        for index in result.groups.indices where result.groups[index].enabled {
            var seen = Set<String>()
            result.groups[index].matches = result.groups[index].sites.flatMap { site in
                if let cached = expanded[site] { return cached }
                let items: [String]
                if site.hasPrefix("full:") || site.hasPrefix("keyword:") || site.hasPrefix("regexp:") {
                    items = [site]
                } else if let rule = ListRule.parse(site) {
                    items = rule.isNetwork ? ["ipcidr:" + rule.text] : rule.expanded
                } else {
                    items = []
                }
                expanded[site] = items
                return items
            }.filter { seen.insert($0).inserted }
        }
        return result
    }

    struct Target: Codable, Hashable {
        let host: String?
        let address: String
    }

    /// Compile the same matcher as the gate, once for an on-screen batch.
    func rules(covering targets: [Target]) -> [Target: UInt32] {
        guard isActive, !targets.isEmpty,
              let config = try? JSONEncoder().encode(forBackgroundService),
              let input = try? JSONEncoder().encode(targets),
              let result = ac_egress_match_targets(String(decoding: config, as: UTF8.self),
                                                   String(decoding: input, as: UTF8.self)) else { return [:] }
        defer { egress_string_free(result) }
        guard let matches = try? JSONDecoder().decode([UInt32?].self, from: Data(String(cString: result).utf8))
        else { return [:] }
        return zip(targets, matches).reduce(into: [:]) { result, pair in result[pair.0] = pair.1 }
    }

    static func newGroup(in config: Self, name: String) -> Group {
        let ids = Set(config.groups.map(\.id))
        var id = UInt32.random(in: 1...UInt32.max)
        while ids.contains(id) { id = UInt32.random(in: 1...UInt32.max) }
        return Group(id: id, name: name)
    }
}

struct EgressRuleChange: Identifiable, Equatable {
    let id = UUID()
    let before: EgressProtection
    let after: EgressProtection

    init(before: EgressProtection, after: EgressProtection) {
        self.before = before
        self.after = after
    }

    init(config: EgressProtection, edit: (inout EgressProtection) -> Void) {
        before = config
        var result = config.rulesForEditing
        edit(&result)
        result.updateEnabledFromRules()
        after = result
    }

    func needsReconnect(connected: Bool) -> Bool { connected && before.isActive != after.isActive }
    var undo: Self { .init(before: after, after: before) }
    var confirmationTitle: String { after.isActive ? "开启并重连" : "关闭并重连" }
    static let reconnectCaption = "需要重新连接一次 VPN。通常不用在手机上确认，已打开的网页可能需要刷新。"

    static func replacingSites(_ sites: [String], expected: [String], group id: UInt32, in config: EgressProtection) -> Self? {
        guard let index = config.groups.firstIndex(where: { $0.id == id && $0.sites == expected }) else { return nil }
        var updated = config
        updated.groups[index].sites = sites
        return Self(before: config, after: updated)
    }

    static func adding(_ input: EgressRuleInput, countries: [String], unverified: EgressProtection.Unverified,
                       config: EgressProtection) -> Self? {
        guard !input.lines.isEmpty, !countries.isEmpty else { return nil }
        let batches = Dictionary(grouping: input.lines, by: \.group)
        let change = Self(config: config) { result in
            var seen = Set<String?>()
            for line in input.lines where seen.insert(line.group).inserted {
                let sites = batches[line.group, default: []].map(\.site)
                if let name = line.group, let index = result.groups.firstIndex(where: { $0.name == name }) {
                    var existing = Set(result.groups[index].sites)
                    result.groups[index].sites += sites.filter { existing.insert($0).inserted }
                } else {
                    var group = EgressProtection.newGroup(in: result, name: line.group ?? sites[0])
                    group.enabled = true
                    var unique = Set<String>()
                    group.sites = sites.filter { unique.insert($0).inserted }
                    group.expect = countries
                    group.unverified = unverified
                    result.groups.append(group)
                }
            }
        }
        guard change.after.groups.count <= EgressRuleInput.groupLimit,
              change.after.groups.allSatisfy({ $0.sites.count <= EgressRuleInput.siteLimit }) else { return nil }
        return change
    }
}

struct EgressConfigUpdate: Codable {
    let config: EgressProtection
    let previous: EgressProtection?
}
