import Foundation
import Network

extension EgressProtection {
    /// A disabled master switch in a candidate build must not arm the old
    /// checked groups when the interface switches to per-rule switches.
    var rulesForEditing: Self {
        guard !enabled else { return self }
        var result = self
        for index in result.groups.indices { result.groups[index].enabled = false }
        return result
    }

    mutating func updateEnabledFromRules() {
        enabled = groups.contains(where: \.enabled)
    }

    func rule(covering host: String?) -> Group? {
        guard enabled, let host else { return nil }
        return groups.first { group in
            group.enabled && group.members.contains { $0.matchesSite(host) }
        }
    }
}

extension EgressProtection.Group {
    /// The common apex/wildcard pair represents one site in the interface.
    var websiteNames: [String] {
        let names = members.map { $0.pattern.hasPrefix("*.") ? String($0.pattern.dropFirst(2)) : $0.pattern }
        var seen = Set<String>()
        return (names + cidrs).filter { seen.insert($0).inserted }
    }

    var titleForWebsite: String {
        let websites = websiteNames
        guard let first = websites.first else { return "网站规则" }
        return websites.count > 1 ? "\(first) 等 \(websites.count) 个网站" : first
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
}

struct EgressConfigUpdate: Codable {
    let config: EgressProtection
    let previous: EgressProtection?
}

struct EgressSetupRequest: Codable {
    let host: String
    let method: String
}

struct EgressWebsiteScope: Equatable {
    let host: String
    let includesSubdomains: Bool

    init?(_ input: String, includesSubdomains: Bool) {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        let text = trimmed.contains("://") ? trimmed : "https://" + trimmed
        guard let components = URLComponents(string: text), ["http", "https"].contains(components.scheme?.lowercased()),
              components.user == nil, components.password == nil,
              let name = components.url?.host?.lowercased(),
              let host = DirectSites.clean(name), IPv4Address(host) == nil, IPv6Address(host) == nil,
              EgressProtection.Member(pattern: host).concreteHost != nil else { return nil }
        self.host = host
        self.includesSubdomains = includesSubdomains
    }

    var website: String { includesSubdomains ? DirectSites.site(of: host) : host }

    func conflicts(in config: EgressProtection, rule: UInt32?, direct: [DirectSite]) -> Bool {
        let candidates = [host, website]
        if candidates.contains(where: { DirectSites.covering(direct, host: $0, address: "") != nil }) { return true }
        if includesSubdomains && direct.flatMap(\.domains).contains(where: { line in
            if case .domain(let domain)? = ListRule.parse(line) { return domain.hasSuffix("." + website) }
            return false
        }) { return true }
        guard config.enabled else { return false }
        return config.groups.contains { group in
            group.enabled && group.id != rule && group.members.contains { member in
                let name = member.pattern.hasPrefix("*.") ? String(member.pattern.dropFirst(2)) : member.pattern
                return candidates.contains(where: member.matchesSite)
                    || (includesSubdomains && (name == website || name.hasSuffix("." + website)))
            }
        }
    }

    func members(method: String?) -> [EgressProtection.Member] {
        if !includesSubdomains { return [.init(pattern: host, method: method)] }
        let root = website
        if host == root {
            // We have no concrete subdomain to probe yet. The wildcard
            // follows the rule, so an untested subdomain cannot bypass it.
            return [.init(pattern: root, method: method), .init(pattern: "*." + root)]
        }
        // The site itself is checked with the same method: as a follow-only member it
        // would be blocked whenever any other address of the site failed (§66.21).
        return [.init(pattern: root, method: method), .init(pattern: "*." + root, method: method, probeHost: host)]
    }

    static func unique(_ scopes: [Self]) -> [Self] {
        var seen = Set<String>()
        return scopes.filter { seen.insert($0.website).inserted }
    }

    static func adding(_ scopes: [Self], to config: EgressProtection, rule id: UInt32?, newRuleID: UInt32,
                       methods: [String: String], countries: [String], activateExisting: Bool = true) -> EgressRuleChange? {
        guard !scopes.isEmpty else { return nil }
        var result = config.rulesForEditing
        let index: Int
        if let id {
            guard let existing = result.groups.firstIndex(where: { $0.id == id }) else { return nil }
            index = existing
        } else {
            guard !result.groups.contains(where: { $0.id == newRuleID }) else { return nil }
            index = result.groups.count
            result.groups.append(.init(id: newRuleID, name: scopes[0].website))
        }
        var rule = result.groups[index]
        let originalTitle = rule.titleForWebsite
        for scope in scopes {
            for member in scope.members(method: methods[scope.host]) {
                if let existing = rule.members.firstIndex(where: { $0.pattern == member.pattern }) {
                    // A follow-only addition must never remove direct evidence.
                    if member.method != nil { rule.members[existing] = member }
                } else { rule.members.append(member) }
            }
        }
        if id == nil || rule.name == originalTitle { rule.name = rule.titleForWebsite }
        if id == nil || (!rule.enabled && activateExisting) { rule.expect = countries }
        rule.enabled = rule.enabled || id == nil || activateExisting
        if rule.enabled && (rule.expect.isEmpty || result.directMembers(in: rule).isEmpty) { return nil }
        result.groups[index] = rule
        result.updateEnabledFromRules()
        return .init(before: config, after: result)
    }
}

extension EgressProtection.Group {
    func patternsCovering(_ host: String) -> Set<String> {
        let matches = members.filter { $0.matchesSite(host) }
        var patterns = Set(matches.map(\.pattern))
        // The generated apex and wildcard are one website. Removing one
        // requires showing that scope before the user confirms.
        for member in matches where member.pattern.hasPrefix("*.") {
            let root = String(member.pattern.dropFirst(2))
            if members.contains(where: { $0.pattern == root }) { patterns.insert(root) }
        }
        if members.contains(where: { $0.pattern == "*." + host }) { patterns.insert("*." + host) }
        return patterns
    }
}

extension EgressRuleChange {
    static func move(host: String, source: UInt32, target: UInt32?,
                     config: EgressProtection) -> (change: Self, patterns: Set<String>)? {
        let rules = config.rulesForEditing.groups
        guard let owner = rules.first(where: { $0.id == source }),
              target == nil || (source != target && rules.contains { $0.id == target }) else { return nil }
        let patterns = owner.patternsCovering(host)
        guard !patterns.isEmpty else { return nil }
        let moved = owner.members.filter { patterns.contains($0.pattern) }
        let change = Self(config: config) { result in
            if let index = result.groups.firstIndex(where: { $0.id == source }) {
                result.groups[index].members.removeAll { patterns.contains($0.pattern) }
                if result.groups[index].members.isEmpty && result.groups[index].cidrs.isEmpty {
                    result.groups[index].enabled = false
                }
            }
            if let target, let index = result.groups.firstIndex(where: { $0.id == target }) {
                for member in moved where !result.groups[index].members.contains(where: { $0.pattern == member.pattern }) {
                    result.groups[index].members.append(member)
                }
            }
        }
        return (change, patterns)
    }
}

extension EgressProtection.SetupProbe {
    static func unavailable(_ host: String) -> Self {
        .init(host: host, method: "", status: "unavailable", error: nil, resolvedAddressCount: 0,
              probedAddressCount: 0, truncated: false, coverageIncomplete: true, results: [])
    }

    var isComplete: Bool { status == "ok" || status == "unsupported" }

    private var countriesByCount: [(country: String, count: Int)] {
        var counts: [String: Int] = [:]
        var addresses = Set<String>()
        for row in results.prefix(8) where row.status == "ok" && row.method == method {
            guard let country = row.country, country.utf8.count == 2,
                  country.utf8.allSatisfy({ (65...90).contains($0) }),
                  (IPv4Address(row.address) != nil || IPv6Address(row.address) != nil),
                  addresses.insert(row.address).inserted else { continue }
            counts[country, default: 0] += 1
        }
        return counts.map { ($0.key, $0.value) }.sorted {
            $0.count == $1.count ? $0.country < $1.country : $0.count > $1.count
        }
    }

    var verifiedMethod: String? { status == "ok" && !method.isEmpty && !countriesByCount.isEmpty ? method : nil }

    var suggestedCountry: String? {
        let counts = countriesByCount
        guard verifiedMethod != nil, let first = counts.first, first.count > (counts.dropFirst().first?.count ?? 0) else { return nil }
        return first.country
    }

    /// One line for the add sheet's list: where it leaves from, plainly.
    var shortCaption: String {
        switch status {
        case "ok":
            let counts = countriesByCount
            guard !counts.isEmpty else { return "这次没查到出口" }
            let failed = max(0, probedAddressCount - counts.reduce(0) { $0 + $1.count })
            if counts.count == 1 && failed == 0 {
                return "\(probedAddressCount) 个服务器都从 \(egressFlag(counts[0].country)) \(egressCountryName(counts[0].country)) 出去"
            }
            let parts = counts.map { "\($0.count) 个从 \(egressFlag($0.country)) \(egressCountryName($0.country))" }
            return parts.joined(separator: "，") + (failed > 0 ? "，\(failed) 个查不到" : "")
        case "unsupported":
            return "不能直接检查，跟着一起保护"
        default:
            return error ?? "这次没查到出口"
        }
    }

    var caption: String {
        switch status {
        case "ok":
            let counts = countriesByCount
            let breakdown = counts.map { "\($0.count) 个从 \(egressCountryName($0.country)) 出去" }.joined(separator: "，")
            guard !breakdown.isEmpty else { return "这次没有查到出口，请重新检查。" }
            let failed = max(0, probedAddressCount - counts.reduce(0) { $0 + $1.count })
            let missing = failed > 0 ? "，\(failed) 个查不到" : ""
            let incomplete = coverageIncomplete || truncated ? "。本次未覆盖全部服务器" : ""
            return "检查了 \(probedAddressCount) 个服务器：\(breakdown)\(missing)\(incomplete)。"
        case "unsupported":
            return "这个网站没法直接检查出口。它会跟着同一条规则里的其他网站一起保护。"
        default:
            return error ?? "这次没能检查出口。请确认 VPN 已连接，再重新检查。"
        }
    }
}

func verifiedMethods(_ results: [String: EgressProtection.SetupProbe], config: EgressProtection) -> [String: String] {
    results.compactMapValues { $0.verifiedMethod.flatMap { config.method($0)?.isDirect == true ? $0 : nil } }
}

func suggestedEgressCountry(_ results: [String: EgressProtection.SetupProbe]) -> String? {
    let checked = results.values.filter { $0.verifiedMethod != nil }
    let suggestions = Set(checked.compactMap(\.suggestedCountry))
    guard checked.allSatisfy({ $0.suggestedCountry != nil }), suggestions.count == 1 else { return nil }
    return suggestions.first
}
