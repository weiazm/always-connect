import Foundation

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

/// Lines typed for exit protection, read by the same parser as the
/// split list (ListRule, DESIGN.md §66.30): one syntax for both.
struct EgressRuleInput {
    static let siteLimit = 256
    static let groupLimit = 16

    struct Issue: Identifiable {
        let id: Int
        let message: String
    }

    /// The rules in stored form, in input order, without repeats.
    var sites: [String] = []
    var issues: [Issue] = []

    init(_ input: String) {
        var seen = Set<String>()
        for (index, raw) in input.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline).enumerated() {
            let text = raw.trimmingCharacters(in: .whitespaces)
            guard !text.isEmpty, !text.hasPrefix("#"), !text.hasPrefix("//") else { continue }
            if let rule = ListRule.parse(text) {
                if seen.insert(rule.text).inserted { sites.append(rule.text) }
            } else {
                issues.append(Issue(id: index + 1, message: ListRule.problem(text) ?? "写法无效"))
            }
        }
    }

    func adding(to old: [String]) -> [String] {
        var seen = Set(old)
        return old + sites.filter { seen.insert($0).inserted }
    }

    /// Editing replaces the whole list. Every non-comment line must parse.
    var replacementSites: [String]? {
        guard issues.isEmpty else { return nil }
        return (1...Self.siteLimit).contains(sites.count) ? sites : nil
    }

    /// Every rule as text the input reads back: "# name" before each
    /// protection's lines (a comment, so pasting it all adds the lines).
    static func text(of config: EgressProtection) -> String {
        config.groups.filter { !$0.sites.isEmpty }
            .map { (["# " + $0.name] + $0.sites).joined(separator: "\n") }
            .joined(separator: "\n\n")
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
                let items = ListRule.parse(site).map { $0.isNetwork ? ["ipcidr:" + $0.text] : $0.expanded } ?? []
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
        guard let first = input.sites.first, !countries.isEmpty else { return nil }
        let change = Self(config: config) { result in
            var group = EgressProtection.newGroup(in: result, name: first)
            group.enabled = true
            group.sites = input.sites
            group.expect = countries
            group.unverified = unverified
            result.groups.append(group)
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
