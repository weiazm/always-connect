import Foundation

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

    /// The enabled rule protecting this host, if any.
    func rule(covering host: String?) -> Group? {
        guard enabled, let host else { return nil }
        return groups.first { $0.enabled && $0.covers(host) }
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

    /// A new rule protecting these sites from these countries.
    static func addingSites(_ sites: [String], countries: [String], config: EgressProtection) -> Self? {
        guard !sites.isEmpty, !countries.isEmpty else { return nil }
        var added = EgressProtection.newGroup(in: config, name: sites.count > 1 ? "\(sites[0]) 等 \(sites.count) 个" : sites[0])
        added.enabled = true
        added.sites = sites
        added.expect = countries
        return Self(config: config) { $0.groups.append(added) }
    }
}

struct EgressConfigUpdate: Codable {
    let config: EgressProtection
    let previous: EgressProtection?
}
