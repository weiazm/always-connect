import SwiftUI
import Network

extension EgressProtection {
    static func newGroup(in config: Self, name: String = "新建组") -> Group {
        let ids = Set(config.groups.map(\.id))
        var id = UInt32.random(in: 1...UInt32.max)
        while ids.contains(id) { id = UInt32.random(in: 1...UInt32.max) }
        return Group(id: id, name: name)
    }

    /// Geosite data stays in the bundle. Send only the selected list's rules.
    func forService() -> Self {
        var config = self
        for index in config.groups.indices {
            config.groups[index].members = groups[index].members.flatMap { member in
                guard member.pattern.hasPrefix("geosite:") else { return [member] }
                guard let rule = ListRule.parse(member.pattern) else { return [] }
                return rule.expanded.map { Member(pattern: $0) }
            }
        }
        return config
    }
}
