import Foundation
import Network

func egressCountryName(_ code: String) -> String {
    Locale(identifier: "zh_Hans").localizedString(forRegionCode: code) ?? code
}

func egressFlag(_ code: String) -> String {
    let letters = code.uppercased().unicodeScalars
    guard letters.count == 2, letters.allSatisfy({ (65...90).contains($0.value) }) else { return "" }
    return String(String.UnicodeScalarView(letters.compactMap { UnicodeScalar(127_397 + $0.value) }))
}

func egressCountryLabel(_ code: String) -> String {
    let flag = egressFlag(code)
    return (flag.isEmpty ? "" : flag + " ") + egressCountryName(code)
}

func egressCountriesLabel(_ codes: [String]) -> String {
    codes.isEmpty ? "还没选国家" : codes.map(egressCountryLabel).joined(separator: "、")
}

struct EgressCountryApproval: Codable, Equatable, Identifiable {
    let group: UInt32
    let started: Double
    let observation: EgressProtection.Observation
    var country: String { observation.country ?? "" }
    var id: String { "\(group):\(started):\(country)" }

    func applying(_ countries: [String]?, then stored: EgressProtection, now current: EgressProtection,
                  sameSession: Bool) -> EgressProtection? {
        guard sameSession, current.enabled,
              let rule = stored.groups.first(where: { $0.id == group && $0.enabled }),
              let countries, Set(countries).count == countries.count, Set(countries) == Set(rule.expect + [country]),
              let index = current.groups.firstIndex(of: rule) else { return nil }
        var updated = current
        updated.groups[index].expect = countries
        return updated
    }
}

extension EgressProtection {
    /// ok; partial: some servers exit from a wrong country and only those
    /// are blocked; unknown: not checked yet.
    enum Level: String {
        case ok, partial, unknown
    }

    /// A rule that is blocking some servers right now.
    struct BlockedGroupNotice: Identifiable, Equatable {
        let id: UInt32
        let name: String
    }

    /// An action may only expand the countries of the same currently
    /// blocked servers.
    struct WrongExit: Hashable {
        let host: String
        let address: String
        let country: String
        let path: String
    }

    static func wrongExits(_ observations: [Observation], expected: [String]) -> Set<WrongExit>? {
        let failed = observations.filter { $0.country != nil && $0.isOutside(expected) }
        guard !failed.isEmpty else { return nil }
        let exits = failed.compactMap(\.wrongExit)
        return exits.count == failed.count ? Set(exits) : nil
    }
}

extension EgressProtection.Observation {
    func isOutside(_ expected: [String]) -> Bool {
        guard let country else { return true }
        return !expected.contains { $0.caseInsensitiveCompare(country) == .orderedSame }
    }

    fileprivate var wrongExit: EgressProtection.WrongExit? {
        guard let country,
              country.utf8.count == 2, country.utf8.allSatisfy({ (65...90).contains($0) }) else { return nil }
        let route = path ?? "cisco"
        if let address = peerAddress {
            guard IPv4Address(address) != nil || IPv6Address(address) != nil else { return nil }
            return .init(host: host, address: address, country: country, path: route)
        }
        guard route.hasPrefix("proxy:") else { return nil }
        return .init(host: host, address: "", country: country, path: route)
    }
}

extension EgressProtection.GroupState {
    var displayLevel: EgressProtection.Level {
        switch state {
        case "ok": return .ok
        case "blocked": return .partial
        default: return .unknown
        }
    }

    var blockCaption: String? {
        guard displayLevel == .partial else { return nil }
        let count = blockedCount ?? 0
        if !observed.isEmpty && observed.allSatisfy({ $0.country == nil }) {
            return count > 0 ? "已拦下 \(count) 次连接 · 查不到出口" : "有服务器查不到出口，已拦下"
        }
        return count > 0 ? "已拦下 \(count) 次连接，其他服务器照常逐条检查" : "有些服务器出口不对，已拦下；其他照常检查"
    }
}

extension EgressProtection.Status {
    // The menu-bar poll needs current availability only. History stays
    // on demand in Settings and diagnostics, even on a long session.
    static func monitoring(_ data: Data) -> Self? {
        struct Snapshot: Decodable {
            let running: Bool
            let checking: [UInt32]
            let groups: [EgressProtection.GroupState]
        }
        return (try? JSONDecoder().decode(Snapshot.self, from: data)).map {
            .init(running: $0.running, checking: $0.checking, groups: $0.groups, records: [])
        }
    }

    var blockingNotices: [EgressProtection.BlockedGroupNotice] {
        groups.filter { $0.displayLevel == .partial }.map { .init(id: $0.id, name: $0.name) }
    }

    var displayLevel: EgressProtection.Level { displayLevel(expectedRules: nil) }

    func displayLevel(expectedRules: Set<UInt32>?) -> EgressProtection.Level {
        guard running else { return .unknown }
        let current = expectedRules.map { ids in groups.filter { ids.contains($0.id) } } ?? groups
        if current.contains(where: { $0.displayLevel == .partial }) { return .partial }
        if let expectedRules, !expectedRules.isSubset(of: current.map(\.id)) { return .unknown }
        return !current.isEmpty && current.allSatisfy { $0.displayLevel == .ok } ? .ok : .unknown
    }

    var blockedCount: UInt64 {
        groups.reduce(0) { total, group in
            let (sum, overflow) = total.addingReportingOverflow(group.blockedCount ?? 0)
            return overflow ? .max : sum
        }
    }

    func panelCaption(checkingFor: TimeInterval, expectedRules: Set<UInt32>? = nil) -> String {
        switch displayLevel(expectedRules: expectedRules) {
        case .partial:
            return blockedCount > 0 ? "本次已拦下 \(blockedCount) 次连接" : "部分地址已拦截"
        case .ok: return "正常"
        case .unknown:
            if running && !checking.isEmpty && checkingFor >= 1 { return "正在核对出口" }
            return running ? "尚未核实出口" : "尚未取得保护状态"
        }
    }

    func permits(_ approval: EgressCountryApproval, in config: EgressProtection) -> Bool {
        guard running, config.enabled,
              let rule = config.groups.first(where: { $0.enabled && $0.id == approval.group }),
              let group = groups.first(where: { $0.id == approval.group }),
              let record = records.first(where: { $0.group == approval.group && $0.started == approval.started }),
              record.expected == rule.expect,
              let target = approval.observation.wrongExit else { return false }
        return record.wrongExitsToTrust(current: group)?.contains(target) == true
    }

    func approvals(for id: UInt32) -> [EgressCountryApproval] {
        guard let current = groups.first(where: { $0.id == id }),
              let record = records.first(where: { $0.group == id && $0.ended == nil }),
              let active = record.wrongExitsToTrust(current: current) else { return [] }
        var countries = Set<String>()
        return record.observed.compactMap { obs in
            guard let target = obs.wrongExit, active.contains(target), countries.insert(target.country).inserted else { return nil }
            return .init(group: id, started: record.started, observation: obs)
        }.sorted { $0.country < $1.country }
    }
}

/// Notifies once per rule and connection when it starts blocking servers.
struct EgressNoticeLedger {
    private var notified = Set<UInt32>()

    mutating func retain(_ rules: Set<UInt32>) {
        notified.formIntersection(rules)
    }

    mutating func update(_ groups: [EgressProtection.GroupState]) -> [EgressProtection.GroupState] {
        groups.filter { $0.displayLevel == .partial && ($0.blockedCount ?? 0) > 0 && notified.insert($0.id).inserted }
    }
}

extension EgressProtection.BlockRecord {
    func wrongExitsToTrust(current: EgressProtection.GroupState) -> Set<EgressProtection.WrongExit>? {
        guard ended == nil, current.id == group, current.blocked,
              let failures = EgressProtection.wrongExits(observed, expected: expected),
              failures == EgressProtection.wrongExits(current.observed, expected: expected) else { return nil }
        return failures
    }
}
