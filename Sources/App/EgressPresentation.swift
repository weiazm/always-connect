import Foundation
import Network

func egressCountryName(_ code: String) -> String {
    Locale(identifier: "zh_Hans").localizedString(forRegionCode: code) ?? code
}

struct EgressCountryApproval: Codable, Equatable, Identifiable {
    let group: UInt32
    let started: Double
    let observation: EgressProtection.Observation
    var country: String { observation.country ?? "" }
    var id: String { "\(group):\(started):\(country)" }

    func applying(_ countries: [String]?, then stored: EgressProtection, now current: EgressProtection,
                  sameSession: Bool) -> EgressProtection? {
        guard sameSession, current.enabled, current.methods == stored.methods,
              let rule = stored.groups.first(where: { $0.id == group && $0.enabled }),
              let countries, Set(countries).count == countries.count, Set(countries) == Set(rule.expect + [country]),
              let index = current.groups.firstIndex(of: rule) else { return nil }
        var updated = current
        updated.groups[index].expect = countries
        return updated
    }
}

extension EgressProtection.Method {
    static let thirdPartyCaption = "第三方查询点：仅供参考，不参与放行或拦截"
    var scopeCaption: String { isDirect ? "直接检查网站" : Self.thirdPartyCaption }

    static func preferredDirectMethod(_ methods: [Self], observations: [EgressProtection.Observation]) -> String? {
        methods.first { method in
            method.isDirect && observations.contains { $0.method == method.id && $0.country != nil }
        }?.id
    }
}

extension EgressProtection {
    enum Level: String {
        case ok, partial, blocked, unknown
    }

    enum BlockReason: String {
        case noDirectMethod = "no-direct-method"
        case failedTargetOverflow = "failed-target-overflow"

        var caption: String {
            switch self {
            case .noDirectMethod: return "无法核实网站本身的出口，已拦截这组新连接"
            case .failedTargetOverflow: return "失败地址过多，已拦截这组新连接"
            }
        }
    }

    struct BlockedGroupNotice: Identifiable, Equatable {
        let id: UInt32
        let name: String
        let reason: BlockReason
    }

    enum Evidence: String, CaseIterable {
        case direct, proxy, member, unknown
        case thirdParty = "third-party"

        var caption: String {
            switch self {
            case .direct: return "直接观测（同名、固定目的地址）"
            case .proxy: return "按借用身份查到（代理观测）"
            case .thirdParty: return Method.thirdPartyCaption
            case .member: return "按网站名查询（组内成员）"
            case .unknown: return "来源未记录"
            }
        }
    }

    /// An action from a notification may only expand the countries of the
    /// same currently blocked direct targets.
    struct DirectTargetObservation: Hashable, Codable {
        let host: String
        let address: String
        let method: String
        let country: String
    }

    static func directFailures(_ observations: [Observation], expected: [String]) -> Set<DirectTargetObservation>? {
        let failed = observations.filter { $0.evidenceKind != .thirdParty && $0.isOutside(expected) }
        guard !failed.isEmpty else { return nil }
        let direct = failed.compactMap(\.directTarget)
        return direct.count == failed.count ? Set(direct) : nil
    }
}

extension EgressProtection.Observation {
    var evidenceKind: EgressProtection.Evidence {
        evidence.flatMap(EgressProtection.Evidence.init(rawValue:)) ?? .unknown
    }

    private var countryAndAddress: String {
        guard let country else { return "未查到" }
        return country + (ip.map { "（出口 IP \($0)）" } ?? "")
    }

    var observationCaption: String {
        let address = peerAddress.map { "（目的地址 \($0)）" } ?? ""
        return "\(host)\(address)：\(countryAndAddress) · \(evidenceKind.caption)"
    }

    func isOutside(_ expected: [String]) -> Bool {
        guard let country else { return true }
        return !expected.contains { $0.caseInsensitiveCompare(country) == .orderedSame }
    }

    fileprivate var directTarget: EgressProtection.DirectTargetObservation? {
        guard evidenceKind == .direct, let country, let address = peerAddress,
              IPv4Address(address) != nil || IPv6Address(address) != nil,
              country.utf8.count == 2, country.utf8.allSatisfy({ (65...90).contains($0) }) else { return nil }
        return .init(host: host, address: address, method: method, country: country)
    }
}

extension EgressProtection.GroupState {
    var displayLevel: EgressProtection.Level {
        if blockReason != nil { return .blocked }
        if let level, let known = EgressProtection.Level(rawValue: level) { return known }
        // Old replies have no site-level availability statement.
        return state == "ok" ? .ok : .unknown
    }

    var blockReason: EgressProtection.BlockReason? {
        reason.flatMap(EgressProtection.BlockReason.init(rawValue:))
    }

    var blockCaption: String? {
        if let reason = blockReason { return reason.caption }
        switch displayLevel {
        case .ok: return nil
        case .partial:
            let count = blockedCount ?? 0
            return count > 0 ? "已拦下 \(count) 次连接，其他地址仍逐条核对" : "部分地址已拦截，其他地址仍逐条核对"
        case .blocked:
            let website = sites?.first(where: { $0.state == "blocked" })?.host ?? lastBlockedHost ?? name
            return "\(website) 暂时打不开：出口无法核实"
        case .unknown: return blocked ? "有连接已拦截，正在等待出口状态" : nil
        }
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
        groups.compactMap { group in
            guard group.blocked, let reason = group.blockReason else { return nil }
            return .init(id: group.id, name: group.name, reason: reason)
        }
    }

    var displayLevel: EgressProtection.Level { displayLevel(expectedRules: nil) }

    func displayLevel(expectedRules: Set<UInt32>?) -> EgressProtection.Level {
        guard running else { return .unknown }
        let current = expectedRules.map { ids in groups.filter { ids.contains($0.id) } } ?? groups
        if current.contains(where: { $0.displayLevel == .blocked }) { return .blocked }
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
        case .blocked:
            return groups.first { $0.displayLevel == .blocked }?.blockCaption ?? "有网站暂时打不开"
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
              let target = approval.observation.directTarget,
              record.directTargetsToTrust(current: group)?.contains(target) == true else { return false }
        return config.directMembers(in: rule).contains { $0.method == target.method && $0.matchesSite(target.host) }
    }

    func approvals(for id: UInt32) -> [EgressCountryApproval] {
        guard let current = groups.first(where: { $0.id == id }),
              let record = records.first(where: { $0.group == id && $0.ended == nil }),
              let active = record.directTargetsToTrust(current: current) else { return [] }
        var countries = Set<String>()
        return record.observed.compactMap { obs in
            guard let target = obs.directTarget, active.contains(target), countries.insert(target.country).inserted else { return nil }
            return .init(group: id, started: record.started, observation: obs)
        }.sorted { $0.country < $1.country }
    }
}

struct EgressNoticeLedger {
    enum Kind { case partial, blocked, recovered }
    struct Event {
        let kind: Kind
        let rule: EgressProtection.GroupState
    }
    private var partial = Set<UInt32>()
    private var blocked = Set<UInt32>()
    private var recovered = Set<UInt32>()

    mutating func retain(_ rules: Set<UInt32>) {
        partial.formIntersection(rules)
        blocked.formIntersection(rules)
        recovered.formIntersection(rules)
    }

    mutating func update(_ groups: [EgressProtection.GroupState]) -> [Event] {
        groups.compactMap { group in
            let id = group.id
            switch group.displayLevel {
            case .blocked:
                return blocked.insert(id).inserted ? .init(kind: .blocked, rule: group) : nil
            case .ok, .partial:
                if blocked.contains(id) && recovered.insert(id).inserted { return .init(kind: .recovered, rule: group) }
                if group.displayLevel == .partial && (group.blockedCount ?? 0) > 0
                    && !blocked.contains(id) && partial.insert(id).inserted {
                    return .init(kind: .partial, rule: group)
                }
                return nil
            case .unknown:
                return nil
            }
        }
    }
}

extension EgressProtection.BlockRecord {
    func directFailures() -> Set<EgressProtection.DirectTargetObservation>? {
        EgressProtection.directFailures(observed, expected: expected)
    }

    func directTargetsToTrust(current: EgressProtection.GroupState) -> Set<EgressProtection.DirectTargetObservation>? {
        guard ended == nil, current.id == group, current.blocked, current.reason == nil,
              let failures = directFailures(),
              failures == EgressProtection.directFailures(current.observed, expected: expected) else { return nil }
        return failures
    }

    var evidenceSummary: String {
        let counts = Dictionary(grouping: observed, by: \.evidenceKind).mapValues(\.count)
        return EgressProtection.Evidence.allCases.compactMap { evidence in
            counts[evidence].map { "\(evidence.rawValue)=\($0)" }
        }.joined(separator: "，")
    }
}
